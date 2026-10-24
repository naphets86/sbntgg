"""Stateless JSON API for subnet planning and related operations."""
from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import asdict
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from subnetplan.access import service_differences, services_included
from subnetplan.checks import plan_warnings
from subnetplan.config import build_config, build_extension
from subnetplan.extend import extend_plan, plan_from_json
from subnetplan.firewall import FirewallOptions, render_firewall
from subnetplan.models import FIREWALLS, FORMATS, GATEWAY_POSITIONS, STRATEGIES, Plan, PlanError
from subnetplan.planner import plan_subnets
from subnetplan.ports import ServiceSet
from subnetplan.render import render_json
from subnetplan.roundtrip import check_roundtrip
from subnetplan.semantics import cisco_verdict, firewall_verdict, locate
from subnetplan.sequence import DEFAULT_GRAPH, SequenceError, advance, load_graph
from subnetplan.stats import plan_statistics
from subnetplan.verify import verify_plan

API_PREFIX = "/api/v1"

app = FastAPI(
    title="subnetplan API",
    summary="IPv4- und IPv6-Subnetzplanung als JSON API",
    description="""
    Die **subnetplan API** berechnet Subnetze und stellt die zugehörigen Firewall- und
    Analysefunktionen als zustandslose JSON-Endpunkte bereit. Jede Planoperation erhält
    ihre Konfiguration im Request; Pläne werden nicht serverseitig gespeichert.

    ## Ablauf

    1. Eine Konfiguration mit `base_network` und einer nichtleeren `groups`-Liste an
       `POST /api/v1/plans` senden.
    2. Das Ergebnis enthält die Subnetze, Gateways, VLAN-IDs, freien Bereiche und die
       Belegungskennzahlen.
    3. Den Plan oder die ursprüngliche Konfiguration anschließend an Analyse-Endpunkte
       übergeben, um ihn zu verifizieren, zu erweitern oder Regeln zu erzeugen.

    ## Eingaben und Fehler

    Konfigurationen verwenden dieselben Schlüssel wie die YAML-/JSON-Dateien der
    Kommandozeile. Optionale `overrides` überschreiben passende Werte aus `config`.
    Fachliche Validierungs- und Planungsfehler antworten mit HTTP **422** und dem Schema
    `{"error":{"type":"plan_error","message":"..."}}`. Ungültige JSON-Feldtypen
    werden von FastAPI ebenfalls mit HTTP 422 abgewiesen.

    ## Sequenzen (optional)

    Ein einzelner Request ist zustandslos. Eine **Folge** von Requests (planen, prüfen,
    Regeln erzeugen, zurückprüfen, erweitern) ist ein Prozess mit Reihenfolge. Wer das
    wünscht, sendet die Kopfzeilen `X-Sequence-Start` (Kennung, nur im ersten Schritt),
    `X-Sequence-Token` (zuletzt erhaltenes Token) und `X-Sequence-End: true` (letzter
    Schritt). Die API prüft dann zustandslos, ob der Request an dieser Stelle der Folge
    zulässig ist, und antwortet bei einem Verstoß mit HTTP **409** und dem Schema
    `{"status":409,"error":{"type":"sequence/...","message":"..."}}`. Ohne diese
    Kopfzeilen verhält sich jeder Endpunkt wie bisher.

    ## Sicherheitshinweis

    Die Firewall-Ausgaben verwenden standardmäßig Default-Deny. Sie sind Textvorlagen zur
    Prüfung und zum manuellen Einspielen, keine Änderungen an einem laufenden Firewall-System.
    Der Richtlinienvergleich enthält eine exakte Prüfung und zusätzlich einen heuristischen
    Subgraph-Vergleich; `subgraph_agrees` zeigt, ob beide Entscheidungen übereinstimmen.
    """,
    version="4.1.0",
    openapi_tags=[
        {"name": "meta", "description": "Status und zulässige Konfigurationsoptionen."},
        {"name": "plans", "description": "Subnetzpläne berechnen oder ohne Verschieben bestehender Netze erweitern."},
        {"name": "analysis", "description": "Pläne verifizieren, auswerten, vergleichen oder Paketflüsse beurteilen."},
        {"name": "firewall", "description": "Firewall-Regeltexte erzeugen und deren Rückübersetzung prüfen."},
    ],
)


class ErrorDetails(BaseModel):
    type: str = Field(description="Fehlerkategorie; fachliche Fehler haben den Wert `plan_error`.", examples=["plan_error"])
    message: str = Field(description="Menschenlesbare Erklärung des Fehlers.", examples=["Pflichtfeld 'base_network' fehlt"])


class ErrorResponse(BaseModel):
    error: ErrorDetails = Field(description="Strukturierte Fehlerdetails.")


class ValidationErrorResponse(BaseModel):
    detail: list[dict[str, Any]] = Field(description="FastAPI-Validierungsfehler mit Feldpfad, Meldung und Fehlerkategorie.")


class ServiceUnavailableResponse(BaseModel):
    detail: str = Field(description="Erklärung, warum die angeforderte Funktion nicht verfügbar ist.", examples=["Richtlinienvergleich ist nicht verfügbar"])


class HealthResponse(BaseModel):
    status: Literal["ok"] = Field(description="`ok`, wenn der API-Prozess Anfragen beantwortet.", examples=["ok"])


class OptionsResponse(BaseModel):
    strategies: list[str] = Field(description="Zulässige Zuteilungsstrategien: `vlsm` oder `fixed`.")
    gateway_positions: list[str] = Field(description="Zulässige Gateway-Positionen: `first`, `last` oder `none`.")
    formats: list[str] = Field(description="Von der Bibliothek unterstützte Ausgabeformate.")
    firewalls: list[str] = Field(description="Verfügbare Firewall-Ausgaben einschließlich `none`.")
    cisco_return_modes: list[str] = Field(description="Cisco-Rückverkehrsoptionen: `none` oder `established`.")


class SubnetResponse(BaseModel):
    group: str = Field(description="Name der Gruppe aus der Konfiguration.", examples=["Server"])
    vlan_id: int = Field(description="Zugewiesene VLAN-ID.", examples=[10])
    network: str = Field(description="Zugewiesenes Subnetz in CIDR-Notation.", examples=["10.20.0.0/24"])
    netmask: str = Field(description="Subnetzmaske (bei IPv4) beziehungsweise Adressmaske.", examples=["255.255.255.0"])
    gateway: str | None = Field(description="Gateway-Adresse oder `null`, wenn kein Gateway vorgesehen ist.", examples=["10.20.0.1"])
    first_host: str = Field(description="Erste nutzbare Adresse im Subnetz.", examples=["10.20.0.2"])
    last_host: str = Field(description="Letzte nutzbare Adresse im Subnetz.", examples=["10.20.0.254"])
    broadcast: str | None = Field(description="Broadcast-Adresse bei IPv4; bei IPv6 `null`.", examples=["10.20.0.255"])
    usable_hosts: int = Field(description="Anzahl der nutzbaren Adressen nach Reservierungen.", examples=[253])
    requested_hosts: int = Field(description="Angeforderte Host-Anzahl der Gruppe.", examples=[120])
    access: list[str] = Field(description="Gruppen, zu denen neue Verbindungen erlaubt werden.", examples=[["Drucker"]])
    site: str | None = Field(default=None, description="Standortname bei hierarchischer Planung.", examples=["Berlin"])
    services: dict[str, list[str]] | None = Field(default=None, description="Auf Protokolle und Ports eingeschränkte Freigaben je Zielgruppe; Ziele ohne Eintrag sind für alle Dienste freigegeben.", examples=[{"Server": ["tcp/22", "tcp/443"]}])


class PlanResponse(BaseModel):
    base_network: str = Field(description="Primäres Basisnetz in CIDR-Notation.", examples=["10.20.0.0/16"])
    total_addresses: int = Field(description="Gesamtzahl der Adressen in allen Pools.", examples=[65536])
    allocated_addresses: int = Field(description="Durch Plan oder Standortblöcke belegte Adressen.", examples=[256])
    free_addresses: int = Field(description="Noch nicht belegte oder reservierte Adressen.", examples=[65280])
    utilization_percent: float = Field(description="Belegung aller Pools in Prozent.", examples=[0.39])
    free_ranges: list[str] = Field(description="Zusammengefasste freie CIDR-Bereiche.", examples=[["10.20.1.0/24", "10.20.2.0/23"]])
    subnets: list[SubnetResponse] = Field(description="Ein Eintrag pro geplanter Gruppe.")
    pools: list[str] | None = Field(default=None, description="Zusätzliche Pools neben `base_network`, falls vorhanden.")
    reserved: list[str] | None = Field(default=None, description="Bereits belegte Netze, die nicht Teil dieses Plans sind.")
    site_blocks: dict[str, str] | None = Field(default=None, description="Zugewiesene Standortblöcke bei hierarchischer Planung.")


class VerificationResponse(BaseModel):
    valid: bool = Field(description="`true`, wenn alle geprüften Planeigenschaften erfüllt sind.", examples=[True])
    problems: list[str] = Field(description="Liste der gefundenen Verletzungen; bei gültigem Plan leer.", examples=[[]])
    plan: PlanResponse = Field(description="Der geprüfte Plan im JSON-Format.")


class StatisticsResponse(BaseModel):
    block_utilization: dict[str, float] = Field(description="Bedarf geteilt durch Blockgröße, je Gruppe.", examples=[{"Server": 0.828125}])
    mean_utilization: float = Field(description="Mittlere Blockauslastung aller Gruppen.", examples=[0.828125])
    min_utilization: float = Field(description="Niedrigste Blockauslastung einer Gruppe.", examples=[0.828125])
    allocated: int = Field(description="Summe der Blockgrößen der geplanten Subnetze.", examples=[256])
    required: int = Field(description="Summe der benötigten Adressen einschließlich Reservierungen.", examples=[53])
    internal_waste: int = Field(description="Interner Verschnitt: `allocated - required`.", examples=[203])


class WarningsResponse(BaseModel):
    warnings: list[str] = Field(description="Hinweise zu Adressbereichen, Überschneidungen, Auslastung und Firewall-Optionen.")


class FirewallResponse(BaseModel):
    firewall: Literal["iptables", "nftables", "cisco"] = Field(description="Zielsystem der erzeugten Regeln.")
    rules: str = Field(description="Vollständiger Regeltext. Vor dem Einspielen prüfen.", examples=["table inet subnet_acl { ... }"])


class NetworkPair(BaseModel):
    source: str = Field(description="Quellnetz eines Regel- beziehungsweise Zugriffspaars.", examples=["10.20.0.0/24"])
    target: str = Field(description="Zielnetz eines Regel- beziehungsweise Zugriffspaars.", examples=["10.20.1.0/24"])


class RoundtripCheck(BaseModel):
    ok: bool = Field(description="`true`, wenn alle erwarteten Regeln rekonstruiert wurden und Default-Deny gilt.")
    missing: list[NetworkPair] = Field(description="Erwartete Zugriffspaare, die im Regeltext fehlen.")
    extra: list[NetworkPair] = Field(description="Zusätzliche Zugriffspaare, die der Regeltext erlauben würde.")
    default_deny: bool = Field(description="Gibt an, ob der Regeltext nicht ausdrücklich erlaubten Verkehr verwirft.")
    returns: list[NetworkPair] = Field(description="Gesondert erkannte Cisco-Rückverkehrsregeln.")
    service_mismatch: list[NetworkPair] = Field(default_factory=list, description="Zugriffspaare, bei denen die aus dem Regeltext rekonstruierte Dienstmenge (Protokolle und Ports) von der Konfiguration abweicht.")


class RoundtripResponse(BaseModel):
    results: dict[str, RoundtripCheck] = Field(description="Prüfergebnis je angefordertem Firewall-System.")


class ServiceDifference(BaseModel):
    source: str = Field(description="Quellgruppe des Zugriffspaares.", examples=["Entwicklung"])
    target: str = Field(description="Zielgruppe des Zugriffspaares.", examples=["Server"])
    a: list[str] = Field(description="Freigegebene Dienste in Plan A; `all` bedeutet ohne Einschränkung, eine leere Liste keine Freigabe.", examples=[["tcp/22", "tcp/443"]])
    b: list[str] = Field(description="Freigegebene Dienste in Plan B; `all` bedeutet ohne Einschränkung, eine leere Liste keine Freigabe.", examples=[["all"]])


class ServiceCompareResponse(BaseModel):
    relation: Literal["equal", "a_in_b", "b_in_a", "incomparable"] = Field(description="Exakte Relation der Freigaben auf Dienstebene: `a_in_b` heißt, jede Freigabe von A (Paar und Dienst) ist auch in B erlaubt.")
    a_in_b: bool = Field(description="Ob jede Freigabe von A auch in B erlaubt ist.")
    b_in_a: bool = Field(description="Ob jede Freigabe von B auch in A erlaubt ist.")
    differences: list[ServiceDifference] = Field(description="Zugriffspaare mit unterschiedlicher Dienstmenge; bei Gleichheit leer.")


class CompareResponse(BaseModel):
    relation: str = Field(description="Exakte Relation der Zugriffsmengen: `equal`, `a_in_b`, `b_in_a` oder `incomparable`.")
    same_groups: bool = Field(description="Ob beide Pläne dieselben Gruppennamen enthalten.")
    rotation_a_in_b: int | None = Field(description="Startposition für die zyklische Einbettung von A in B; `null`, falls keine besteht.")
    rotation_b_in_a: int | None = Field(description="Startposition für die zyklische Einbettung von B in A; `null`, falls keine besteht.")
    rotation_relation: str = Field(description="Exakte Relation der Matrizen bis auf zyklische Verschiebung.")
    subgraph_decision: str = Field(description="Rohentscheidung des Subgraph Algorithmus.")
    subgraph_relation: str = Field(description="Normalisierte Relation aus dem Subgraph Algorithmus.")
    subgraph_agrees: bool = Field(description="Ob Subgraph- und exakte Rotationsprüfung übereinstimmen.")
    keep: str = Field(description="Empfehlung: `a`, `b` oder `both`; maßgeblich ist die exakte Zugriffsmengenrelation.")


class VerdictResponse(BaseModel):
    firewall: Literal["accept", "drop"] = Field(description="Urteil für den Paketfluss in der zustandsbehafteten Firewall-Semantik.")
    source_group: str | None = Field(description="Gruppe, in deren Subnetz die Quelladresse liegt; andernfalls `null`.")
    target_group: str | None = Field(description="Gruppe, in deren Subnetz die Zieladresse liegt; andernfalls `null`.")
    cisco: Literal["accept", "drop"] | None = Field(default=None, description="Cisco-ACL-Urteil, wenn `ingress_group` angegeben wurde.")


COMMON_RESPONSES = {
    422: {
        "model": ErrorResponse | ValidationErrorResponse,
        "description": "Fachliche Konfigurations- oder Planungsfehler (Schema `error`) oder ungültige Request-Felder (Schema `detail`).",
        "content": {"application/json": {"examples": {
            "plan_error": {"summary": "Fachlicher Planungsfehler", "value": {"error": {"type": "plan_error", "message": "Pflichtfeld 'base_network' fehlt"}}},
            "request_validation": {"summary": "Fehlerhafte Request-Validierung", "value": {"detail": [{"loc": ["body", "firewall"], "msg": "Field required", "type": "missing"}]}},
        }}},
    },
    409: {
        "model": ErrorResponse,
        "description": "Sequenzfehler (nur mit Kopfzeilen `X-Sequence-*`): unzulässiges Betreten (`sequence/entry_invalid`), unzulässiger Übergang (`sequence/transition_invalid`), unzulässiges Ende (`sequence/end_invalid`), abgelaufene Frist (`sequence/abandoned_late`) oder ungültiges Token (`sequence/context_invalid`). Die Antwort nennt den letzten gültigen Schritt und die zulässigen Nachfolger.",
    },
}


class ConfigRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"config": {"base_network": "10.20.0.0/16", "growth_factor": 1.25, "allocation_strategy": "vlsm", "gateway_position": "first", "groups": [{"name": "Server", "hosts": 40, "vlan_id": 100, "access": ["Drucker"]}, {"name": "Drucker", "hosts": 12}]}, "overrides": {}}]})

    config: dict[str, Any] = Field(
        description="Subnetzplan-Konfiguration. Pflichtfelder sind `base_network` und eine nichtleere `groups`-Liste. Unterstützte Zusatzfelder umfassen `growth_factor`, `allocation_strategy`, `gateway_position`, `max_prefix`, `pools` und `existing`.",
        examples=[{"base_network": "10.20.0.0/16", "growth_factor": 1.25, "allocation_strategy": "vlsm", "gateway_position": "first", "groups": [{"name": "Server", "hosts": 40, "vlan_id": 100, "access": ["Drucker"]}, {"name": "Drucker", "hosts": 12}]}],
    )
    overrides: dict[str, Any] = Field(
        default_factory=dict,
        description="Optionale Überschreibungen der Konfiguration, etwa `base_network`, `growth_factor`, `allocation_strategy`, `gateway_position` oder `max_prefix`.",
        examples=[{"growth_factor": 1.5, "allocation_strategy": "fixed"}],
    )


class ExtendRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"plan": {"base_network": "10.20.0.0/16", "total_addresses": 65536, "allocated_addresses": 256, "free_addresses": 65280, "utilization_percent": 0.39, "free_ranges": ["10.20.1.0/24"], "subnets": []}, "config": {"groups": [{"name": "Neu", "hosts": 25, "access": ["Server"]}]}, "overrides": {}}]})

    plan: dict[str, Any] = Field(description="Vollständiges Plan-JSON aus `POST /api/v1/plans`; bestehende Subnetze bleiben erhalten.")
    config: dict[str, Any] = Field(description="Konfiguration mit den neu aufzunehmenden Gruppen. `base_network` darf entfallen und wird aus dem Plan übernommen.", examples=[{"groups": [{"name": "Neu", "hosts": 25, "access": ["Server"]}]}])
    overrides: dict[str, Any] = Field(default_factory=dict, description="Optionale Überschreibungen für die Erweiterungsplanung.")


class FirewallSettings(BaseModel):
    idempotent: bool = Field(default=True, description="iptables: vorhandene Kette vor dem Anlegen entfernen; macht das Skript wiederholt ausführbar.")
    group_rules: bool = Field(default=False, description="Regeln mit gleichen Zielmengen zusammenfassen; je nach Firewall-System entstehen Mengen oder Objektgruppen.")
    cisco_return: Literal["none", "established"] = Field(default="none", description="Cisco-Rückverkehr: `established` ergänzt TCP-Antwortregeln; UDP und ICMP werden dadurch nicht abgedeckt.")
    ascii_names: bool = Field(default=False, description="Namen in Regelkommentaren und Cisco-ACLs nach ASCII transliterieren.")
    log_drops: bool = Field(default=False, description="Verworfene Pakete zusätzlich protokollieren.")
    icmpv6_types: list[str] = Field(default_factory=list, description="Erlaubte ICMPv6-Typen; nur für IPv6-Pläne. Einträge bestehen aus Kleinbuchstaben, Ziffern und Bindestrichen.", examples=[["packet-too-big", "nd-neighbor-advert"]])

    def to_options(self) -> FirewallOptions:
        return FirewallOptions(
            idempotent=self.idempotent,
            group_rules=self.group_rules,
            cisco_return=self.cisco_return,
            ascii_names=self.ascii_names,
            log_drops=self.log_drops,
            icmpv6_types=tuple(self.icmpv6_types),
        )


class FirewallRequest(ConfigRequest):
    firewall: Literal["iptables", "nftables", "cisco"] = Field(description="Zielsystem, für das der Regeltext generiert wird.")
    options: FirewallSettings = Field(default_factory=FirewallSettings, description="Optionen für Gruppierung, Kommentare, Logging und Rückverkehr.")


class WarningsRequest(ConfigRequest):
    threshold: float = Field(default=80.0, ge=0, le=100, description="Auslastungsschwelle in Prozent, ab der ein Hinweis ausgegeben wird.", examples=[80])
    vpn_networks: list[str] = Field(default_factory=list, description="Fremde IPv4-/IPv6-Netze, auf Überschneidungen mit den Plan-Pools zu prüfen.", examples=[["10.0.0.0/8", "2001:db8:100::/48"]])
    firewall: Literal["none", "iptables", "nftables", "cisco"] = Field(default="none", description="Firewall-System, dessen besondere Warnungen berücksichtigt werden sollen.")
    cisco_return: Literal["none", "established"] = Field(default="none", description="Cisco-Rückverkehrsmodus; beeinflusst Hinweise zu zustandslosen ACLs.")


class RoundtripRequest(ConfigRequest):
    firewalls: list[Literal["iptables", "nftables", "cisco"]] = Field(
        default_factory=lambda: ["iptables", "nftables", "cisco"],
        description="Firewall-Systeme, deren generierte Regeln zurückgelesen und geprüft werden.",
        examples=[["iptables", "nftables", "cisco"]],
    )
    options: FirewallSettings = Field(default_factory=FirewallSettings, description="Dieselben Generatoroptionen wie bei `POST /api/v1/plans/firewall`.")


class CompareRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"config_a": {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 30, "access": ["B"]}, {"name": "B", "hosts": 10}]}, "config_b": {"base_network": "10.1.0.0/24", "groups": [{"name": "A", "hosts": 30}, {"name": "B", "hosts": 10, "access": ["A"]}]}}]})

    config_a: dict[str, Any] = Field(description="Konfiguration der ersten Zugriffspolitik A.")
    config_b: dict[str, Any] = Field(description="Konfiguration der zweiten Zugriffspolitik B.")
    overrides_a: dict[str, Any] = Field(default_factory=dict, description="Optionale Planungsüberschreibungen für A.")
    overrides_b: dict[str, Any] = Field(default_factory=dict, description="Optionale Planungsüberschreibungen für B.")


class VerdictRequest(ConfigRequest):
    source: str = Field(description="Zu prüfende Quell-IP-Adresse, nicht CIDR-Netz.", examples=["10.20.0.10"])
    target: str = Field(description="Zu prüfende Ziel-IP-Adresse, nicht CIDR-Netz.", examples=["10.20.1.20"])
    state: Literal["new", "established"] = Field(default="new", description="`new` prüft die Zugriffsmatrix; `established` wird in der zustandsbehafteten Firewall-Semantik angenommen.")
    ingress_group: str | None = Field(default=None, description="Optionaler Gruppenname, um zusätzlich das Urteil der eingehenden Cisco-ACL dieser Gruppe zu berechnen.", examples=["Server"])
    service: str | None = Field(default=None, description="Optionaler Zieldienst des Pakets, z. B. `tcp/443`, `udp/53` oder `icmp`. Ohne Angabe genügt irgendeine Freigabe des Gruppenpaares.", examples=["tcp/443"])


def _make_plan(config: dict[str, Any], overrides: dict[str, Any] | None = None) -> tuple[Any, Plan]:
    cfg = build_config(config, overrides)
    return cfg, plan_subnets(cfg)


def _plan_payload(plan: Plan) -> dict[str, Any]:
    return json.loads(render_json(plan))


def _network_list(values: list[str]) -> list[Any]:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise PlanError(f"Ungültiges VPN-Netz {value!r}: {exc}") from exc
    return networks


def _pair_payload(pairs: Any) -> list[dict[str, str]]:
    return [{"source": str(source), "target": str(target)} for source, target in sorted(pairs, key=lambda pair: (str(pair[0]), str(pair[1])))]


SEQUENCE_KEY: bytes | None = os.getenv("SUBNETPLAN_SEQUENCE_KEY", "").encode() or None
SEQUENCE_TTL = int(os.getenv("SUBNETPLAN_SEQUENCE_TTL", "600"))
_graph_path = os.getenv("SUBNETPLAN_SEQUENCE_GRAPH")
SEQUENCE_GRAPH = load_graph(_graph_path) if _graph_path else DEFAULT_GRAPH
_now = time.time


def sequence_guard(node: str):
    """Abhängigkeit je Endpunkt: prüft die optionale Sequenz zustandslos über das Token im Header.

    Ohne `X-Sequence-*`-Kopfzeilen geschieht nichts. Ein gültiger Schritt liefert das nächste
    Token in `X-Sequence-Token` (nach `X-Sequence-End: true` keines mehr). Schlägt der Endpunkt
    selbst fehl (zum Beispiel 422), wird kein neues Token ausgegeben: der Schritt zählt nicht.
    """

    def guard(
        response: Response,
        x_sequence_start: str | None = Header(default=None, description="Kennung der Folge; nur im ersten Schritt."),
        x_sequence_token: str | None = Header(default=None, description="Token aus der Antwort des vorigen Schritts."),
        x_sequence_end: str | None = Header(default=None, description="`true` markiert diesen Schritt als letzten der Folge."),
    ) -> None:
        if x_sequence_start is None and x_sequence_token is None and x_sequence_end is None:
            return
        if SEQUENCE_KEY is None:
            raise SequenceError(
                "not_configured",
                "Die Sequenzprüfung ist nicht eingerichtet (SUBNETPLAN_SEQUENCE_KEY fehlt)",
                status=503,
            )
        result = advance(
            SEQUENCE_GRAPH,
            SEQUENCE_KEY,
            node,
            start=x_sequence_start,
            token=x_sequence_token,
            end=(x_sequence_end or "").strip().lower() == "true",
            now=_now(),
            ttl=SEQUENCE_TTL,
        )
        if result.token is not None:
            response.headers["X-Sequence-Token"] = result.token

    return guard


@app.exception_handler(SequenceError)
async def sequence_error_handler(_: Request, exc: SequenceError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content=exc.body)


@app.exception_handler(PlanError)
async def plan_error_handler(_: Request, exc: PlanError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": {"type": "plan_error", "message": str(exc)}})


@app.get(
    f"{API_PREFIX}/health",
    tags=["meta"],
    summary="API-Erreichbarkeit prüfen",
    description="Liefert einen einfachen Prozessstatus. Der Endpunkt führt keine Probe der Planungsabhängigkeiten oder externen Dienste aus.",
    response_model=HealthResponse,
    responses={503: {"description": "Der API-Dienst ist nicht verfügbar."}},
)
def health() -> dict[str, str]:
    """Gibt `ok` zurück, wenn der API-Prozess Anfragen entgegennehmen kann."""
    return {"status": "ok"}


@app.get(
    f"{API_PREFIX}/options",
    tags=["meta"],
    summary="Unterstützte Optionen abrufen",
    description="Gibt die Strategien, Gateway-Positionen, Ausgabeformate, Firewall-Ziele und Cisco-Rückverkehrsmodi zurück. Die Werte eignen sich zum Aufbau von Client-Auswahllisten.",
    response_model=OptionsResponse,
)
def options() -> dict[str, Any]:
    """Liefert die von Konfiguration und Firewall-Generatoren akzeptierten Auswahlwerte."""
    return {
        "strategies": list(STRATEGIES),
        "gateway_positions": list(GATEWAY_POSITIONS),
        "formats": list(FORMATS),
        "firewalls": list(FIREWALLS),
        "cisco_return_modes": ["none", "established"],
    }


@app.post(
    f"{API_PREFIX}/plans",
    dependencies=[Depends(sequence_guard("plans"))],
    tags=["plans"],
    summary="Subnetzplan berechnen",
    description="Validiert die übergebene Konfiguration, berechnet VLAN-IDs und Subnetze und liefert Plan, freie Bereiche und Belegungswerte. Die Konfiguration muss `base_network` und mindestens eine Gruppe enthalten. Mit `overrides` lassen sich unterstützte Konfigurationswerte für diese Berechnung überschreiben.",
    response_model=PlanResponse,
    response_model_exclude_none=True,
    responses=COMMON_RESPONSES,
)
def create_plan(request: ConfigRequest) -> dict[str, Any]:
    """Berechnet einen neuen Plan und serialisiert ihn im selben Schema wie der CLI-JSON-Output."""
    _, plan = _make_plan(request.config, request.overrides)
    return _plan_payload(plan)


@app.post(
    f"{API_PREFIX}/plans/extend",
    dependencies=[Depends(sequence_guard("extend"))],
    tags=["plans"],
    summary="Bestehenden Plan erweitern",
    description="Nimmt ein zuvor von dieser API ausgegebenes Plan-JSON und eine Konfiguration neuer Gruppen entgegen. Bereits belegte Subnetze werden erhalten; die Konfiguration darf `base_network` auslassen, da das Basisnetz aus dem Plan übernommen wird. `access` der neuen Gruppen darf auch bestehende Gruppen referenzieren.",
    response_model=PlanResponse,
    response_model_exclude_none=True,
    responses=COMMON_RESPONSES,
)
def extend_existing_plan(request: ExtendRequest) -> dict[str, Any]:
    """Plant zusätzliche Gruppen in freien Bereichen, ohne bestehende Netze zu verschieben."""
    old_plan = plan_from_json(json.dumps(request.plan))
    cfg, new_groups = build_extension(
        request.config,
        [subnet.group for subnet in old_plan.subnets],
        old_plan.base_network,
        request.overrides,
    )
    return _plan_payload(extend_plan(old_plan, new_groups, cfg))


@app.post(
    f"{API_PREFIX}/plans/verify",
    dependencies=[Depends(sequence_guard("verify"))],
    tags=["analysis"],
    summary="Plan formal verifizieren",
    description="Berechnet den Plan und prüft anschließend die implementierten Planeigenschaften. `valid` ist nur dann `true`, wenn `problems` leer ist. Das Ergebnis enthält zusätzlich den geprüften Plan.",
    response_model=VerificationResponse,
    response_model_exclude_none=True,
    responses=COMMON_RESPONSES,
)
def verify(request: ConfigRequest) -> dict[str, Any]:
    """Gibt Plan, Gesamturteil und gegebenenfalls die Liste verletzter Eigenschaften zurück."""
    cfg, plan = _make_plan(request.config, request.overrides)
    problems = verify_plan(plan, cfg)
    return {"valid": not problems, "problems": problems, "plan": _plan_payload(plan)}


@app.post(
    f"{API_PREFIX}/plans/stats",
    dependencies=[Depends(sequence_guard("stats"))],
    tags=["analysis"],
    summary="Belegungsstatistiken berechnen",
    description="Berechnet pro Gruppe die Blockauslastung sowie Mittelwert, Minimum, Gesamtbedarf, belegte Adressen und internen Verschnitt. Die Kennzahlen beziehen sich auf die tatsächlich zugeteilten Subnetzblöcke.",
    response_model=StatisticsResponse,
    responses=COMMON_RESPONSES,
)
def statistics(request: ConfigRequest) -> dict[str, Any]:
    """Berechnet die Kennzahlen aus Plan und validierter Konfiguration."""
    cfg, plan = _make_plan(request.config, request.overrides)
    stats = plan_statistics(plan, cfg)
    return asdict(stats)


@app.post(
    f"{API_PREFIX}/plans/warnings",
    dependencies=[Depends(sequence_guard("warnings"))],
    tags=["analysis"],
    summary="Planungshinweise ermitteln",
    description="Prüft unter anderem private Adressbereiche, VPN-Überschneidungen, Auslastungsschwellen und Besonderheiten zustandsloser Cisco-ACLs. `threshold` wird als Prozentwert von 0 bis 100 angegeben.",
    response_model=WarningsResponse,
    responses=COMMON_RESPONSES,
)
def warnings(request: WarningsRequest) -> dict[str, Any]:
    """Sammelt Hinweise, ohne die Berechnung als Fehler zu behandeln."""
    cfg, plan = _make_plan(request.config, request.overrides)
    found = plan_warnings(
        plan,
        cfg,
        request.threshold,
        _network_list(request.vpn_networks),
        request.firewall,
        request.cisco_return,
    )
    return {"warnings": found}


@app.post(
    f"{API_PREFIX}/plans/firewall",
    dependencies=[Depends(sequence_guard("firewall"))],
    tags=["firewall"],
    summary="Firewall-Regeln generieren",
    description="Erzeugt einen Regeltext für iptables, nftables oder Cisco-ACLs auf Basis von `access`. Nicht ausdrücklich erlaubter Verkehr wird verworfen. Der Endpunkt gibt Text zurück und spielt Regeln nicht auf einem System ein. Bei IPv6-spezifischen ICMP-Regeln muss das Basisnetz IPv6 sein.",
    response_model=FirewallResponse,
    responses=COMMON_RESPONSES,
)
def firewall(request: FirewallRequest) -> dict[str, str]:
    """Rendert Firewall-Regeln für den angeforderten Zieltyp und die gewählten Optionen."""
    _, plan = _make_plan(request.config, request.overrides)
    rules = render_firewall(plan, request.firewall, request.options.to_options())
    return {"firewall": request.firewall, "rules": rules}


@app.post(
    f"{API_PREFIX}/plans/roundtrip",
    dependencies=[Depends(sequence_guard("roundtrip"))],
    tags=["analysis", "firewall"],
    summary="Firewall-Regeln rückübersetzen und prüfen",
    description="Generiert für jedes angeforderte System intern Regeln, liest die Zugriffspaare zurück und vergleicht sie mit der Zugriffsmatrix. `ok` setzt voraus, dass keine Regeln fehlen oder zusätzlich erlaubt werden und Default-Deny erkannt wird. Ohne `firewalls` werden iptables, nftables und Cisco geprüft.",
    response_model=RoundtripResponse,
    responses=COMMON_RESPONSES,
)
def roundtrip(request: RoundtripRequest) -> dict[str, Any]:
    """Prüft die Übereinstimmung zwischen Zugriffsmatrix und generiertem Regelwerk."""
    _, plan = _make_plan(request.config, request.overrides)
    options = request.options.to_options()
    results = {}
    for kind in request.firewalls:
        result = check_roundtrip(plan, kind, options)
        results[kind] = {
            "ok": result.ok,
            "missing": _pair_payload(result.missing),
            "extra": _pair_payload(result.extra),
            "default_deny": result.default_deny,
            "returns": _pair_payload(result.returns),
            "service_mismatch": _pair_payload(result.service_mismatch),
        }
    return {"results": results}


@app.post(
    f"{API_PREFIX}/plans/compare",
    dependencies=[Depends(sequence_guard("compare"))],
    tags=["analysis"],
    summary="Zwei Zugriffspolitiken vergleichen",
    description="Berechnet zwei Pläne und vergleicht deren Zugriffsmengen exakt sowie zusätzlich mit dem Subgraph Algorithmus. `relation` und `keep` beruhen auf dem exakten Vergleich; `subgraph_agrees` zeigt, ob die heuristische Subgraph-Entscheidung übereinstimmt. Beide Konfigurationen müssen die Gruppen enthalten, deren Zugriffspolitik verglichen wird.",
    response_model=CompareResponse,
    responses={
        **COMMON_RESPONSES,
        503: {"model": ServiceUnavailableResponse, "description": "Der Subgraph Algorithmus ist nicht verfügbar."},
    },
)
def compare(request: CompareRequest) -> dict[str, Any]:
    """Vergleicht die exakten Zugriffsmengen und die zusätzliche Subgraph-Heuristik."""
    _, plan_a = _make_plan(request.config_a, request.overrides_a)
    _, plan_b = _make_plan(request.config_b, request.overrides_b)
    try:
        from subnetplan.policy import compare_policies
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Richtlinienvergleich ist nicht verfügbar") from exc
    return asdict(compare_policies(plan_a, plan_b))


def _service_payload(sigma: ServiceSet) -> list[str]:
    return ["all"] if sigma == ServiceSet.everything() else list(sigma.specs())


@app.post(
    f"{API_PREFIX}/plans/compare-services",
    dependencies=[Depends(sequence_guard("compare-services"))],
    tags=["analysis"],
    summary="Freigegebene Dienste zweier Pläne vergleichen",
    description="Berechnet zwei Pläne und vergleicht je Zugriffspaar die freigegebenen Protokolle und Ports exakt (Teilmengenprüfung je Protokoll). Ein Paar ohne Einschränkung gibt alle Dienste frei, ein Paar ohne Freigabe keinen. `relation` ist `equal`, `a_in_b`, `b_in_a` oder `incomparable`; `differences` nennt die Paare mit unterschiedlicher Dienstmenge. Die Gruppen werden über ihre Namen zugeordnet.",
    response_model=ServiceCompareResponse,
    responses=COMMON_RESPONSES,
)
def compare_services(request: CompareRequest) -> dict[str, Any]:
    """Vergleicht die Dienstmengen aller Zugriffspaare zweier Konfigurationen."""
    _, plan_a = _make_plan(request.config_a, request.overrides_a)
    _, plan_b = _make_plan(request.config_b, request.overrides_b)
    a_in_b = services_included(plan_a, plan_b)
    b_in_a = services_included(plan_b, plan_a)
    relation = "equal" if a_in_b and b_in_a else "a_in_b" if a_in_b else "b_in_a" if b_in_a else "incomparable"
    return {
        "relation": relation,
        "a_in_b": a_in_b,
        "b_in_a": b_in_a,
        "differences": [
            {"source": src, "target": dst, "a": _service_payload(sa), "b": _service_payload(sb)}
            for src, dst, sa, sb in service_differences(plan_a, plan_b)
        ],
    }


@app.post(
    f"{API_PREFIX}/plans/verdict",
    dependencies=[Depends(sequence_guard("verdict"))],
    tags=["analysis"],
    summary="Paketfluss anhand des Plans beurteilen",
    description="Ermittelt die Quell- und Zielgruppe anhand einzelner IP-Adressen und entscheidet `accept` oder `drop`. Etablierte Verbindungen werden in der zustandsbehafteten Semantik angenommen; neue Verbindungen benötigen eine passende `access`-Freigabe. Mit `ingress_group` wird zusätzlich das Urteil der eingehenden Cisco-ACL berechnet.",
    response_model=VerdictResponse,
    response_model_exclude_none=True,
    responses=COMMON_RESPONSES,
)
def verdict(request: VerdictRequest) -> dict[str, Any]:
    """Berechnet Firewall- und optional Cisco-Urteile für einen konkreten IP-Paketfluss."""
    _, plan = _make_plan(request.config, request.overrides)
    result = {
        "firewall": firewall_verdict(plan, request.source, request.target, request.state, request.service),
        "source_group": (subnet.group if (subnet := locate(plan, request.source)) else None),
        "target_group": (subnet.group if (subnet := locate(plan, request.target)) else None),
    }
    if request.ingress_group is not None:
        result["cisco"] = cisco_verdict(plan, request.ingress_group, request.source, request.target, request.service)
    return result


def run() -> None:
    """Console entry point for ``subnetplan-api``."""
    import uvicorn

    uvicorn.run(
        "web.api:app",
        host=os.getenv("SUBNETPLAN_API_HOST", "127.0.0.1"),
        port=int(os.getenv("SUBNETPLAN_API_PORT", "8000")),
    )
