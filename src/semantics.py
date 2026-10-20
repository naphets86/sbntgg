"""Urteilsfunktionen der erzeugten Regeln (Sätze "Default-Deny-Korrektheit" und "Cisco-Semantik").

Die Funktionen berechnen das Urteil, das die erzeugten Regelwerke nach den Sätzen der Arbeit
fällen. Sie dienen als Referenz für Tests und für die Rückübersetzung (``roundtrip``).

Mit dem optionalen Zieldienst gilt der Satz "Default-Deny-Korrektheit mit Diensten": ein neues
Paket wird genau dann angenommen, wenn Quelle und Ziel in verschiedenen Gruppen i, j liegen und
der Dienst in ``Sigma_ij`` enthalten ist. Ohne Dienstangabe entscheidet nur das Paar (i, j).
"""
from __future__ import annotations

import ipaddress
from typing import Optional, Tuple, Union

from .models import IPAddress, Plan, PlanError, Subnet
from .ports import ServiceSet, parse_service

AddressLike = Union[str, IPAddress]
ServiceLike = Union[str, Tuple[str, Optional[int]]]


def _addr(value: AddressLike) -> IPAddress:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise PlanError(f"Ungültige Adresse {value!r}: {exc}") from exc


def locate(plan: Plan, address: AddressLike) -> Optional[Subnet]:
    """Das Subnetz, das die Adresse enthält (nach (K3) höchstens eines), sonst None."""
    addr = _addr(address)
    for subnet in plan.subnets:
        if subnet.network.version == addr.version and addr in subnet.network:
            return subnet
    return None


def _parsed(service: Optional[ServiceLike]) -> Optional[Tuple[str, Optional[int]]]:
    return None if service is None else parse_service(service)


def _permitted(src: Subnet, dst: Subnet, service: Optional[Tuple[str, Optional[int]]] = None) -> bool:
    """Gibt ``src`` das Ziel ``dst`` frei (und, falls angegeben, für den Dienst)?"""
    if src.group == dst.group or dst.group not in src.access:
        return False
    sigma: Optional[ServiceSet] = dict(src.services).get(dst.group)
    if service is None or sigma is None:
        return True
    return sigma.contains(*service)


def firewall_verdict(
    plan: Plan,
    source: AddressLike,
    target: AddressLike,
    state: str = "new",
    service: Optional[ServiceLike] = None,
) -> str:
    """Urteil von iptables/nftables: ``accept`` oder ``drop``.

    ``state`` ist ``new`` oder ``established`` (umfasst auch *related*). Etablierte Pakete
    werden immer angenommen; neue nur, wenn es Gruppen i != j mit Quelle in N_i, Ziel in N_j
    und g_j in acc(g_i) gibt. Alles andere, auch Verkehr ins Internet, wird verworfen.
    ``service`` (``"tcp/443"``, ``("udp", 53)`` oder ``"icmp"``) schränkt zusätzlich auf die
    freigegebenen Dienste ein; ohne Angabe genügt irgendeine Freigabe des Paares.
    """
    if state not in ("new", "established"):
        raise PlanError(f"Unbekannter Zustand {state!r}, erlaubt: ['established', 'new']")
    parsed = _parsed(service)
    if state == "established":
        return "accept"
    src = locate(plan, source)
    dst = locate(plan, target)
    if src is not None and dst is not None and _permitted(src, dst, parsed):
        return "accept"
    return "drop"


def cisco_verdict(
    plan: Plan,
    ingress_group: str,
    source: AddressLike,
    target: AddressLike,
    service: Optional[ServiceLike] = None,
) -> str:
    """Urteil der eingehenden Cisco-ACL am Interface der Gruppe ``ingress_group``.

    Weitergeleitet wird genau dann, wenn die Quelle im eigenen Subnetz liegt (Schutz vor
    gefälschten Quellen) und das Ziel in einer freigegebenen anderen Gruppe.
    """
    own = next((s for s in plan.subnets if s.group == ingress_group), None)
    if own is None:
        raise PlanError(f"Unbekannte Gruppe {ingress_group!r}")
    parsed = _parsed(service)
    src_addr = _addr(source)
    if src_addr.version != own.network.version or src_addr not in own.network:
        return "drop"
    dst = locate(plan, target)
    if dst is not None and _permitted(own, dst, parsed):
        return "accept"
    return "drop"
