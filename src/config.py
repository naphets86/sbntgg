"""Laden und Validieren der Konfiguration (YAML oder JSON)."""
from __future__ import annotations

import ipaddress
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import yaml

from .access import clean_access
from .models import (
    GATEWAY_POSITIONS,
    GROUP_KEYS,
    NAME_RE,
    STRATEGIES,
    TOP_KEYS,
    VLAN_MAX,
    VLAN_MIN,
    Group,
    IPNetwork,
    PlanConfig,
    PlanError,
)


def _as_int(value: Any, label: str, minimum: int, maximum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanError(f"{label}: ganze Zahl erwartet, erhalten {value!r}")
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f">= {minimum}" if maximum is None else f"{minimum}..{maximum}"
        raise PlanError(f"{label}: Wert {value} außerhalb des erlaubten Bereichs ({bounds})")
    return value


def _parse_network(value: Any, label: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(value), strict=True)
    except ValueError as exc:
        raise PlanError(f"{label} {value!r} ist ungültig: {exc}") from exc


def _parse_base_network(value: Any) -> IPNetwork:
    return _parse_network(value, "base_network")


def _parse_group(raw: Any, index: int) -> Group:
    where = f"Gruppe #{index}"
    if not isinstance(raw, dict):
        raise PlanError(f"{where}: Mapping erwartet, erhalten {type(raw).__name__}")
    unknown = set(raw) - GROUP_KEYS
    if unknown:
        raise PlanError(f"{where}: unbekannte Schlüssel {sorted(map(str, unknown))}")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PlanError(f"{where}: 'name' fehlt oder ist leer")
    name = name.strip()
    if not NAME_RE.fullmatch(name):
        raise PlanError(
            f"{where}: Name {name!r} enthält unzulässige Zeichen "
            "(erlaubt: Buchstaben, Ziffern, '_', '-', Leerzeichen)"
        )
    where = f"Gruppe {name!r}"

    hosts = _as_int(raw.get("hosts"), f"{where}: hosts", 1)
    vlan_raw = raw.get("vlan_id")
    vlan_id = None if vlan_raw is None else _as_int(vlan_raw, f"{where}: vlan_id", VLAN_MIN, VLAN_MAX)
    priority = _as_int(raw.get("priority", 0), f"{where}: priority", 0)

    access = raw.get("access", [])
    if not isinstance(access, list) or not all(isinstance(a, str) for a in access):
        raise PlanError(f"{where}: 'access' muss eine Liste von Gruppennamen sein")

    overhead_raw = raw.get("overhead")
    overhead = None if overhead_raw is None else _as_int(overhead_raw, f"{where}: overhead", 0)
    network_raw = raw.get("network")
    network = None if network_raw is None else _parse_network(network_raw, f"{where}: network")

    site_raw = raw.get("site")
    site: Optional[str] = None
    if site_raw is not None:
        if not isinstance(site_raw, str) or not site_raw.strip() or not NAME_RE.fullmatch(site_raw.strip()):
            raise PlanError(
                f"{where}: 'site' muss ein nichtleerer Name sein "
                "(erlaubt: Buchstaben, Ziffern, '_', '-', Leerzeichen)"
            )
        site = site_raw.strip()
    return Group(name, hosts, vlan_id, tuple(a.strip() for a in access), priority, overhead, network, site)


def _check_groups(groups: Sequence[Group]) -> None:
    """Validierung in O(n + a) mit Zählern statt ``list.count``."""
    name_counts = Counter(g.name for g in groups)
    duplicates = sorted(n for n, c in name_counts.items() if c > 1)
    if duplicates:
        raise PlanError(f"Doppelte Gruppennamen: {duplicates}")

    vlan_counts = Counter(g.vlan_id for g in groups if g.vlan_id is not None)
    dup_vlans = sorted(v for v, c in vlan_counts.items() if c > 1)
    if dup_vlans:
        raise PlanError(f"Doppelte VLAN-IDs: {dup_vlans}")

    known = set(name_counts)
    for g in groups:
        missing = sorted(set(g.access) - known)
        if missing:
            raise PlanError(f"Gruppe {g.name!r}: access verweist auf unbekannte Gruppen {missing}")

    with_site = [g for g in groups if g.site is not None]
    if with_site and len(with_site) != len(groups):
        raise PlanError("'site' muss entweder für alle Gruppen oder für keine angegeben werden")


def _parse_network_list(value: Any, key: str, base: IPNetwork) -> Tuple[IPNetwork, ...]:
    if not isinstance(value, list):
        raise PlanError(f"'{key}' muss eine Liste von Netzen sein")
    nets: List[IPNetwork] = []
    for item in value:
        net = _parse_network(item, f"{key}-Eintrag")
        if net.version != base.version:
            raise PlanError(f"{key}-Eintrag {net} hat eine andere IP-Version als base_network {base}")
        nets.append(net)
    return tuple(nets)


def build_config(raw: Any, overrides: Optional[Dict[str, Any]] = None) -> PlanConfig:
    """Validiert die Rohdaten (YAML/JSON) und wendet CLI-Overrides an."""
    if not isinstance(raw, dict):
        raise PlanError("Die Konfiguration muss ein Mapping (Schlüssel: Wert) sein")
    data = dict(raw)
    for key, value in (overrides or {}).items():
        if value is not None:
            data[key] = value

    unknown = set(data) - TOP_KEYS
    if unknown:
        raise PlanError(f"Unbekannte Schlüssel in der Konfiguration: {sorted(map(str, unknown))}")
    if "base_network" not in data:
        raise PlanError("Pflichtfeld 'base_network' fehlt")
    base = _parse_base_network(data["base_network"])

    growth = data.get("growth_factor", 1.25)
    if (
        isinstance(growth, bool)
        or not isinstance(growth, (int, float))
        or not math.isfinite(growth)
        or growth < 1.0
    ):
        raise PlanError(f"growth_factor muss eine Zahl >= 1.0 sein, erhalten {growth!r}")

    strategy = data.get("allocation_strategy", "vlsm")
    if strategy not in STRATEGIES:
        raise PlanError(f"allocation_strategy {strategy!r} ungültig, erlaubt: {list(STRATEGIES)}")

    gateway = data.get("gateway_position", "first")
    if gateway not in GATEWAY_POSITIONS:
        raise PlanError(f"gateway_position {gateway!r} ungültig, erlaubt: {list(GATEWAY_POSITIONS)}")

    max_prefix_raw = data.get("max_prefix")
    max_prefix = (
        None
        if max_prefix_raw is None
        else _as_int(max_prefix_raw, "max_prefix", 0, base.max_prefixlen)
    )

    pools = _parse_network_list(data["pools"], "pools", base) if "pools" in data else ()
    existing = _parse_network_list(data["existing"], "existing", base) if "existing" in data else ()

    raw_groups = data.get("groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise PlanError("'groups' muss eine nicht-leere Liste sein")
    groups = tuple(_parse_group(g, i) for i, g in enumerate(raw_groups, start=1))
    _check_groups(groups)
    for g in groups:
        if g.network is not None and g.network.version != base.version:
            raise PlanError(f"Gruppe {g.name!r}: network {g.network} hat eine andere IP-Version als {base}")

    groups, warnings = clean_access(groups)
    return PlanConfig(
        base, groups, float(growth), strategy, gateway, max_prefix, pools, existing, warnings
    )


def build_extension(
    raw: Any, existing_groups: Sequence[str], base_network: Any, overrides: Optional[Dict[str, Any]] = None
) -> Tuple[PlanConfig, Tuple[Group, ...]]:
    """Validiert eine Erweiterungs-Konfiguration (für ``--extend``).

    ``existing_groups`` sind die Namen der Gruppen des bestehenden Plans: ``access`` darf auf
    sie verweisen, und neue Gruppen dürfen ihre Namen nicht wiederverwenden. Fehlt
    ``base_network`` in der Datei, wird das des bestehenden Plans verwendet.
    Rückgabe: Konfiguration (für Faktor, Strategie, Gateway) und die neuen Gruppen.
    """
    if not isinstance(raw, dict):
        raise PlanError("Die Konfiguration muss ein Mapping (Schlüssel: Wert) sein")
    data = dict(raw)
    data.setdefault("base_network", str(base_network))
    new_raw = data.get("groups")
    if not isinstance(new_raw, list) or not new_raw:
        raise PlanError("'groups' muss eine nicht-leere Liste sein")
    placeholders = [{"name": name, "hosts": 1} for name in existing_groups]
    data["groups"] = placeholders + list(new_raw)
    cfg = build_config(data, overrides)
    return cfg, cfg.groups[len(placeholders) :]


def load_config_file(path: Union[str, Path]) -> Any:
    """Liest eine YAML- oder JSON-Datei (anhand der Endung)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"Konfigurationsdatei nicht lesbar: {exc}") from exc
    try:
        if p.suffix.lower() == ".json":
            return json.loads(text)
        return yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise PlanError(f"Konfigurationsdatei {p} ist kein gültiges YAML/JSON: {exc}") from exc
