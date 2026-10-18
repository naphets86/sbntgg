"""Laden und Validieren der Konfiguration (YAML oder JSON)."""
from __future__ import annotations

import ipaddress
import json
import math
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Union

import yaml

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


def _parse_base_network(value: Any) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(value), strict=True)
    except ValueError as exc:
        raise PlanError(f"base_network {value!r} ist ungültig: {exc}") from exc


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
    return Group(name, hosts, vlan_id, tuple(a.strip() for a in access), priority)


def _check_groups(groups: Sequence[Group]) -> None:
    names = [g.name for g in groups]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise PlanError(f"Doppelte Gruppennamen: {duplicates}")

    vlans = [g.vlan_id for g in groups if g.vlan_id is not None]
    dup_vlans = sorted({v for v in vlans if vlans.count(v) > 1})
    if dup_vlans:
        raise PlanError(f"Doppelte VLAN-IDs: {dup_vlans}")

    known = set(names)
    for g in groups:
        missing = sorted(set(g.access) - known)
        if missing:
            raise PlanError(f"Gruppe {g.name!r}: access verweist auf unbekannte Gruppen {missing}")


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

    raw_groups = data.get("groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise PlanError("'groups' muss eine nicht-leere Liste sein")
    groups = tuple(_parse_group(g, i) for i, g in enumerate(raw_groups, start=1))
    _check_groups(groups)

    return PlanConfig(base, groups, float(growth), strategy, gateway)


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
