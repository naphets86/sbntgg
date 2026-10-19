"""Inkrementelle Planung: Plan laden, erweitern, Netze an Ort und Stelle verdoppeln.

Umgesetzt werden Korollar "Verlustfreie Erweiterbarkeit" (bestehende Subnetze bleiben
unverändert) und der Hinweis aus dem Ausblick zur Verdopplung eines Netzes: Ein Netz lässt
sich an Ort und Stelle verdoppeln, wenn es die linke Hälfte seines Elternblocks ist und
dessen rechte Hälfte frei ist.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .blocks import free_ranges_in_pool, maximal_free_blocks, pack, packable
from .models import Group, IPNetwork, Plan, PlanConfig, PlanError, Subnet
from .planner import _build_subnet, _ordered, assign_vlans, group_prefix


def plan_from_json(text: str) -> Plan:
    """Liest einen mit ``--format json`` erzeugten Plan wieder ein."""
    try:
        data = json.loads(text)
        base = ipaddress.ip_network(data["base_network"])
        subnets = tuple(_subnet_from_dict(d) for d in data["subnets"])
        pools = tuple(ipaddress.ip_network(p) for p in data.get("pools", []))
        reserved = tuple(ipaddress.ip_network(r) for r in data.get("reserved", []))
        free = tuple(ipaddress.ip_network(f) for f in data["free_ranges"])
    except (ValueError, KeyError, TypeError) as exc:
        raise PlanError(f"Plan-Datei ist kein gültiger Plan im JSON-Format: {exc}") from exc
    return Plan(base, subnets, free, pools, reserved)


def _subnet_from_dict(d: Dict[str, Any]) -> Subnet:
    def opt(key: str) -> Optional[Any]:
        return None if d.get(key) is None else ipaddress.ip_address(d[key])

    return Subnet(
        group=d["group"],
        vlan_id=int(d["vlan_id"]),
        requested_hosts=int(d["requested_hosts"]),
        network=ipaddress.ip_network(d["network"]),
        gateway=opt("gateway"),
        first_host=ipaddress.ip_address(d["first_host"]),
        last_host=ipaddress.ip_address(d["last_host"]),
        broadcast=opt("broadcast"),
        usable_hosts=int(d["usable_hosts"]),
        access=tuple(d.get("access", [])),
        site=d.get("site"),
    )


def _occupied(plan: Plan) -> List[IPNetwork]:
    return [s.network for s in plan.subnets] + list(plan.reserved)


def current_free_blocks(plan: Plan) -> Tuple[IPNetwork, ...]:
    """Maximale freie Blöcke des Plans (aus den belegten Netzen neu berechnet)."""
    return maximal_free_blocks(plan.all_pools, _occupied(plan))


def extend_plan(plan: Plan, new_groups: Sequence[Group], cfg: PlanConfig) -> Plan:
    """Ergänzt neue Gruppen, ohne ein bestehendes Subnetz zu verschieben.

    ``cfg`` liefert Wachstumsfaktor, Strategie und Gateway-Position für die *neuen*
    Gruppen (``cfg.groups`` wird ignoriert). Bestehende Subnetze und VLAN-IDs bleiben
    unverändert; neue VLAN-IDs kollidieren nicht mit vorhandenen. Nach Korollar
    "Verlustfreie Erweiterbarkeit" geht dabei keine Kapazität gegenüber einer Neuplanung
    verloren.
    """
    if not new_groups:
        raise PlanError("Keine neuen Gruppen zum Ergänzen angegeben")
    old_names = {s.group for s in plan.subnets}
    clash = sorted(g.name for g in new_groups if g.name in old_names)
    if clash:
        raise PlanError(f"Gruppen existieren bereits im Plan: {clash}")
    known = old_names | {g.name for g in new_groups}
    for g in new_groups:
        missing = sorted(set(g.access) - known)
        if missing:
            raise PlanError(f"Gruppe {g.name!r}: access verweist auf unbekannte Gruppen {missing}")
    if any(g.network is not None or g.site is not None for g in new_groups):
        raise PlanError("Neue Gruppen dürfen beim Erweitern weder 'network' noch 'site' angeben")

    used_vlans = {s.vlan_id for s in plan.subnets}
    explicit = [g.vlan_id for g in new_groups if g.vlan_id is not None]
    clash_vlan = sorted(set(explicit) & used_vlans)
    if clash_vlan:
        raise PlanError(f"VLAN-IDs bereits vergeben: {clash_vlan}")

    width = plan.base_network.max_prefixlen
    sub_cfg = replace(cfg, base_network=plan.base_network, groups=tuple(new_groups), pools=(), existing=())
    sized = [(g, group_prefix(g, sub_cfg)) for g in new_groups]
    if cfg.allocation_strategy == "fixed":
        uniform = min(p for _, p in sized)
        sized = [(g, uniform) for g, _ in sized]
    order = _ordered(sized, cfg.allocation_strategy)
    items = [(g.name, 1 << (width - prefix)) for g, prefix in order]

    free = current_free_blocks(plan)
    if not packable(free, [size for _, size in items]):
        raise PlanError(
            "Platzmangel: die neuen Gruppen passen nicht in die freien Bereiche des Plans"
        )
    placed = pack(free, items)

    # VLAN-Vergabe: vorhandene IDs als "explizit" behandeln, dann nur die neuen Gruppen zuweisen.
    pseudo = [Group(f"__old{i}", 1, v) for i, v in enumerate(sorted(used_vlans))] + list(new_groups)
    vlans = assign_vlans(pseudo)
    by_name = {g.name: g for g in new_groups}
    added = [
        _build_subnet(by_name[name], vlans[name], net, cfg.gateway_position) for name, net in placed.items()
    ]
    subnets = sorted(list(plan.subnets) + added, key=lambda s: int(s.network.network_address))
    remaining = maximal_free_blocks(plan.all_pools, [s.network for s in subnets] + list(plan.reserved))
    return Plan(plan.base_network, tuple(subnets), remaining, plan.pools, plan.reserved, plan.site_blocks)


def _infer_gateway_position(subnet: Subnet) -> str:
    if subnet.gateway is None:
        return "none"
    if int(subnet.gateway) == int(subnet.network.network_address) + 1:
        return "first"
    return "last"


def can_double(plan: Plan, group: str) -> bool:
    """Ob das Netz der Gruppe an Ort und Stelle verdoppelt werden kann.

    Bedingung: linke Hälfte des Elternblocks und die rechte Hälfte liegt vollständig im
    freien Adressraum des Plans.
    """
    subnet = next((s for s in plan.subnets if s.group == group), None)
    if subnet is None:
        raise PlanError(f"Unbekannte Gruppe {group!r}")
    net = subnet.network
    if net.prefixlen == 0:
        return False
    parent = net.supernet(prefixlen_diff=1)
    if parent.network_address != net.network_address:  # rechte Hälfte: Verdoppeln würde verschieben
        return False
    if not any(parent.subnet_of(p) for p in plan.all_pools):  # type: ignore[arg-type]
        return False
    sibling = next(h for h in parent.subnets() if h != net)
    return any(sibling.subnet_of(b) for b in current_free_blocks(plan))  # type: ignore[arg-type]


def double_in_place(plan: Plan, group: str) -> Plan:
    """Verdoppelt das Netz einer Gruppe (Präfixlänge -1) ohne Umnummerierung der Hosts.

    Netzadresse, VLAN-ID und (bei Gateway ``first``/``none``) alle Hostadressen bleiben
    gleich; bei Gateway ``last`` wandert das Gateway ans neue Blockende.
    """
    if not can_double(plan, group):
        raise PlanError(
            f"Gruppe {group!r}: das Netz kann nicht an Ort und Stelle verdoppelt werden "
            "(es muss die linke Hälfte seines Elternblocks sein und die rechte Hälfte frei)"
        )
    subnet = next(s for s in plan.subnets if s.group == group)
    parent = subnet.network.supernet(prefixlen_diff=1)
    gateway_position = _infer_gateway_position(subnet)
    overhead = subnet.network.num_addresses - subnet.usable_hosts
    template = Group(
        subnet.group, subnet.requested_hosts, subnet.vlan_id, subnet.access, 0, overhead, None, subnet.site
    )
    grown = _build_subnet(template, subnet.vlan_id, parent, gateway_position)
    subnets = tuple(grown if s.group == group else s for s in plan.subnets)
    remaining = maximal_free_blocks(plan.all_pools, [s.network for s in subnets] + list(plan.reserved))
    return Plan(plan.base_network, subnets, remaining, plan.pools, plan.reserved, plan.site_blocks)


def renumbered_hosts(old: Subnet, new: Subnet) -> int:
    """Zahl der Adressen, die sich beim Wechsel von ``old`` zu ``new`` ändern (Gateway/Hosts)."""
    old_hosts = set(range(int(old.first_host), int(old.last_host) + 1))
    new_hosts = set(range(int(new.first_host), int(new.last_host) + 1))
    changed = len(old_hosts - new_hosts)
    if old.gateway != new.gateway:
        changed += 1
    return changed
