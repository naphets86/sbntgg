"""Berechnung der Subnetze (VLSM oder feste Präfixlänge)."""
from __future__ import annotations

import ipaddress
import math
from typing import Dict, List, Optional, Sequence, Tuple

from .models import (
    AUTO_VLAN_START,
    AUTO_VLAN_STEP,
    VLAN_MAX,
    Group,
    IPAddress,
    IPNetwork,
    Plan,
    PlanConfig,
    PlanError,
    Subnet,
)


def required_addresses(group: Group, growth_factor: float, gateway_position: str, version: int) -> int:
    """Adressen inkl. Wachstumsreserve und Overhead (Netz, Broadcast, Gateway)."""
    wanted = math.ceil(round(group.hosts * growth_factor, 9))
    overhead = 2 if version == 4 else 1  # IPv6 kennt keinen Broadcast
    if gateway_position != "none":
        overhead += 1
    return wanted + overhead


def prefix_for(total: int, max_prefix: int, name: str) -> int:
    """Kleinste Präfixlänge, deren Block mindestens ``total`` Adressen fasst."""
    prefix = max_prefix - (total - 1).bit_length()
    if prefix < 0:
        raise PlanError(f"Gruppe {name!r}: {total} Adressen passen in keinen Adressraum")
    return prefix


def assign_vlans(groups: Sequence[Group]) -> Dict[str, int]:
    """Explizite VLAN-IDs übernehmen, fehlende automatisch vergeben (10, 20, ...)."""
    used = {g.vlan_id for g in groups if g.vlan_id is not None}
    result: Dict[str, int] = {}
    candidate = AUTO_VLAN_START
    for g in groups:
        if g.vlan_id is not None:
            result[g.name] = g.vlan_id
            continue
        while candidate in used:
            candidate += AUTO_VLAN_STEP
        if candidate > VLAN_MAX:
            raise PlanError("Keine freie VLAN-ID mehr verfügbar")
        used.add(candidate)
        result[g.name] = candidate
    return result


def _build_subnet(group: Group, vlan_id: int, net: IPNetwork, gateway_position: str) -> Subnet:
    first = net.network_address + 1
    broadcast: Optional[IPAddress]
    if net.version == 4:
        broadcast = net.broadcast_address
        last = net.broadcast_address - 1
    else:
        broadcast = None
        last = net.broadcast_address  # letzte Adresse des Blocks
    gateway = None
    if gateway_position == "first":
        gateway, first = first, first + 1
    elif gateway_position == "last":
        gateway, last = last, last - 1
    usable = int(last) - int(first) + 1
    return Subnet(
        group=group.name,
        vlan_id=vlan_id,
        requested_hosts=group.hosts,
        network=net,
        gateway=gateway,
        first_host=first,
        last_host=last,
        broadcast=broadcast,
        usable_hosts=usable,
        access=group.access,
    )


def _free_ranges(base: IPNetwork, nets: Sequence[IPNetwork]) -> Tuple[IPNetwork, ...]:
    addr = type(base.network_address)
    pos = int(base.network_address)
    end = int(base.broadcast_address)
    free: List[IPNetwork] = []
    for net in sorted(nets, key=lambda n: int(n.network_address)):
        start = int(net.network_address)
        if start > pos:
            free.extend(ipaddress.summarize_address_range(addr(pos), addr(start - 1)))
        pos = int(net.broadcast_address) + 1
    if pos <= end:
        free.extend(ipaddress.summarize_address_range(addr(pos), addr(end)))
    return tuple(free)


def plan_subnets(cfg: PlanConfig) -> Plan:
    """Berechnet die Subnetze (VLSM: größte zuerst; fixed: einheitliche Länge)."""
    base = cfg.base_network
    max_prefix = base.max_prefixlen
    sized = [
        (
            g,
            prefix_for(
                required_addresses(g, cfg.growth_factor, cfg.gateway_position, base.version),
                max_prefix,
                g.name,
            ),
        )
        for g in cfg.groups
    ]

    if cfg.allocation_strategy == "fixed":
        uniform = min(prefix for _, prefix in sized)  # kleinste Länge = größter Block
        sized = [(g, uniform) for g, _ in sized]
        order = sorted(sized, key=lambda item: item[0].priority)
    else:
        order = sorted(sized, key=lambda item: (item[1], item[0].priority))

    vlans = assign_vlans(cfg.groups)
    net_cls = type(base)
    cursor = int(base.network_address)
    end = int(base.broadcast_address)
    subnets: List[Subnet] = []

    for group, prefix in order:
        if prefix < base.prefixlen:
            raise PlanError(
                f"Platzmangel: Gruppe {group.name!r} benötigt ein /{prefix}, "
                f"das Basisnetz {base} ist kleiner"
            )
        size = 1 << (max_prefix - prefix)
        start = -(-cursor // size) * size  # auf Blockgrenze aufrunden
        if start + size - 1 > end:
            raise PlanError(
                f"Platzmangel: Gruppe {group.name!r} (/{prefix}) passt nicht mehr in {base}"
            )
        net = net_cls((start, prefix))
        subnets.append(_build_subnet(group, vlans[group.name], net, cfg.gateway_position))
        cursor = start + size

    free = _free_ranges(base, [s.network for s in subnets])
    return Plan(base, tuple(subnets), free)
