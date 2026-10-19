"""Berechnung der Subnetze (VLSM oder feste Präfixlänge) einschließlich Bestandsplanung."""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from .blocks import free_ranges_in_pool, maximal_free_blocks, pack, packable
from .exact import ceil_product
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


def default_overhead(gateway_position: str, version: int) -> int:
    """Overhead o: Netzadresse, Broadcast (nur IPv4) und Gateway (außer bei ``none``)."""
    overhead = 2 if version == 4 else 1  # IPv6 kennt keinen Broadcast
    if gateway_position != "none":
        overhead += 1
    return overhead


def group_overhead(group: Group, gateway_position: str, version: int) -> int:
    """Overhead der Gruppe: ihr eigener Wert (Satz "Robustheit") oder der Standard."""
    if group.overhead is not None:
        return group.overhead
    return default_overhead(gateway_position, version)


def required_addresses(group: Group, growth_factor: float, gateway_position: str, version: int) -> int:
    """Adressen r = ceil(gamma * h) + o, mit exakter Rechnung (siehe ``exact``)."""
    return ceil_product(group.hosts, growth_factor) + group_overhead(group, gateway_position, version)


def prefix_for(total: int, max_prefix: int, name: str) -> int:
    """Kleinste Präfixlänge, deren Block mindestens ``total`` Adressen fasst."""
    prefix = max_prefix - (total - 1).bit_length()
    if prefix < 0:
        raise PlanError(f"Gruppe {name!r}: {total} Adressen passen in keinen Adressraum")
    return prefix


def group_prefix(group: Group, cfg: PlanConfig) -> int:
    """Präfixlänge der Gruppe inklusive Mindestgröße (``max_prefix``) und festem Netz."""
    base = cfg.base_network
    need = required_addresses(group, cfg.growth_factor, cfg.gateway_position, base.version)
    if group.network is not None:
        if group.network.num_addresses < need:
            raise PlanError(
                f"Gruppe {group.name!r}: das feste Netz {group.network} fasst "
                f"{group.network.num_addresses} Adressen, benötigt werden {need}"
            )
        return group.network.prefixlen
    prefix = prefix_for(need, base.max_prefixlen, group.name)
    if cfg.max_prefix is not None:
        prefix = min(prefix, cfg.max_prefix)
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


def _layout(net: IPNetwork, overhead: int) -> Tuple[int, int]:
    """Reservierte Adressen am unteren und oberen Blockende.

    Reihenfolge der Reservierung: Netzadresse, Broadcast (nur IPv4), dann Gateway-Platz;
    weitere Adressen (z. B. Cloud-Reserven) werden am Blockanfang reserviert.
    Der Rückgabewert ``(low, high)`` erfüllt ``low + high == overhead``.
    """
    low = high = 0
    if overhead >= 1:
        low = 1
    if overhead >= 2 and net.version == 4:
        high = 1
    return low, high


def _build_subnet(
    group: Group, vlan_id: int, net: IPNetwork, gateway_position: str, site: Optional[str] = None
) -> Subnet:
    overhead = group_overhead(group, gateway_position, net.version)
    low, high = _layout(net, overhead)
    gateway: Optional[IPAddress] = None
    left = overhead - low - high
    if left > 0 and gateway_position == "first":
        gateway = net.network_address + low
        low += 1
        left -= 1
    elif left > 0 and gateway_position == "last":
        gateway = net.broadcast_address - high
        high += 1
        left -= 1
    low += max(left, 0)  # weitere reservierte Adressen (nur bei explizitem overhead)
    first = net.network_address + low
    last = net.broadcast_address - high
    broadcast: Optional[IPAddress] = net.broadcast_address if net.version == 4 and high >= 1 else None
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
        site=site if site is not None else group.site,
    )


def _free_ranges(base: IPNetwork, nets: Sequence[IPNetwork]) -> Tuple[IPNetwork, ...]:
    return free_ranges_in_pool(base, nets)


def _ordered(sized: List[Tuple[Group, int]], strategy: str) -> List[Tuple[Group, int]]:
    """Zuteilungsreihenfolge: vlsm = (Präfix, Priorität), fixed = Priorität (stabil)."""
    if strategy == "fixed":
        return sorted(sized, key=lambda item: item[0].priority)
    return sorted(sized, key=lambda item: (item[1], item[0].priority))


def _plan_simple(cfg: PlanConfig) -> Plan:
    """Ein Pool, kein Bestand: der Algorithmus der Arbeit (lückenlos ab Adresse a_B)."""
    base = cfg.base_network
    max_prefix = base.max_prefixlen
    sized = [(g, group_prefix(g, cfg)) for g in cfg.groups]

    if cfg.allocation_strategy == "fixed":
        uniform = min(prefix for _, prefix in sized)  # kleinste Länge = größter Block
        sized = [(g, uniform) for g, _ in sized]
    order = _ordered(sized, cfg.allocation_strategy)

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


def _plan_general(cfg: PlanConfig) -> Plan:
    """Bestandsplanung (Satz "Planung mit Bestand und mehreren Pools").

    Feste Netze und Bestandsnetze sind belegt; die übrigen Gruppen werden mit dem
    konstruktiven Verfahren aus dem Beweis von Satz "Packbarkeit" in die maximalen freien
    Blöcke aller Pools gelegt. Die Planung gelingt genau dann, wenn Bedingung (*) gilt.
    """
    base = cfg.base_network
    pools = (base,) + cfg.pools
    width = base.max_prefixlen
    fixed = {g.name: g.network for g in cfg.groups if g.network is not None}
    occupied = list(cfg.existing) + list(fixed.values())
    free = maximal_free_blocks(pools, occupied)

    for g in cfg.groups:  # feste Netze müssen den Bedarf der Gruppe fassen
        if g.network is not None:
            group_prefix(g, cfg)
    movable = [(g, group_prefix(g, cfg)) for g in cfg.groups if g.network is None]
    if cfg.allocation_strategy == "fixed" and movable:
        uniform = min(prefix for _, prefix in movable)
        movable = [(g, uniform) for g, _ in movable]
    order = _ordered(movable, cfg.allocation_strategy)
    items = [(g.name, 1 << (width - prefix)) for g, prefix in order]

    if not packable(free, [size for _, size in items]):
        need = sum(size for _, size in items)
        have = sum(b.num_addresses for b in free)
        raise PlanError(
            f"Platzmangel: die Gruppen benötigen {need} Adressen in ausgerichteten Blöcken, "
            f"in den freien Bereichen ({have} Adressen) lassen sie sich nicht unterbringen"
        )
    placed = pack(free, items)
    placed.update(fixed)

    vlans = assign_vlans(cfg.groups)
    by_name = {g.name: g for g in cfg.groups}
    subnets = [
        _build_subnet(by_name[name], vlans[name], net, cfg.gateway_position)
        for name, net in placed.items()
    ]
    subnets.sort(key=lambda s: int(s.network.network_address))
    all_nets = [s.network for s in subnets] + list(cfg.existing)
    remaining = maximal_free_blocks(pools, all_nets)
    return Plan(base, tuple(subnets), remaining, cfg.pools, tuple(cfg.existing))


def plan_subnets(cfg: PlanConfig) -> Plan:
    """Berechnet die Subnetze (VLSM: größte zuerst; fixed: einheitliche Länge)."""
    if any(g.site is not None for g in cfg.groups):
        from .hierarchy import plan_hierarchical  # Importzyklus vermeiden

        return plan_hierarchical(cfg)
    if cfg.pools or cfg.existing or any(g.network is not None for g in cfg.groups):
        return _plan_general(cfg)
    return _plan_simple(cfg)
