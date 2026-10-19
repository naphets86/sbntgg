"""Zweistufige (hierarchische) Planung nach Satz "Zweistufige Planung".

Jeder Standort erhält zuerst einen eigenen Block E_sigma = 2^ceil(log2 D_sigma), wobei
D_sigma die Summe der Blockgrößen seiner Gruppen ist. Aus diesem Block werden die Gruppen
des Standorts mit dem normalen Algorithmus geplant. Ergebnis: ein Routing-Eintrag je Standort
statt einer je Gruppe (Routen-Aggregation).
"""
from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Tuple

from .blocks import block_size_for, free_ranges_in_pool
from .models import IPNetwork, Plan, PlanConfig, PlanError, Subnet
from .planner import _plan_simple, assign_vlans, group_prefix


def site_demands(cfg: PlanConfig) -> Dict[str, int]:
    """D_sigma je Standort (bei ``fixed``: n_sigma * größter Block des Standorts)."""
    width = cfg.base_network.max_prefixlen
    sizes: Dict[str, List[int]] = {}
    for g in cfg.groups:
        sizes.setdefault(g.site or "", []).append(1 << (width - group_prefix(g, cfg)))
    if cfg.allocation_strategy == "fixed":
        return {site: len(s) * max(s) for site, s in sizes.items()}
    return {site: sum(s) for site, s in sizes.items()}


def plan_hierarchical(cfg: PlanConfig) -> Plan:
    """Plant erst die Standortblöcke, dann die Gruppen innerhalb jedes Standortblocks."""
    if cfg.pools or cfg.existing or any(g.network is not None for g in cfg.groups):
        raise PlanError("Standorte lassen sich nicht mit pools, existing oder festen Netzen kombinieren")
    base = cfg.base_network
    width = base.max_prefixlen
    demands = site_demands(cfg)
    blocks = {site: block_size_for(d) for site, d in demands.items()}

    appearance = {site: i for i, site in enumerate(demands)}
    priority: Dict[str, int] = {}
    for g in cfg.groups:
        site = g.site or ""
        priority[site] = min(priority.get(site, g.priority), g.priority)
    order = sorted(demands, key=lambda s: (-blocks[s], priority[s], appearance[s]))

    net_cls = type(base)
    cursor = int(base.network_address)
    end = int(base.broadcast_address)
    site_nets: Dict[str, IPNetwork] = {}
    for site in order:
        size = blocks[site]
        if size > base.num_addresses:
            raise PlanError(f"Platzmangel: Standort {site!r} benötigt {size} Adressen, das Basisnetz {base} ist kleiner")
        start = -(-cursor // size) * size
        if start + size - 1 > end:
            raise PlanError(f"Platzmangel: Standort {site!r} ({size} Adressen) passt nicht mehr in {base}")
        site_nets[site] = net_cls((start, width - (size.bit_length() - 1)))
        cursor = start + size

    vlans = assign_vlans(cfg.groups)
    subnets: List[Subnet] = []
    for site, block in site_nets.items():
        members = tuple(replace(g, vlan_id=vlans[g.name], site=None) for g in cfg.groups if (g.site or "") == site)
        sub_cfg = PlanConfig(
            block, members, cfg.growth_factor, cfg.allocation_strategy, cfg.gateway_position, cfg.max_prefix
        )
        subnets.extend(replace(s, site=site) for s in _plan_simple(sub_cfg).subnets)
    subnets.sort(key=lambda s: int(s.network.network_address))

    free = free_ranges_in_pool(base, list(site_nets.values()))
    ordered_sites: Tuple[Tuple[str, IPNetwork], ...] = tuple(
        sorted(site_nets.items(), key=lambda item: int(item[1].network_address))
    )
    return Plan(base, tuple(subnets), free, site_blocks=ordered_sites)


def aggregation_summary(plan: Plan) -> Dict[str, object]:
    """Routen-Aggregation: Einträge je Standort statt je Gruppe."""
    return {
        "routes_flat": len(plan.subnets),
        "routes_aggregated": len(plan.site_blocks) if plan.site_blocks else len(plan.subnets),
        "site_blocks": {site: str(net) for site, net in plan.site_blocks},
    }
