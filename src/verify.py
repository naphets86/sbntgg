"""Laufzeitprüfung eines Plans gegen die Sätze der Arbeit.

``verify_plan`` prüft die Eigenschaften (K1) bis (K6) aus Satz "Korrektheit der Zuteilung",
Satz "Lückenlosigkeit", Satz "Freie Bereiche" (F1) bis (F3), Lemma "Nutzbare Hosts",
Satz "Interner Verschnitt" und die VLAN-Regeln. Die Prüfung ist unabhängig vom Planer
implementiert und eignet sich damit für Eingangskontrollen und Zufallstests.
"""
from __future__ import annotations

from typing import List, Optional

from .blocks import maximal_free_blocks
from .models import Plan, PlanConfig, PlanError, VLAN_MAX, VLAN_MIN
from .planner import group_overhead, group_prefix, required_addresses


def _simple(cfg: PlanConfig) -> bool:
    """Ein Pool, kein Bestand, keine festen Netze, keine Standorte: Beweisvoraussetzungen."""
    return not (cfg.pools or cfg.existing) and all(g.network is None and g.site is None for g in cfg.groups)


def _pure(cfg: PlanConfig) -> bool:
    """Zusätzlich keine Mindestgröße und kein eigener Overhead (Minimalität, Verschnitt)."""
    return _simple(cfg) and cfg.max_prefix is None and all(g.overhead is None for g in cfg.groups)


def verify_plan(plan: Plan, cfg: Optional[PlanConfig] = None) -> List[str]:
    """Gibt alle Verletzungen aus; eine leere Liste bedeutet: der Plan ist korrekt."""
    problems: List[str] = []
    subnets = list(plan.subnets)
    pools = plan.all_pools

    # (K1) Ausrichtung, (K2) Enthaltensein
    for s in subnets:
        n = s.network
        if int(n.network_address) % n.num_addresses:  # pragma: no cover - ip_network erzwingt Ausrichtung
            problems.append(f"(K1) {n} ist nicht ausgerichtet")
        if not any(n.subnet_of(p) for p in pools if p.version == n.version):  # type: ignore[arg-type]
            problems.append(f"(K2) {n} liegt in keinem Pool")

    # (K3) Disjunktheit, (K5) aufsteigende Reihenfolge
    for a, b in zip(subnets, subnets[1:]):
        if int(a.network.network_address) >= int(b.network.network_address):
            problems.append(f"(K5) {a.network} steht nicht vor {b.network}")
    ordered = sorted(subnets, key=lambda s: (int(s.network.network_address), s.network.prefixlen))
    for a, b in zip(ordered, ordered[1:]):
        if a.network.overlaps(b.network):
            problems.append(f"(K3) {a.network} ({a.group}) überlappt {b.network} ({b.group})")
    for r in plan.reserved:
        for s in subnets:
            if r.overlaps(s.network):
                problems.append(f"(K3) {s.network} ({s.group}) überlappt das Bestandsnetz {r}")

    # VLAN-Regeln (Lemma "VLAN-Vergabe")
    vlans = [s.vlan_id for s in subnets]
    if len(set(vlans)) != len(vlans):
        problems.append("Lemma VLAN: VLAN-IDs sind nicht eindeutig")
    for v in vlans:
        if not VLAN_MIN <= v <= VLAN_MAX:
            problems.append(f"Lemma VLAN: ID {v} außerhalb {VLAN_MIN}..{VLAN_MAX}")

    # Nutzbare Hosts (K4) und Lemma "Nutzbare Hosts"
    for s in subnets:
        if s.usable_hosts < s.requested_hosts:
            problems.append(f"(K4) {s.group}: nur {s.usable_hosts} nutzbare Hosts für {s.requested_hosts}")
        if not (s.network.network_address <= s.first_host <= s.last_host <= s.network.broadcast_address):
            problems.append(f"Lemma Nutzbare Hosts: {s.group}: Host-Bereich liegt außerhalb von {s.network}")

    # Freie Bereiche (F): gleich den maximalen freien Blöcken, Summe und Eindeutigkeit
    blocks = [net for _, net in plan.site_blocks] if plan.site_blocks else [s.network for s in subnets]
    occupied = blocks + list(plan.reserved)
    try:
        expected_free = maximal_free_blocks(pools, occupied)
    except PlanError as exc:
        problems.append(f"(F) {exc}")
        expected_free = ()
    if set(plan.free_ranges) != set(expected_free):
        problems.append("(F1) free_ranges stimmen nicht mit der minimalen Zerlegung des freien Raums überein")
    free_total = sum(n.num_addresses for n in plan.free_ranges)
    if free_total != plan.free_addresses:
        problems.append(f"(F) Summe der freien Bereiche ({free_total}) != freie Adressen ({plan.free_addresses})")

    if cfg is None:
        return problems

    # Gruppenbezogene Eigenschaften
    by_group = {g.name: g for g in cfg.groups}
    if {s.group for s in subnets} != set(by_group):
        problems.append("Die Subnetze entsprechen nicht den Gruppen der Konfiguration")
        return problems
    for s in subnets:
        g = by_group[s.group]
        o = group_overhead(g, cfg.gateway_position, s.network.version)
        if s.usable_hosts != s.network.num_addresses - o:
            problems.append(f"Lemma Nutzbare Hosts: {s.group}: u={s.usable_hosts} != s-o={s.network.num_addresses - o}")
        need = required_addresses(g, cfg.growth_factor, cfg.gateway_position, s.network.version)
        if s.network.num_addresses < need:
            problems.append(f"(K4) {s.group}: Block {s.network} fasst nur {s.network.num_addresses} < {need} Adressen")
        if _pure(cfg) and cfg.allocation_strategy == "vlsm":
            if s.network.num_addresses >= 2 * need:  # (K6) und Satz "Interner Verschnitt"
                problems.append(f"(K6) {s.group}: Block {s.network} ist nicht minimal für Bedarf {need}")
            if s.network.prefixlen != group_prefix(g, cfg):
                problems.append(f"(K1) {s.group}: Präfixlänge entspricht nicht dem Bedarf")

    if _simple(cfg):
        sizes = [s.network.num_addresses for s in subnets]
        base = cfg.base_network
        pos = int(base.network_address)
        for s in subnets:  # Satz "Lückenlosigkeit"
            if int(s.network.network_address) != pos:
                problems.append(f"Satz Lückenlosigkeit: Lücke vor {s.network}")
                break
            pos += s.network.num_addresses
        if cfg.allocation_strategy == "vlsm":
            by_addr = sorted(subnets, key=lambda s: int(s.network.network_address))
            for a, b in zip(by_addr, by_addr[1:]):  # absteigende Blockgröße
                if a.network.num_addresses < b.network.num_addresses:
                    problems.append("Satz Kompaktheit: Blöcke sind nicht nach absteigender Größe angeordnet")
                    break
        if _pure(cfg) and cfg.allocation_strategy == "vlsm":
            total_r = sum(
                required_addresses(g, cfg.growth_factor, cfg.gateway_position, base.version) for g in cfg.groups
            )
            if sum(sizes) >= 2 * total_r:
                problems.append("Satz Interner Verschnitt: S >= 2*Summe(r)")
        free = base.num_addresses - sum(sizes)
        if len(plan.free_ranges) != bin(free).count("1"):
            problems.append("(F1) Zahl der freien Blöcke ist nicht popcount(F)")
        if free and max(n.num_addresses for n in plan.free_ranges) != 1 << (free.bit_length() - 1):
            problems.append("(F3) der größte freie Block hat nicht die Größe 2^floor(log2 F)")
    return problems


def assert_plan(plan: Plan, cfg: Optional[PlanConfig] = None) -> None:
    """Wirft ``PlanError`` mit allen Verletzungen, falls der Plan nicht korrekt ist."""
    problems = verify_plan(plan, cfg)
    if problems:
        raise PlanError("Plan verletzt Eigenschaften:\n- " + "\n- ".join(problems))
