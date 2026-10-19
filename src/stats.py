"""Kennzahlen zur Platznutzung (Sätze "Interner Verschnitt", "VLSM dominiert feste
Präfixlänge", "Mittlere Auslastung") und Dimensionierung der Wachstumsreserve."""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .models import Plan, PlanConfig, PlanError
from .planner import required_addresses

EXPECTED_UTILIZATION = 1.0 / (2.0 * math.log(2.0))  # ≈ 0,7213 (Satz "Mittlere Auslastung")


@dataclass(frozen=True)
class PlanStats:
    block_utilization: Dict[str, float]  # r_i / s_i je Gruppe
    mean_utilization: float
    min_utilization: float
    allocated: int  # S
    required: int  # Summe der r_i
    internal_waste: int  # S - Summe r_i


def fixed_extra_waste(sizes: Sequence[int]) -> int:
    """Mehrverbrauch W = n * max(s) - sum(s) von ``fixed`` gegenüber ``vlsm`` (Satz "VLSM dominiert")."""
    if not sizes:
        raise PlanError("Keine Blockgrößen angegeben")
    return len(sizes) * max(sizes) - sum(sizes)


def plan_statistics(plan: Plan, cfg: PlanConfig) -> PlanStats:
    """Blockauslastung je Gruppe sowie Mittelwert, Minimum und Verschnitt."""
    by_group = {g.name: g for g in cfg.groups}
    util: Dict[str, float] = {}
    required = 0
    allocated = 0
    for s in plan.subnets:
        need = required_addresses(by_group[s.group], cfg.growth_factor, cfg.gateway_position, s.network.version)
        required += need
        allocated += s.network.num_addresses
        util[s.group] = need / s.network.num_addresses
    values = list(util.values())
    return PlanStats(util, sum(values) / len(values), min(values), allocated, required, allocated - required)


def simulate_mean_utilization(samples: int = 100_000, seed: int = 1, decades: float = 6.0) -> float:
    """Monte-Carlo-Schätzung der mittleren Blockauslastung bei gleichverteiltem log2(r) mod 1."""
    if samples < 1:
        raise PlanError("samples muss mindestens 1 sein")
    rng = random.Random(seed)
    total = 0.0
    for _ in range(samples):
        x = rng.uniform(1.0, 1.0 + decades * math.log2(10))  # Größen über mehrere Größenordnungen
        total += 2.0 ** (x - math.ceil(x))
    return total / samples


def poisson_cdf(k: int, lam: float) -> float:
    """P[H <= k] für H ~ Poisson(lam), numerisch stabil über Log-Terme."""
    if lam < 0 or k < 0:
        raise PlanError("lam und k müssen nichtnegativ sein")
    if lam == 0:
        return 1.0
    total = 0.0
    for i in range(k + 1):
        total += math.exp(-lam + i * math.log(lam) - math.lgamma(i + 1))
    return min(total, 1.0)


def poisson_block_exponent(lam: float, overhead: int, alpha: float, max_exponent: int = 40) -> int:
    """Kleinstes k mit P[H + overhead <= 2^k] >= 1 - alpha für H ~ Poisson(lam).

    Dimensionierung der Wachstumsreserve unter einem Wachstumsmodell (Ausblick).
    """
    if not 0.0 < alpha < 1.0:
        raise PlanError("alpha muss echt zwischen 0 und 1 liegen")
    if overhead < 0:
        raise PlanError("overhead muss nichtnegativ sein")
    for k in range(max_exponent + 1):
        limit = (1 << k) - overhead
        if limit >= 0 and poisson_cdf(limit, lam) >= 1.0 - alpha:
            return k
    raise PlanError("Kein Blockexponent bis 2^%d erfüllt die Anforderung" % max_exponent)


def sites_bound_holds(plan: Plan, cfg: PlanConfig) -> Tuple[bool, int, int, int]:
    """Prüft Satz "Zweistufige Planung": sum(E) < 2*sum(s) < 4*sum(r) (nur bei vlsm, ohne Überschreibungen)."""
    if not plan.site_blocks:
        raise PlanError("Der Plan hat keine Standortblöcke")
    total_e = sum(net.num_addresses for _, net in plan.site_blocks)
    total_s = sum(s.network.num_addresses for s in plan.subnets)
    total_r = sum(
        required_addresses(g, cfg.growth_factor, cfg.gateway_position, plan.base_network.version) for g in cfg.groups
    )
    return total_e < 2 * total_s < 4 * total_r, total_e, total_s, total_r
