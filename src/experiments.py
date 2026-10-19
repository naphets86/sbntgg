"""Experimente zur Arbeit "Der Subnetting Algorithmus sbntgg".

Jedes Experiment prüft oder misst eine Aussage der Arbeit an zufälligen Eingaben und schreibt
sein Ergebnis als JSON-Datei nach ``src/results/<name>.json``. Zusätzlich entsteht
``src/results/summary.json`` mit den Rahmendaten des Laufs (Seed, Python-Version, Dauer) und
dem Urteil je Experiment.

Aufruf im Projektverzeichnis::

    python -m src.experiments                      # alle Experimente, Standardgrößen
    python -m src.experiments --quick              # kleine Größen (Sekunden statt Minuten)
    python -m src.experiments --only runtime packability --seed 7
    python -m src.experiments --list               # verfügbare Experimente anzeigen
    python -m src.experiments --output-dir /tmp/ergebnisse

Die Experimente sind wiederholbar: Der Seed legt alle Zufallszahlen fest (je Experiment ein
eigener Strom). Nur die gemessenen Zeiten schwanken von Lauf zu Lauf.

Das Experiment ``policy_comparison`` benötigt das Paket ``subgraph``; fehlt es, wird es
übersprungen und als ``skipped`` vermerkt.
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if __package__ in (None, ""):  # direkter Aufruf: python src/experiments.py
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import argparse
import ipaddress
import itertools
import json
import math
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from decimal import ROUND_CEILING, Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from src.access import policy_pairs, rule_groups
from src.blocks import maximal_free_blocks, pack, packable
from src.config import build_config, build_extension
from src.exact import ceil_product
from src.extend import can_double, double_in_place, extend_plan, renumbered_hosts
from src.firewall import FirewallOptions, render_firewall
from src.hierarchy import site_demands
from src.models import PlanError
from src.planner import group_prefix, plan_subnets
from src.roundtrip import check_roundtrip
from src.stats import (
    EXPECTED_UTILIZATION,
    fixed_extra_waste,
    plan_statistics,
    simulate_mean_utilization,
    sites_bound_holds,
)
from src.verify import verify_plan

RESULTS_DIR = Path(__file__).resolve().parent / "results"
GATEWAYS = ("first", "last", "none")
HOST_CHOICES = (1, 2, 5, 10, 30, 60, 120, 250)

Scale = Dict[str, int]

# Größen je Experiment: (Standard, schneller Lauf)
SIZES: Dict[str, Tuple[Scale, Scale]] = {
    "runtime": ({"repeats": 3, "max_n": 5000}, {"repeats": 1, "max_n": 300}),
    "utilization": ({"plans": 4000}, {"plans": 150}),
    "growth_factor": ({"samples": 200000}, {"samples": 5000}),
    "packability": ({"cases": 4000}, {"cases": 200}),
    "extension": ({"plans": 1500}, {"plans": 80}),
    "grouping": ({"plans": 40}, {"plans": 4}),
    "roundtrip": ({"plans": 300}, {"plans": 12}),
    "hierarchy": ({"plans": 1000}, {"plans": 60}),
    "doubling": ({"plans": 300}, {"plans": 25}),
    "ipv6": ({"max_n": 2000, "plans": 100}, {"max_n": 100, "plans": 10}),
    "policy_comparison": ({"pairs": 3000}, {"pairs": 150}),
}


# --------------------------------------------------------------------------- Hilfsfunktionen
def summarize(values: Sequence[float]) -> Dict[str, Any]:
    """Kennzahlen einer Messreihe (leer: nur ``n`` = 0)."""
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def timed(fn: Callable[[], Any], repeats: int) -> float:
    """Median der Laufzeit in Sekunden über ``repeats`` Aufrufe."""
    runs = []
    for _ in range(max(1, repeats)):
        start = time.perf_counter()
        fn()
        runs.append(time.perf_counter() - start)
    return statistics.median(runs)


def loglog_slope(points: Sequence[Tuple[float, float]]) -> Optional[float]:
    """Steigung der Ausgleichsgeraden von ln(t) über ln(n) (Wachstumsexponent)."""
    pts = [(math.log(x), math.log(y)) for x, y in points if x > 0 and y > 0]
    if len(pts) < 2:
        return None
    mx = statistics.fmean(p[0] for p in pts)
    my = statistics.fmean(p[1] for p in pts)
    var = sum((p[0] - mx) ** 2 for p in pts)
    if var == 0:
        return None
    return sum((p[0] - mx) * (p[1] - my) for p in pts) / var


def random_raw(
    rng: random.Random,
    n: Optional[int] = None,
    v6: bool = False,
    strategy: str = "vlsm",
    density: Optional[float] = None,
    base: Optional[str] = None,
    extra_selfref: bool = True,
) -> Dict[str, Any]:
    """Zufällige Rohkonfiguration. ``density`` ist die Wahrscheinlichkeit je Gruppenpaar."""
    n = n if n is not None else rng.randint(1, 8)
    names = [f"G{i}" for i in range(n)]
    groups = []
    for name in names:
        if density is None:
            access = rng.sample(names, rng.randint(0, min(3, n)))
        else:
            access = [m for m in names if m != name and rng.random() < density]
        if extra_selfref and rng.random() < 0.15:
            access.append(name)  # Selbstbezug: wird beim Laden bereinigt
        groups.append({"name": name, "hosts": rng.choice(HOST_CHOICES), "access": access})
    raw: Dict[str, Any] = {
        "base_network": base or ("2001:db8::/48" if v6 else "10.0.0.0/16"),
        "groups": groups,
        "growth_factor": rng.choice([1.0, 1.1, 1.25, 1.5]),
        "allocation_strategy": strategy,
        "gateway_position": rng.choice(GATEWAYS),
    }
    if v6:
        raw["max_prefix"] = 64
    return raw


def exhaustive_packable(free_blocks: Sequence[Any], sizes: Sequence[int], universe: int) -> bool:
    """Vollständige Suche (Backtracking) nach einer überlappungsfreien Zuteilung.

    Referenz für Satz "Packbarkeit": unabhängig von ``blocks.packable`` implementiert.
    Die freien Blöcke müssen im Universum ``[0, universe)`` ab ``base`` liegen.
    """
    # Das Universum beginnt an einer Vielfachen seiner Größe (Ausrichtung bleibt erhalten).
    first = min(int(b.network_address) for b in free_blocks) if free_blocks else 0
    base = first // universe * universe
    blocks = [(int(b.network_address) - base, b.num_addresses) for b in free_blocks]
    ordered = sorted(sizes, reverse=True)

    def place(i: int, used: List[Tuple[int, int]]) -> bool:
        if i == len(ordered):
            return True
        size = ordered[i]
        for start in range(0, universe, size):
            inside = any(start >= bs and start + size <= bs + bl for bs, bl in blocks)
            clash = any(start < u + us and u < start + size for u, us in used)
            if inside and not clash and place(i + 1, used + [(start, size)]):
                return True
        return False

    return place(0, [])


# --------------------------------------------------------------------------- Experimente
def exp_runtime(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Laufzeit über n (Satz "Laufzeit"): Planung, Prüfung und Regelerzeugung.

    Erwartet wird ein Wachstum nahe n log n; der Exponent der Ausgleichsgeraden im
    Log-Log-Diagramm liegt dann knapp über 1.
    """
    sizes = [n for n in (10, 30, 100, 300, 1000, 2000, 5000) if n <= scale["max_n"]]
    rows = []
    for n in sizes:
        raw = random_raw(rng, n=n, base="10.0.0.0/8", extra_selfref=False)
        for g in raw["groups"]:
            g["access"] = rng.sample([x["name"] for x in raw["groups"] if x["name"] != g["name"]], min(3, n - 1))
        cfg = build_config(raw)
        plan = plan_subnets(cfg)
        row: Dict[str, Any] = {"n": n, "access_pairs": len(policy_pairs(plan))}
        row["seconds_config"] = timed(lambda: build_config(raw), scale["repeats"])
        row["seconds_plan"] = timed(lambda: plan_subnets(cfg), scale["repeats"])
        row["seconds_verify"] = timed(lambda: verify_plan(plan, cfg), scale["repeats"])
        for kind in ("iptables", "nftables", "cisco"):
            row[f"seconds_{kind}"] = timed(lambda k=kind: render_firewall(plan, k), scale["repeats"])
        row["seconds_rule_groups"] = timed(lambda: rule_groups(plan), scale["repeats"])
        row["plan_per_n_log_n"] = row["seconds_plan"] / (n * math.log(max(n, 2)))
        rows.append(row)
    slopes = {
        key: loglog_slope([(r["n"], r[key]) for r in rows])
        for key in ("seconds_plan", "seconds_verify", "seconds_nftables", "seconds_cisco")
    }
    return {
        "description": "Laufzeit über der Gruppenzahl n (je 3 Zugriffsziele); Median der Wiederholungen",
        "rows": rows,
        "loglog_slope": slopes,
        "passed": True,  # Messung ohne Sollwert; die Steigung ist zu interpretieren
    }


def exp_utilization(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Mittlere Auslastung (Satz "Mittlere Auslastung") und VLSM gegen feste Länge.

    Die Gruppengrößen sind logarithmisch gleichverteilt, damit die Annahme des Satzes
    (log2 r mod 1 gleichverteilt) näherungsweise erfüllt ist.
    """
    utils: List[float] = []
    min_util = 1.0
    violations = 0
    waste_equal = 0
    ratios: List[float] = []
    verify_failures = 0
    for _ in range(scale["plans"]):
        n = rng.randint(2, 12)
        raw = random_raw(rng, n=n, base="10.0.0.0/8", extra_selfref=False)
        for g in raw["groups"]:
            g["hosts"] = max(1, int(round(10 ** rng.uniform(0, 3.3))))
        raw["gateway_position"] = rng.choice(GATEWAYS)
        cfg = build_config(raw)
        plan = plan_subnets(cfg)
        verify_failures += bool(verify_plan(plan, cfg))
        st = plan_statistics(plan, cfg)
        utils.extend(st.block_utilization.values())
        min_util = min(min_util, st.min_utilization)
        violations += sum(1 for u in st.block_utilization.values() if u <= 0.5)  # Satz Verschnitt: > 1/2
        fixed = build_config({**raw, "allocation_strategy": "fixed"})
        fixed_plan = plan_subnets(fixed)
        sizes = [s.network.num_addresses for s in plan.subnets]
        waste_equal += (fixed_plan.allocated_addresses - plan.allocated_addresses) == fixed_extra_waste(sizes)
        ratios.append(fixed_plan.allocated_addresses / plan.allocated_addresses)
    mean = statistics.fmean(utils)
    return {
        "description": "Blockauslastung r/s bei logarithmisch gleichverteilten Gruppengrößen",
        "groups_observed": len(utils),
        "mean_utilization": mean,
        "expected_utilization": EXPECTED_UTILIZATION,
        "deviation_from_theory": mean - EXPECTED_UTILIZATION,
        "monte_carlo_reference": simulate_mean_utilization(100_000, seed=1),
        "min_utilization": min_util,
        "utilization_distribution": summarize(utils),
        "utilization_at_most_half": violations,
        "fixed_over_vlsm_ratio": summarize(ratios),
        "fixed_waste_formula_matches": waste_equal,
        "plans": scale["plans"],
        "verify_failures": verify_failures,
        "passed": violations == 0 and waste_equal == scale["plans"] and verify_failures == 0
        and abs(mean - EXPECTED_UTILIZATION) < 0.03,
    }


def exp_growth_factor(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Wachstumsfaktor und exakte Arithmetik (Lemma "Gleitkomma-Aufrundung", Lemma "Exakte Aufrundung").

    Teil 1 variiert gamma bei festem Beispiel und misst Belegung und Auslastung.
    Teil 2 vergleicht drei Berechnungen von ceil(gamma*h) mit einer Dezimal-Referenz.
    """
    benchmark = [("Server", 40), ("Entwicklung", 120), ("HR", 25), ("Drucker", 12), ("Gaeste", 60)]
    sweep = []
    for tenth in range(10, 21):
        gamma = tenth / 10
        cfg = build_config(
            {"base_network": "10.20.0.0/16", "growth_factor": gamma,
             "groups": [{"name": n, "hosts": h} for n, h in benchmark]}
        )
        plan = plan_subnets(cfg)
        st = plan_statistics(plan, cfg)
        sweep.append({"growth_factor": gamma, "allocated": plan.allocated_addresses,
                      "utilization_percent": plan.utilization, "mean_block_utilization": st.mean_utilization})

    naive_wrong = old_wrong = exact_wrong = 0
    examples: List[Dict[str, Any]] = []
    for _ in range(scale["samples"]):
        h = rng.randint(1, 2_000_000)
        gamma = rng.randint(100, 2000) / 1000  # bis zu drei Nachkommastellen
        truth = int((Decimal(str(gamma)) * h).to_integral_value(rounding=ROUND_CEILING))
        naive = math.ceil(h * gamma)
        old = math.ceil(round(h * gamma, 9))
        exact = ceil_product(h, gamma)
        naive_wrong += naive != truth
        old_wrong += old != truth
        exact_wrong += exact != truth
        if naive != truth and len(examples) < 5:
            examples.append({"hosts": h, "gamma": gamma, "naive": naive, "exact": truth})
    return {
        "description": "gamma-Sweep für das Konfigurationsbeispiel und Vergleich der Aufrundungen",
        "sweep": sweep,
        "samples": scale["samples"],
        "naive_float_mismatches": naive_wrong,
        "rounded_float_mismatches": old_wrong,
        "exact_mismatches": exact_wrong,
        "naive_examples": examples,
        "passed": exact_wrong == 0 and old_wrong == 0,
    }


def exp_packability(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Bedingung (*) aus Satz "Packbarkeit" gegen vollständige Suche (32 Adressen)."""
    pool = ipaddress.ip_network("10.0.0.0/27")
    agree = packable_cases = constructive_ok = 0
    for _ in range(scale["cases"]):
        occupied = [b for b in pool.subnets(new_prefix=29) if rng.random() < 0.35]
        free = maximal_free_blocks([pool], occupied)
        sizes = [rng.choice([1, 2, 4, 8, 16]) for _ in range(rng.randint(0, 5))]
        fast = packable(free, sizes)
        slow = exhaustive_packable(free, sizes, 32) if free else not sizes
        agree += fast == slow
        if fast:
            packable_cases += 1
            placed = pack(free, [(str(i), s) for i, s in enumerate(sizes)])
            nets = list(placed.values())
            disjoint = not any(a.overlaps(b) for a, b in itertools.combinations(nets, 2))
            inside = all(any(n.subnet_of(f) for f in free) for n in nets)
            constructive_ok += disjoint and inside
    return {
        "description": "packable() gegen Backtracking in einem Universum von 32 Adressen",
        "cases": scale["cases"],
        "agreements": agree,
        "packable_cases": packable_cases,
        "constructive_placements_valid": constructive_ok,
        "passed": agree == scale["cases"] and constructive_ok == packable_cases,
    }


def exp_extension(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Korollar "Verlustfreie Erweiterbarkeit": Erweiterung gelingt genau bei Summe <= F."""
    agree = unchanged = extended = 0
    for _ in range(scale["plans"]):
        cfg = build_config(random_raw(rng, n=rng.randint(1, 8)))
        plan = plan_subnets(cfg)
        free = sum(n.num_addresses for n in plan.free_ranges)
        hosts = rng.choice([5, 50, 500, 5000, 50000])
        ecfg, new = build_extension(
            {"groups": [{"name": "NEU", "hosts": hosts}], "growth_factor": cfg.growth_factor,
             "gateway_position": cfg.gateway_position},
            [s.group for s in plan.subnets], plan.base_network,
        )
        size = 1 << (plan.base_network.max_prefixlen - group_prefix(new[0], ecfg))
        try:
            ext = extend_plan(plan, new, ecfg)
            fits = True
            extended += 1
            unchanged += all(s in ext.subnets for s in plan.subnets) and not verify_plan(ext)
        except PlanError:
            fits = False
        agree += fits == (size <= free)
    return {
        "description": "Erweiterung eines Plans um eine Gruppe; Vorhersage aus der Summe der freien Adressen",
        "plans": scale["plans"],
        "prediction_matches": agree,
        "extensions_succeeded": extended,
        "existing_subnets_unchanged_and_valid": unchanged,
        "passed": agree == scale["plans"] and unchanged == extended,
    }


def exp_grouping(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Regelgruppierung (Satz "Regelgruppierung"): Regelzahl und Ausgabelänge über der Dichte."""
    rows = []
    all_equal = True
    for n in (10, 30, 100):
        for density in (0.05, 0.1, 0.3, 0.5, 0.9):
            pairs: List[int] = []
            groups: List[int] = []
            lines: Dict[str, List[int]] = {"iptables": [], "nftables": [], "cisco": []}
            lines_grouped: Dict[str, List[int]] = {"iptables": [], "nftables": [], "cisco": []}
            for _ in range(scale["plans"]):
                raw = random_raw(rng, n=n, density=density, base="10.0.0.0/8", extra_selfref=False)
                plan = plan_subnets(build_config(raw))
                rgs = rule_groups(plan)
                covered = {(s.group, t.group) for rg in rgs for s in rg.sources for t in rg.targets}
                all_equal &= covered == policy_pairs(plan)
                pairs.append(len(policy_pairs(plan)))
                groups.append(len(rgs))
                for kind in lines:
                    lines[kind].append(len(render_firewall(plan, kind).splitlines()))
                    lines_grouped[kind].append(
                        len(render_firewall(plan, kind, FirewallOptions(group_rules=True)).splitlines())
                    )
            mean_pairs, mean_groups = statistics.fmean(pairs), statistics.fmean(groups)
            rows.append({
                "n": n, "density": density,
                "mean_pairs": mean_pairs, "mean_rule_groups": mean_groups,
                "rule_ratio": mean_groups / mean_pairs if mean_pairs else None,
                "mean_lines": {k: statistics.fmean(v) for k, v in lines.items()},
                "mean_lines_grouped": {k: statistics.fmean(v) for k, v in lines_grouped.items()},
            })
    return {
        "description": "Regeln je Zugriffspaar gegen Regeln je Zielmenge; Zeilenzahl der Ausgabe",
        "rows": rows,
        "grouped_pairs_equal_policy": all_equal,
        "passed": all_equal and all(r["mean_rule_groups"] <= r["n"] for r in rows),
    }


def exp_roundtrip(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Rückübersetzung: Das zurückgelesene Regelwerk ergibt wieder P (alle Plattformen, Optionen)."""
    option_sets = {
        "standard": FirewallOptions(),
        "alle_optionen": FirewallOptions(group_rules=True, cisco_return="established", log_drops=True,
                                         ascii_names=True),
    }
    counts: Dict[str, Dict[str, int]] = {}
    for v6 in (False, True):
        for _ in range(scale["plans"]):
            plan = plan_subnets(build_config(random_raw(rng, v6=v6)))
            for kind in ("iptables", "nftables", "cisco"):
                for label, opts in option_sets.items():
                    key = f"{'ipv6' if v6 else 'ipv4'}/{kind}/{label}"
                    entry = counts.setdefault(key, {"checked": 0, "ok": 0})
                    entry["checked"] += 1
                    entry["ok"] += check_roundtrip(plan, kind, opts).ok
    total = sum(c["checked"] for c in counts.values())
    ok = sum(c["ok"] for c in counts.values())
    return {
        "description": "check_roundtrip je IP-Version, Plattform und Optionssatz",
        "by_case": counts,
        "checked": total,
        "ok": ok,
        "passed": ok == total,
    }


def exp_hierarchy(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Zweistufige Planung (Satz "Zweistufige Planung"): Schranken und Routen-Aggregation."""
    bound_ok = valid = 0
    block_ratio: List[float] = []
    route_ratio: List[float] = []
    for _ in range(scale["plans"]):
        sites = rng.randint(2, 6)
        raw = random_raw(rng, n=rng.randint(sites, 20), base="10.0.0.0/12", extra_selfref=False)
        for i, g in enumerate(raw["groups"]):
            g["site"] = f"S{i % sites}"
        cfg = build_config(raw)
        plan = plan_subnets(cfg)
        holds, total_e, total_s, total_r = sites_bound_holds(plan, cfg)
        demands = site_demands(cfg)
        per_site = all(dict(plan.site_blocks)[s].num_addresses < 2 * d for s, d in demands.items())
        bound_ok += holds and per_site
        valid += not verify_plan(plan)
        block_ratio.append(total_e / total_s)
        route_ratio.append(len(plan.site_blocks) / len(plan.subnets))
    return {
        "description": "Standortblöcke: E < 2D und Summenkette; Verhältnis aggregierter zu einzelnen Routen",
        "plans": scale["plans"],
        "bounds_hold": bound_ok,
        "plans_valid": valid,
        "site_blocks_over_group_blocks": summarize(block_ratio),
        "routes_aggregated_over_flat": summarize(route_ratio),
        "passed": bound_ok == scale["plans"] and valid == scale["plans"],
    }


def exp_doubling(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Verdopplung an Ort und Stelle (Satz "Verdopplung"): Häufigkeit und Umnummerierung."""
    per_gateway: Dict[str, Dict[str, Any]] = {
        g: {"groups": 0, "doublable": 0, "correct": 0, "renumbered": []} for g in GATEWAYS
    }
    refused_correctly = True
    for _ in range(scale["plans"]):
        raw = random_raw(rng, n=rng.randint(1, 8), base="10.0.0.0/20")
        gw = raw["gateway_position"]
        cfg = build_config(raw)
        plan = plan_subnets(cfg)
        entry = per_gateway[gw]
        for s in plan.subnets:
            entry["groups"] += 1
            if can_double(plan, s.group):
                entry["doublable"] += 1
                grown = double_in_place(plan, s.group)
                new = next(x for x in grown.subnets if x.group == s.group)
                changed = renumbered_hosts(s, new)
                entry["renumbered"].append(changed)
                entry["correct"] += (not verify_plan(grown)) and new.vlan_id == s.vlan_id and (
                    changed == 0 if gw != "last" else True
                )
            else:
                try:
                    double_in_place(plan, s.group)
                    refused_correctly = False
                except PlanError:
                    pass
    for entry in per_gateway.values():
        entry["renumbered"] = summarize(entry["renumbered"])
    all_correct = all(e["correct"] == e["doublable"] for e in per_gateway.values())
    return {
        "description": "can_double / double_in_place je Gateway-Position",
        "by_gateway_position": per_gateway,
        "refusals_correct": refused_correctly,
        "passed": all_correct and refused_correctly,
    }


def exp_ipv6(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """IPv6 mit Mindestgröße /64 (Satz "Robustheit"): Skalierung und Korrektheit."""
    rows = []
    for n in [x for x in (10, 100, 500, 1000, 2000) if x <= scale["max_n"]]:
        raw = random_raw(rng, n=n, v6=True, extra_selfref=False)
        cfg = build_config(raw)
        seconds = timed(lambda: plan_subnets(cfg), 1)
        plan = plan_subnets(cfg)
        rows.append({
            "n": n, "seconds_plan": seconds, "prefix_lengths": sorted({s.network.prefixlen for s in plan.subnets}),
            "free_ranges": len(plan.free_ranges), "verify_problems": len(verify_plan(plan, cfg)),
        })
    ok = 0
    for _ in range(scale["plans"]):
        raw = random_raw(rng, v6=True)
        cfg = build_config(raw)
        plan = plan_subnets(cfg)
        ok += not verify_plan(plan, cfg) and all(s.network.prefixlen <= 64 for s in plan.subnets)
    return {
        "description": "IPv6-Pläne im /48 mit max_prefix 64",
        "rows": rows,
        "random_plans_valid": ok,
        "random_plans": scale["plans"],
        "passed": ok == scale["plans"] and all(r["verify_problems"] == 0 for r in rows),
    }


def exp_policy_comparison(rng: random.Random, scale: Scale) -> Dict[str, Any]:
    """Richtlinienvergleich: exakte Prüfung gegen die Entscheidung des Subgraph Algorithmus.

    Informatives Experiment: Es misst, wie oft die Heuristik eine echte Teilmengenbeziehung
    erkennt (Treffer) und wie oft sie bei nicht enthaltenen Graphen fälschlich "enthalten"
    meldet. ``passed`` ist immer wahr, solange das Experiment läuft.
    """
    try:
        import numpy as np

        from src.policy import compare_matrices, matrix_included
    except ImportError as exc:  # Abhängigkeit fehlt
        return {"skipped": f"Paket 'subgraph' nicht verfügbar: {exc}", "passed": True}
    nrng = np.random.default_rng(rng.randrange(2**32))
    contained = {"a_in_b", "equal"}
    detected = missed = false_pos = rotation_agree = 0
    for _ in range(scale["pairs"]):
        n = int(nrng.integers(3, 7))
        b = (nrng.random((n, n)) < 0.4).astype(int)
        a = b * (nrng.random((n, n)) < 0.6)
        np.fill_diagonal(a, 0)
        np.fill_diagonal(b, 0)
        *_, exact, _decision, norm, _agrees = compare_matrices(a, b)
        assert matrix_included(a, b)
        detected += norm in contained
        missed += norm not in contained
        rotation_agree += exact in contained
    for _ in range(scale["pairs"]):
        n = int(nrng.integers(3, 7))
        a = (nrng.random((n, n)) < 0.4).astype(int)
        b = (nrng.random((n, n)) < 0.4).astype(int)
        np.fill_diagonal(a, 0)
        np.fill_diagonal(b, 0)
        *_, _exact, _decision, norm, _agrees = compare_matrices(a, b)
        false_pos += norm in contained and not matrix_included(a, b)
    pairs = scale["pairs"]
    return {
        "description": "A ⊆ B (komponentenweise) gegen die Signaturprüfung des Subgraph Algorithmus",
        "pairs_per_test": pairs,
        "contained_pairs": {
            "detected": detected, "missed": missed, "missed_rate": missed / pairs,
            "exact_rotation_check_detected": rotation_agree,
        },
        "independent_pairs": {"false_positives": false_pos, "false_positive_rate": false_pos / pairs},
        "conclusion": "Die exakte Prüfung ist maßgeblich; die Heuristik darf keine Richtlinie verwerfen.",
        "passed": rotation_agree == pairs,
    }


EXPERIMENTS: Dict[str, Callable[[random.Random, Scale], Dict[str, Any]]] = {
    "runtime": exp_runtime,
    "utilization": exp_utilization,
    "growth_factor": exp_growth_factor,
    "packability": exp_packability,
    "extension": exp_extension,
    "grouping": exp_grouping,
    "roundtrip": exp_roundtrip,
    "hierarchy": exp_hierarchy,
    "doubling": exp_doubling,
    "ipv6": exp_ipv6,
    "policy_comparison": exp_policy_comparison,
}


# --------------------------------------------------------------------------- Ausgabe und Lauf
def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, (Fraction, Decimal)):
        return float(value)
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    raise TypeError(f"Nicht serialisierbar: {type(value).__name__}")


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Schreibt JSON atomar (erst temporäre Datei, dann umbenennen); legt das Verzeichnis an."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default) + "\n", encoding="utf-8")
    tmp.replace(path)


def run_experiments(
    names: Optional[Sequence[str]] = None,
    output_dir: Path = RESULTS_DIR,
    seed: int = 2026,
    quick: bool = False,
) -> Dict[str, Any]:
    """Führt Experimente aus, schreibt je Experiment eine JSON-Datei und ``summary.json``.

    Gibt die Zusammenfassung zurück. Ein Experiment, das eine Ausnahme wirft, wird mit
    ``error`` vermerkt und gilt als nicht bestanden; die übrigen laufen weiter.
    """
    selected = list(names) if names else list(EXPERIMENTS)
    unknown = [n for n in selected if n not in EXPERIMENTS]
    if unknown:
        raise PlanError(f"Unbekannte Experimente {unknown}, verfügbar: {list(EXPERIMENTS)}")
    output_dir = Path(output_dir)
    started = datetime.now(timezone.utc)
    entries: Dict[str, Any] = {}
    for name in selected:
        scale = SIZES[name][1 if quick else 0]
        rng = random.Random(f"{seed}:{name}")
        begin = time.perf_counter()
        try:
            result = EXPERIMENTS[name](rng, scale)
        except Exception as exc:  # ein fehlerhaftes Experiment soll den Lauf nicht abbrechen
            result = {"error": f"{type(exc).__name__}: {exc}", "passed": False}
        elapsed = time.perf_counter() - begin
        payload = {
            "experiment": name, "seed": seed, "quick": quick, "sizes": scale,
            "seconds": elapsed, **result,
        }
        write_json(output_dir / f"{name}.json", payload)
        entries[name] = {
            "file": f"{name}.json", "seconds": elapsed, "passed": bool(result.get("passed", False)),
            **({"skipped": result["skipped"]} if "skipped" in result else {}),
            **({"error": result["error"]} if "error" in result else {}),
        }
    summary = {
        "software": "subnetplan",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "seed": seed,
        "quick": quick,
        "started": started.isoformat(),
        "finished": datetime.now(timezone.utc).isoformat(),
        "experiments": entries,
        "all_passed": all(e["passed"] for e in entries.values()),
    }
    write_json(output_dir / "summary.json", summary)
    return summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.experiments",
        description="Experimente zur Arbeit sbntgg; Ergebnisse als JSON nach src/results/.",
    )
    parser.add_argument("--only", nargs="+", metavar="NAME", help="nur diese Experimente ausführen")
    parser.add_argument("--list", action="store_true", help="verfügbare Experimente anzeigen und beenden")
    parser.add_argument("--quick", action="store_true", help="kleine Größen für einen schnellen Lauf")
    parser.add_argument("--seed", type=int, default=2026, help="Startwert der Zufallszahlen (Standard: 2026)")
    parser.add_argument("--output-dir", default=str(RESULTS_DIR), help="Zielverzeichnis (Standard: src/results)")
    args = parser.parse_args(argv)

    if args.list:
        for name, fn in EXPERIMENTS.items():
            print(f"{name:18} {(fn.__doc__ or '').strip().splitlines()[0]}")
        return 0
    try:
        summary = run_experiments(args.only, Path(args.output_dir), args.seed, args.quick)
    except PlanError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    for name, entry in summary["experiments"].items():
        state = "übersprungen" if "skipped" in entry else ("bestanden" if entry["passed"] else "FEHLGESCHLAGEN")
        print(f"{name:18} {state:14} {entry['seconds']:8.2f} s")
    print(f"Ergebnisse: {Path(args.output_dir)}")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":  # pragma: no cover - dünner Einstiegspunkt
    sys.exit(main())
