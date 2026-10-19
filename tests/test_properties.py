"""Seeded Zufallstests: die Sätze der Arbeit gelten für beliebige Eingaben (kein Hypothesis nötig)."""
import ipaddress
import random

import pytest

from src.access import policy_pairs, rule_groups
from src.blocks import can_extend
from src.config import build_config, build_extension
from src.extend import current_free_blocks, extend_plan
from src.firewall import FirewallOptions, render_firewall
from src.models import PlanError
from src.planner import plan_subnets
from src.roundtrip import check_roundtrip, parse_rules
from src.semantics import cisco_verdict, firewall_verdict
from src.verify import verify_plan

pytestmark = pytest.mark.slow


def random_config(rng, v6=False, strategy="vlsm"):
    n = rng.randint(1, 8)
    names = [f"G{i}" for i in range(n)]
    groups = [
        {"name": nm, "hosts": rng.choice([1, 2, 5, 10, 30, 60, 100, 250]),
         "access": rng.sample(names, rng.randint(0, min(3, n))) + ([nm] if rng.random() < 0.2 else [])}
        for nm in names
    ]
    raw = {"base_network": "2001:db8::/48" if v6 else "10.0.0.0/16", "groups": groups,
           "growth_factor": rng.choice([1.0, 1.1, 1.25, 1.5, 2.0]), "allocation_strategy": strategy,
           "gateway_position": rng.choice(["first", "last", "none"])}
    if v6:
        raw["max_prefix"] = 64
    return build_config(raw)


@pytest.mark.parametrize("v6", [False, True])
@pytest.mark.parametrize("strategy", ["vlsm", "fixed"])
def test_random_plans_satisfy_all_theorems(v6, strategy):
    rng = random.Random(2026)
    for _ in range(60):
        cfg = random_config(rng, v6, strategy)
        plan = plan_subnets(cfg)
        assert verify_plan(plan, cfg) == []


def test_vlsm_never_worse_than_fixed():
    rng = random.Random(5)
    for _ in range(60):
        cfg = random_config(rng)
        fixed = build_config({**{"base_network": "10.0.0.0/16", "allocation_strategy": "fixed"},
                              "groups": [{"name": g.name, "hosts": g.hosts} for g in cfg.groups],
                              "growth_factor": cfg.growth_factor, "gateway_position": cfg.gateway_position})
        plain = build_config({"base_network": "10.0.0.0/16", "groups": [{"name": g.name, "hosts": g.hosts} for g in cfg.groups],
                              "growth_factor": cfg.growth_factor, "gateway_position": cfg.gateway_position})
        assert plan_subnets(plain).allocated_addresses <= plan_subnets(fixed).allocated_addresses


@pytest.mark.parametrize("kind", ["iptables", "nftables", "cisco"])
@pytest.mark.parametrize("grouped", [False, True])
def test_roundtrip_random(kind, grouped):
    rng = random.Random(11)
    for _ in range(40):
        cfg = random_config(rng, v6=rng.random() < 0.5)
        plan = plan_subnets(cfg)
        opts = FirewallOptions(group_rules=grouped, cisco_return="established", log_drops=True, ascii_names=True)
        assert check_roundtrip(plan, kind, opts).ok
        if grouped:
            assert len(rule_groups(plan)) <= len(plan.subnets)


def test_rule_verdicts_match_semantics():
    """Das Urteil der zurückgelesenen Regeln gleicht dem Referenzurteil aus P."""
    rng = random.Random(21)
    for _ in range(25):
        cfg = random_config(rng)
        plan = plan_subnets(cfg)
        for kind in ("nftables", "iptables", "cisco"):
            pairs = parse_rules(render_firewall(plan, kind), kind).pairs
            for _ in range(30):
                src, dst = (rng.choice(plan.subnets), rng.choice(plan.subnets))
                a = src.network[rng.randrange(src.network.num_addresses)]
                b = dst.network[rng.randrange(dst.network.num_addresses)]
                rules_say = any(a in s and b in d for s, d in pairs)
                assert rules_say == (firewall_verdict(plan, a, b) == "accept")
                if kind == "cisco":
                    assert rules_say == (cisco_verdict(plan, src.group, a, b) == "accept")


def test_extension_is_lossless():
    """Korollar: Erweiterung gelingt genau dann, wenn die Summe der neuen Blöcke <= F."""
    rng = random.Random(33)
    for _ in range(80):
        cfg = random_config(rng)
        plan = plan_subnets(cfg)
        free = sum(n.num_addresses for n in plan.free_ranges)
        hosts = rng.choice([5, 20, 50, 120, 400, 2000, 20000])
        new_raw = {"groups": [{"name": "NEU", "hosts": hosts}], "growth_factor": cfg.growth_factor,
                   "gateway_position": cfg.gateway_position}
        ecfg, new = build_extension(new_raw, [s.group for s in plan.subnets], plan.base_network)
        from src.planner import group_prefix
        size = 1 << (plan.base_network.max_prefixlen - group_prefix(new[0], ecfg))
        assert can_extend(current_free_blocks(plan), [size]) == (size <= free)
        if size <= free:
            ext = extend_plan(plan, new, ecfg)
            assert verify_plan(ext) == []
            assert all(s in ext.subnets for s in plan.subnets)
        else:
            with pytest.raises(PlanError):
                extend_plan(plan, new, ecfg)
