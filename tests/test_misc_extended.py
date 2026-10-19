import ipaddress
from dataclasses import replace
import pytest

from src.access import plan_access_matrix, policy_pairs
from src.config import build_config
from src.firewall import _access_pairs, render_firewall
from src.models import Group, PlanConfig, PlanError
from src.planner import plan_subnets
from src.render import render
from src.roundtrip import parse_cisco
from src.verify import verify_plan
from tests.helpers import make

N = ipaddress.ip_network


def raw_plan(groups, base="10.0.0.0/24"):
    """Plan ohne Bereinigung von access (wie bei von Hand gebauten Konfigurationen)."""
    return plan_subnets(PlanConfig(N(base), tuple(groups)))


def test_unbereinigter_access_wird_toleriert():
    plan = raw_plan([Group("A", 5, access=("A", "B", "Z")), Group("B", 5)])
    assert policy_pairs(plan) == {("A", "B")}
    names, z = plan_access_matrix(plan)
    assert z.sum() == 2  # Selbstbezug zählt in Z, unbekanntes Ziel nicht
    plan2 = raw_plan([Group("A", 5, access=("A", "B")), Group("B", 5)])
    assert [(s.group, t.group) for s, t in _access_pairs(plan2)] == [("A", "B")]


@pytest.mark.parametrize("bad", [
    {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 1, "site": ""}]},
    {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 1, "site": 5}]},
    {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 1, "site": "a/b"}]},
    {"base_network": "10.0.0.0/24", "pools": "10.0.1.0/24", "groups": [{"name": "A", "hosts": 1}]},
    {"base_network": "10.0.0.0/24", "pools": ["2001:db8::/64"], "groups": [{"name": "A", "hosts": 1}]},
    {"base_network": "10.0.0.0/24", "existing": ["x"], "groups": [{"name": "A", "hosts": 1}]},
    {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 1, "network": "2001:db8::/64"}]},
    {"base_network": "10.0.0.0/24", "groups": [{"name": "A", "hosts": 1, "overhead": -1}]},
    {"base_network": "10.0.0.0/24", "max_prefix": 40, "groups": [{"name": "A", "hosts": 1}]},
])
def test_config_rejects(bad):
    with pytest.raises(PlanError):
        build_config(bad)


def test_config_accepts_new_keys_and_warns():
    cfg = build_config({
        "base_network": "10.0.0.0/16", "pools": ["10.1.0.0/16"], "existing": ["10.0.0.0/24"], "max_prefix": 26,
        "groups": [{"name": "A", "hosts": 5, "access": ["A", "B", "B"], "overhead": 2, "site": " X "},
                   {"name": "B", "hosts": 5, "site": "X"}]})
    assert cfg.max_prefix == 26 and cfg.pools == (N("10.1.0.0/16"),) and cfg.existing == (N("10.0.0.0/24"),)
    assert cfg.groups[0].site == "X" and cfg.groups[0].access == ("B",) and len(cfg.warnings) == 2


def test_render_table_with_pools_and_reserved():
    cfg, plan = make(base="10.0.0.0/25", pools=["10.0.1.0/25"], existing=["10.0.0.0/27"],
                     glist=[{"name": "A", "hosts": 40}])
    out = render(plan, "table")
    assert "10.0.0.0/25, 10.0.1.0/25 (256 Adressen)" in out


def test_verify_fixed_strategy_plan():
    cfg, plan = make(allocation_strategy="fixed",
                     glist=[{"name": "A", "hosts": 50}, {"name": "B", "hosts": 5}])
    assert verify_plan(plan, cfg) == []


def test_cisco_parser_ignores_other_deny():
    text = "ip access-list extended X\n deny tcp any any\n permit ip 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255\n"
    parsed = parse_cisco(text)
    assert not parsed.default_deny and len(parsed.pairs) == 1


def test_double_whole_space():
    from src.extend import can_double
    cfg, plan = make(base="0.0.0.0/0", glist=[{"name": "A", "hosts": 2**32 - 3}], growth_factor=1.0)
    assert plan.subnets[0].network.prefixlen == 0 and not can_double(plan, "A")


def test_cannot_double_when_net_fills_pool():
    from src.extend import can_double
    cfg, plan = make(base="10.0.0.0/25", glist=[{"name": "A", "hosts": 100}])
    assert plan.subnets[0].network == plan.base_network and not can_double(plan, "A")
