import ipaddress
import pytest

from src.config import build_config
from src.models import PlanError
from src.planner import (default_overhead, group_overhead, group_prefix, plan_subnets,
                         required_addresses)
from src.verify import verify_plan
from tests.helpers import make

N = ipaddress.ip_network


def test_overhead_defaults_and_override():
    assert default_overhead("first", 4) == 3 and default_overhead("none", 4) == 2
    assert default_overhead("first", 6) == 2 and default_overhead("none", 6) == 1
    cfg, _ = make(glist=[{"name": "A", "hosts": 10, "overhead": 5}])
    g = cfg.groups[0]
    assert group_overhead(g, "first", 4) == 5
    assert required_addresses(g, 1.25, "first", 4) == 13 + 5


def test_overhead_zero_point_to_point():
    cfg, plan = make(glist=[{"name": "P2P", "hosts": 2, "overhead": 0}], growth_factor=1.0)
    s = plan.subnets[0]
    assert s.network.prefixlen == 31 and s.usable_hosts == 2 and s.gateway is None and s.broadcast is None
    assert verify_plan(plan, cfg) == []


def test_overhead_cloud_reserved_five():
    cfg, plan = make(glist=[{"name": "Cloud", "hosts": 11, "overhead": 5}], growth_factor=1.0)
    s = plan.subnets[0]
    assert s.network.num_addresses == 16 and s.usable_hosts == 11
    assert s.gateway == s.network.network_address + 1  # direkt nach der Netzadresse
    assert s.first_host == s.network.network_address + 4  # zwei weitere reservierte Adressen
    assert verify_plan(plan, cfg) == []


def test_overhead_one_and_gateway_last():
    _, plan = make(glist=[{"name": "A", "hosts": 5, "overhead": 1}], gateway_position="last")
    s = plan.subnets[0]
    assert s.broadcast is None and s.usable_hosts == s.network.num_addresses - 1
    _, plan2 = make(glist=[{"name": "A", "hosts": 5}], gateway_position="last")
    s2 = plan2.subnets[0]
    assert s2.gateway == s2.network.broadcast_address - 1


def test_max_prefix_minimum_block_ipv6():
    cfg, plan = make(base="2001:db8::/48", glist=[{"name": "A", "hosts": 10}, {"name": "B", "hosts": 5000}], max_prefix=64)
    assert all(s.network.prefixlen <= 64 for s in plan.subnets)
    assert {s.network.prefixlen for s in plan.subnets} == {64}
    assert verify_plan(plan, cfg) == []
    assert group_prefix(cfg.groups[0], cfg) == 64


def test_fixed_networks_and_existing():
    cfg, plan = make(
        glist=[{"name": "A", "hosts": 40, "network": "10.0.0.128/26"}, {"name": "B", "hosts": 40}, {"name": "C", "hosts": 10}],
        existing=["10.0.0.0/27"],
    )
    nets = {s.group: s.network for s in plan.subnets}
    assert nets["A"] == N("10.0.0.128/26")
    assert not any(n.overlaps(N("10.0.0.0/27")) for g, n in nets.items())
    assert plan.reserved == (N("10.0.0.0/27"),)
    assert plan.reserved_addresses == 32
    assert plan.free_addresses == 256 - sum(n.num_addresses for n in nets.values()) - 32
    assert verify_plan(plan, cfg) == []


def test_fixed_network_too_small_and_overlap():
    with pytest.raises(PlanError, match="fasst"):
        make(glist=[{"name": "A", "hosts": 50, "network": "10.0.0.0/28"}])
    with pytest.raises(PlanError, match="überschneiden"):
        make(glist=[{"name": "A", "hosts": 5, "network": "10.0.0.0/28"}], existing=["10.0.0.0/27"])
    with pytest.raises(PlanError, match="keinem Pool"):
        make(glist=[{"name": "A", "hosts": 5, "network": "10.9.0.0/28"}])


def test_multiple_pools_packing():
    cfg, plan = make(
        base="10.0.0.0/25",
        pools=["10.0.1.0/25"],
        glist=[{"name": "A", "hosts": 100}, {"name": "B", "hosts": 40}, {"name": "C", "hosts": 10}],
    )
    assert plan.total_addresses == 256 and len(plan.all_pools) == 2
    assert all(any(s.network.subnet_of(p) for p in plan.all_pools) for s in plan.subnets)
    assert {s.group: s.network.prefixlen for s in plan.subnets} == {"A": 25, "B": 26, "C": 28}
    assert verify_plan(plan, cfg) == []


def test_pool_space_exhausted_messages():
    with pytest.raises(PlanError, match="Platzmangel"):
        make(base="10.0.0.0/25", pools=["10.0.1.0/26"], glist=[{"name": "A", "hosts": 100}, {"name": "B", "hosts": 100}])


def test_fixed_strategy_with_existing():
    cfg, plan = make(
        base="10.0.0.0/24",
        existing=["10.0.0.0/26"],
        allocation_strategy="fixed",
        glist=[{"name": "A", "hosts": 20}, {"name": "B", "hosts": 5}, {"name": "C", "hosts": 5}],
    )
    assert {s.network.prefixlen for s in plan.subnets} == {27}
    assert verify_plan(plan, cfg) == []


def test_only_fixed_groups():
    cfg, plan = make(glist=[{"name": "A", "hosts": 5, "network": "10.0.0.0/28"}], allocation_strategy="fixed")
    assert plan.subnets[0].network == N("10.0.0.0/28")


def test_strategy_and_prefix_limits_simple():
    with pytest.raises(PlanError):
        make(base="10.0.0.0/30", glist=[{"name": "A", "hosts": 100}])
