import ipaddress
import json
import pytest

from src.config import build_config, build_extension
from src.extend import (can_double, current_free_blocks, double_in_place, extend_plan,
                        plan_from_json, renumbered_hosts)
from src.hierarchy import aggregation_summary, plan_hierarchical, site_demands
from src.models import PlanError
from src.planner import plan_subnets
from src.render import render
from src.stats import sites_bound_holds
from src.verify import verify_plan
from tests.helpers import make

N = ipaddress.ip_network
SITES = [
    {"name": "A", "hosts": 100, "site": "Berlin", "access": ["C"]},
    {"name": "B", "hosts": 20, "site": "Berlin"},
    {"name": "C", "hosts": 50, "site": "Hamburg"},
    {"name": "D", "hosts": 10, "site": "Hamburg"},
]


def test_hierarchical_plan():
    cfg, plan = make(base="10.0.0.0/16", glist=SITES)
    assert dict(plan.site_blocks) == {"Berlin": N("10.0.0.0/24"), "Hamburg": N("10.0.1.0/24")}
    assert all(s.network.subnet_of(dict(plan.site_blocks)[s.site]) for s in plan.subnets)
    assert plan.allocated_addresses == 512
    ok, e, s, r = sites_bound_holds(plan, cfg)
    assert ok and e == 512
    assert verify_plan(plan) == []
    summary = aggregation_summary(plan)
    assert summary["routes_flat"] == 4 and summary["routes_aggregated"] == 2
    assert site_demands(cfg) == {"Berlin": 128 + 32, "Hamburg": 128 + 16}
    out = render(plan, "table")
    assert "Standort" in out and "Standortblöcke" in out
    assert "site" in render(plan, "csv").splitlines()[0]
    assert json.loads(render(plan, "json"))["site_blocks"]["Berlin"] == "10.0.0.0/24"


def test_hierarchical_fixed_strategy_and_summary_flat():
    cfg, plan = make(base="10.0.0.0/16", glist=SITES, allocation_strategy="fixed")
    assert site_demands(cfg)["Berlin"] == 2 * 128
    _, flat = make()
    assert aggregation_summary(flat)["routes_aggregated"] == 2
    with pytest.raises(PlanError):
        sites_bound_holds(flat, make()[0])


def test_hierarchical_errors():
    with pytest.raises(PlanError, match="alle Gruppen oder für keine"):
        make(glist=[{"name": "A", "hosts": 5, "site": "X"}, {"name": "B", "hosts": 5}])
    with pytest.raises(PlanError, match="nicht mit pools"):
        make(base="10.0.0.0/16", glist=SITES, existing=["10.0.200.0/24"])
    with pytest.raises(PlanError, match="Platzmangel"):
        make(base="10.0.0.0/25", glist=SITES)
    with pytest.raises(PlanError, match="passt nicht mehr"):
        make(base="10.0.0.0/23", glist=SITES + [{"name": "E", "hosts": 200, "site": "Koeln"}])


def test_extend_keeps_existing_and_vlans():
    cfg, plan = make()
    cfg2, new = build_extension({"groups": [{"name": "C", "hosts": 20, "access": ["A"]}]}, ["A", "B"], plan.base_network)
    ext = extend_plan(plan, new, cfg2)
    old = {s.group: s for s in plan.subnets}
    assert all(ext_s == old[ext_s.group] for ext_s in ext.subnets if ext_s.group in old)
    assert {s.vlan_id for s in ext.subnets} == {10, 20, 30}
    assert verify_plan(ext) == []
    assert plan_from_json(render(ext, "json")).subnets == ext.subnets


def test_extend_errors():
    cfg, plan = make()
    cfg2, new = build_extension({"groups": [{"name": "C", "hosts": 5}]}, ["A", "B"], plan.base_network)
    with pytest.raises(PlanError, match="Keine neuen"):
        extend_plan(plan, (), cfg2)
    _, dup = build_extension({"groups": [{"name": "C", "hosts": 5}]}, ["A", "B"], plan.base_network)
    with pytest.raises(PlanError, match="existieren bereits"):
        extend_plan(plan, new, cfg2) if False else extend_plan(extend_plan(plan, new, cfg2), new, cfg2)
    from src.models import Group
    with pytest.raises(PlanError, match="unbekannte"):
        extend_plan(plan, (Group("X", 1, access=("Nope",)),), cfg2)
    with pytest.raises(PlanError, match="VLAN"):
        extend_plan(plan, (Group("X", 1, vlan_id=10),), cfg2)
    with pytest.raises(PlanError, match="weder"):
        extend_plan(plan, (Group("X", 1, site="s"),), cfg2)
    with pytest.raises(PlanError, match="Platzmangel"):
        extend_plan(plan, (Group("X", 1000),), cfg2)


def test_extend_fixed_strategy_and_vlan_explicit():
    cfg, plan = make(base="10.0.0.0/24", glist=[{"name": "A", "hosts": 10}])
    cfg2, new = build_extension(
        {"allocation_strategy": "fixed", "groups": [{"name": "X", "hosts": 5, "vlan_id": 99}, {"name": "Y", "hosts": 20}]},
        ["A"], plan.base_network)
    ext = extend_plan(plan, new, cfg2)
    assert {s.group: s.vlan_id for s in ext.subnets}["X"] == 99
    sizes = {s.network.prefixlen for s in ext.subnets if s.group in ("X", "Y")}
    assert len(sizes) == 1


def test_build_extension_errors():
    with pytest.raises(PlanError):
        build_extension([], ["A"], "10.0.0.0/24")
    with pytest.raises(PlanError):
        build_extension({"groups": []}, ["A"], "10.0.0.0/24")


def test_plan_from_json_errors():
    with pytest.raises(PlanError, match="kein gültiger Plan"):
        plan_from_json("{")
    with pytest.raises(PlanError, match="kein gültiger Plan"):
        plan_from_json("{}")


def test_plan_from_json_with_pools_and_reserved():
    cfg, plan = make(base="10.0.0.0/25", pools=["10.0.1.0/25"], existing=["10.0.0.0/27"],
                     glist=[{"name": "A", "hosts": 40}, {"name": "B", "hosts": 40}])
    back = plan_from_json(render(plan, "json"))
    assert back.pools == plan.pools and back.reserved == plan.reserved
    assert set(back.free_ranges) == set(plan.free_ranges)


def test_double_in_place():
    cfg, plan = make(glist=[{"name": "A", "hosts": 100}, {"name": "B", "hosts": 10}])
    assert can_double(plan, "B")  # linke Hälfte, rechte Hälfte frei
    grown = double_in_place(plan, "B")
    b_old = next(s for s in plan.subnets if s.group == "B")
    b_new = next(s for s in grown.subnets if s.group == "B")
    assert b_new.network.prefixlen == b_old.network.prefixlen - 1
    assert b_new.network.network_address == b_old.network.network_address and b_new.gateway == b_old.gateway
    assert b_new.vlan_id == b_old.vlan_id
    assert renumbered_hosts(b_old, b_new) == 0
    assert verify_plan(grown) == []
    with pytest.raises(PlanError, match="Unbekannte"):
        can_double(plan, "Z")


def test_double_not_possible_and_gateway_last():
    cfg, plan = make(glist=[{"name": "A", "hosts": 100}, {"name": "B", "hosts": 100}])
    assert not can_double(plan, "A")  # rechter Nachbar belegt
    assert not can_double(plan, "B")  # rechte Hälfte des Elternblocks
    with pytest.raises(PlanError, match="verdoppelt"):
        double_in_place(plan, "A")
    cfg2, p2 = make(glist=[{"name": "A", "hosts": 10}], gateway_position="last")
    g = double_in_place(p2, "A")
    assert renumbered_hosts(p2.subnets[0], g.subnets[0]) >= 1
    cfg3, p3 = make(glist=[{"name": "A", "hosts": 10}], gateway_position="none")
    assert double_in_place(p3, "A").subnets[0].gateway is None
    cfg4, p4 = make(base="0.0.0.0/0", glist=[{"name": "A", "hosts": 2**31}])
    assert not can_double(p4, "A")


def test_double_outside_pool_and_free_blocks():
    cfg, plan = make(glist=[{"name": "A", "hosts": 100}])
    assert current_free_blocks(plan) == (N("10.0.0.128/25"),)
