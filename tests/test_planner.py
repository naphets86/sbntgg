import ipaddress

import pytest

from src import planner
from src.config import build_config
from src.models import Group, PlanError
from src.planner import (
    _free_ranges,
    assign_vlans,
    plan_subnets,
    prefix_for,
    required_addresses,
)

pytestmark = pytest.mark.unit


def make_plan(**overrides):
    data = {
        "base_network": "10.0.0.0/24",
        "groups": [
            {"name": "A", "hosts": 50, "access": ["B"]},
            {"name": "B", "hosts": 10},
        ],
    }
    data.update(overrides)
    return plan_subnets(build_config(data))


def test_required_addresses_counts_growth_and_overhead():
    group = Group("A", 100)
    assert required_addresses(group, 1.25, "first", 4) == 125 + 3
    assert required_addresses(group, 1.25, "none", 4) == 125 + 2
    assert required_addresses(group, 1.25, "last", 6) == 125 + 2
    assert required_addresses(group, 1.25, "none", 6) == 125 + 1


def test_required_addresses_ignores_float_noise():
    # 100 * 1.1 == 110.00000000000001 darf nicht auf 111 aufrunden
    assert required_addresses(Group("A", 100), 1.1, "none", 4) == 110 + 2


@pytest.mark.parametrize(
    "total, expected",
    [(256, 24), (257, 23), (5, 29), (3, 30), (2, 31)],
)
def test_prefix_for(total, expected):
    assert prefix_for(total, 32, "A") == expected


def test_prefix_for_rejects_impossible_sizes():
    with pytest.raises(PlanError, match="passen in keinen Adressraum"):
        prefix_for(2**40, 32, "A")


def test_assign_vlans_keeps_explicit_ids_and_fills_gaps():
    groups = [
        Group("A", 1),
        Group("B", 1, vlan_id=10),
        Group("C", 1),
        Group("D", 1, vlan_id=30),
        Group("E", 1),
    ]
    assert assign_vlans(groups) == {"A": 20, "B": 10, "C": 40, "D": 30, "E": 50}


def test_assign_vlans_runs_out_of_ids(monkeypatch):
    monkeypatch.setattr(planner, "VLAN_MAX", 20)
    with pytest.raises(PlanError, match="Keine freie VLAN-ID"):
        assign_vlans([Group("A", 1), Group("B", 1), Group("C", 1)])


def test_vlsm_layout_and_details():
    plan = make_plan()
    a, b = plan.subnets  # A: 63 + 3 -> /25 zuerst, B: 13 + 3 = 16 -> /28
    assert a.group == "A"
    assert str(a.network) == "10.0.0.0/25"
    assert a.netmask == "255.255.255.128"
    assert str(a.gateway) == "10.0.0.1"
    assert str(a.first_host) == "10.0.0.2"
    assert str(a.last_host) == "10.0.0.126"
    assert str(a.broadcast) == "10.0.0.127"
    assert a.usable_hosts == 125
    assert a.requested_hosts == 50
    assert a.vlan_id == 10
    assert a.access == ("B",)
    assert str(b.network) == "10.0.0.128/28"
    assert str(b.gateway) == "10.0.0.129"
    assert str(b.broadcast) == "10.0.0.143"
    assert b.usable_hosts == 13
    assert b.vlan_id == 20
    assert [str(n) for n in plan.free_ranges] == ["10.0.0.144/28", "10.0.0.160/27", "10.0.0.192/26"]
    assert plan.total_addresses == 256
    assert plan.allocated_addresses == 144
    assert plan.free_addresses == 112
    assert plan.utilization == pytest.approx(56.25)


def test_vlsm_places_largest_group_first_regardless_of_config_order():
    plan = make_plan(groups=[{"name": "Small", "hosts": 5}, {"name": "Big", "hosts": 100}])
    assert [s.group for s in plan.subnets] == ["Big", "Small"]


def test_vlsm_priority_breaks_ties_then_config_order():
    groups = [
        {"name": "X", "hosts": 10, "priority": 5},
        {"name": "Y", "hosts": 10, "priority": 1},
        {"name": "Z", "hosts": 10, "priority": 1},
    ]
    plan = make_plan(groups=groups)
    assert [s.group for s in plan.subnets] == ["Y", "Z", "X"]


def test_fixed_strategy_uses_uniform_prefix_and_priority_order():
    groups = [
        {"name": "Small", "hosts": 5, "priority": 0},
        {"name": "Big", "hosts": 50, "priority": 1},
    ]
    plan = make_plan(groups=groups, allocation_strategy="fixed")
    assert [s.group for s in plan.subnets] == ["Small", "Big"]
    assert {s.network.prefixlen for s in plan.subnets} == {25}
    assert str(plan.subnets[1].network) == "10.0.0.128/25"
    assert plan.free_ranges == ()


def test_gateway_positions():
    last = make_plan(gateway_position="last").subnets[0]
    assert str(last.gateway) == "10.0.0.126"
    assert str(last.first_host) == "10.0.0.1"
    assert str(last.last_host) == "10.0.0.125"
    none = make_plan(gateway_position="none").subnets[0]
    assert none.gateway is None
    assert str(none.first_host) == "10.0.0.1"
    assert str(none.last_host) == "10.0.0.126"


@pytest.mark.parametrize("hosts", [1, 2, 5, 29, 30, 31, 60, 61, 100, 253])
def test_usable_hosts_cover_demand_including_growth(hosts):
    plan = make_plan(
        base_network="10.0.0.0/8",
        groups=[{"name": "G", "hosts": hosts}],
        growth_factor=1.5,
    )
    assert plan.subnets[0].usable_hosts >= -(-hosts * 3 // 2)


def test_networks_are_aligned_and_do_not_overlap():
    sizes = [3, 200, 17, 60, 9, 1000, 31]
    groups = [{"name": f"G{i}", "hosts": h} for i, h in enumerate(sizes)]
    plan = make_plan(base_network="10.0.0.0/20", groups=groups)
    nets = [s.network for s in plan.subnets]
    for i, net in enumerate(nets):
        assert net.subnet_of(plan.base_network)
        assert all(not net.overlaps(other) for other in nets[i + 1:])
    covered = sum(n.num_addresses for n in nets) + sum(n.num_addresses for n in plan.free_ranges)
    assert covered == plan.total_addresses


def test_single_group_leaves_binary_remainder_as_free_ranges():
    plan = make_plan(groups=[{"name": "G", "hosts": 10}])  # 13 + 3 = 16 -> /28
    assert [str(n) for n in plan.free_ranges] == [
        "10.0.0.16/28",
        "10.0.0.32/27",
        "10.0.0.64/26",
        "10.0.0.128/25",
    ]


def test_free_ranges_include_gap_before_first_network():
    base = ipaddress.ip_network("10.0.0.0/24")
    free = _free_ranges(base, [ipaddress.ip_network("10.0.0.128/25")])
    assert [str(n) for n in free] == ["10.0.0.0/25"]


def test_free_ranges_include_gap_between_networks():
    base = ipaddress.ip_network("10.0.0.0/24")
    nets = [ipaddress.ip_network("10.0.0.0/26"), ipaddress.ip_network("10.0.0.128/25")]
    assert [str(n) for n in _free_ranges(base, nets)] == ["10.0.0.64/26"]


def test_exact_fit_has_no_free_ranges():
    plan = make_plan(groups=[{"name": "G", "hosts": 200}])  # 250 + 3 = 253 -> /24
    assert str(plan.subnets[0].network) == "10.0.0.0/24"
    assert plan.free_ranges == ()
    assert plan.free_addresses == 0


def test_not_enough_space_left():
    groups = [{"name": "A", "hosts": 200}, {"name": "B", "hosts": 10}]
    with pytest.raises(PlanError, match="passt nicht mehr"):
        make_plan(groups=groups)


def test_group_larger_than_base_network():
    with pytest.raises(PlanError, match="Platzmangel.*kleiner"):
        make_plan(groups=[{"name": "A", "hosts": 1000}])


def test_ipv6_plan():
    plan = make_plan(base_network="2001:db8::/64", groups=[{"name": "A", "hosts": 100}])
    subnet = plan.subnets[0]
    assert str(subnet.network) == "2001:db8::/121"  # 125 + Netz + Gateway = 127 -> 128
    assert subnet.broadcast is None
    assert str(subnet.gateway) == "2001:db8::1"
    assert str(subnet.first_host) == "2001:db8::2"
    assert str(subnet.last_host) == "2001:db8::7f"
    assert subnet.usable_hosts == 126
    assert plan.free_ranges[0] == ipaddress.ip_network("2001:db8::80/121")


def test_ipv6_low_addresses_are_not_mistaken_for_ipv4():
    plan = make_plan(base_network="::/64", groups=[{"name": "A", "hosts": 5}])
    assert plan.subnets[0].network.version == 6


def test_subnet_as_dict():
    data = make_plan(gateway_position="none").subnets[0].as_dict()
    assert data["gateway"] is None
    assert data["access"] == ["B"]
    assert data["network"] == "10.0.0.0/25"
    assert data["broadcast"] == "10.0.0.127"
