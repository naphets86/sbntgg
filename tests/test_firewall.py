import pytest

from src.config import build_config
from src.firewall import _access_pairs, cisco_acl_name, render_firewall
from src.models import PlanError
from src.planner import plan_subnets

pytestmark = pytest.mark.unit

V6_GROUPS = [{"name": "A", "hosts": 5, "access": ["B"]}, {"name": "B", "hosts": 5}]


def make_plan(**overrides):
    data = {"base_network": "10.0.0.0/24"}
    data.update(overrides)
    return plan_subnets(build_config(data))


@pytest.fixture
def plan():
    return make_plan(
        groups=[
            {"name": "Entwicklung", "hosts": 50, "vlan_id": 10, "access": ["Server", "Entwicklung"]},
            {"name": "Server", "hosts": 10, "vlan_id": 20},
            {"name": "Gäste", "hosts": 5},
        ]
    )


def networks(plan):
    src = next(s for s in plan.subnets if s.group == "Entwicklung").network
    dst = next(s for s in plan.subnets if s.group == "Server").network
    return src, dst


def test_access_pairs_skip_access_to_own_group(plan):
    pairs = [(a.group, b.group) for a, b in _access_pairs(plan)]
    assert pairs == [("Entwicklung", "Server")]


def test_iptables_rules(plan):
    src, dst = networks(plan)
    text = render_firewall(plan, "iptables")
    lines = text.splitlines()
    assert lines[0] == "#!/bin/sh"
    assert "iptables -N SUBNET_ACL" in lines
    assert (
        f'iptables -A SUBNET_ACL -s {src} -d {dst} '
        '-m comment --comment "Entwicklung -> Server" -j ACCEPT'
    ) in lines
    assert lines[-2:] == ["iptables -A SUBNET_ACL -j DROP", "iptables -I FORWARD 1 -j SUBNET_ACL"]
    assert "ip6tables" not in text


def test_ip6tables_for_ipv6():
    plan = make_plan(base_network="2001:db8::/64", groups=V6_GROUPS)
    text = render_firewall(plan, "iptables")
    assert "ip6tables -N SUBNET_ACL" in text
    assert "ip6tables -A SUBNET_ACL -s 2001:db8::" in text


def test_nftables_rules(plan):
    src, dst = networks(plan)
    text = render_firewall(plan, "nftables")
    assert "policy drop;" in text
    assert "ct state established,related accept" in text
    assert f'ip saddr {src} ip daddr {dst} accept comment "Entwicklung -> Server"' in text
    assert text.rstrip().endswith("}")
    assert "ip6" not in text


def test_nftables_for_ipv6():
    plan = make_plan(base_network="2001:db8::/64", groups=V6_GROUPS)
    assert "ip6 saddr 2001:db8::" in render_firewall(plan, "nftables")


def test_cisco_ipv4_acls(plan):
    src, dst = networks(plan)
    text = render_firewall(plan, "cisco")
    assert "ip access-list extended ACL-10-ENTWICKLUNG" in text
    assert " remark Entwicklung -> Server" in text
    assert (
        f" permit ip {src.network_address} {src.hostmask} {dst.network_address} {dst.hostmask}"
    ) in text
    assert "interface Vlan10\n ip access-group ACL-10-ENTWICKLUNG in" in text


def test_cisco_group_without_access_only_denies(plan):
    text = render_firewall(plan, "cisco")
    guests = plan.subnets[2]
    block = text.split(f"ip access-list extended ACL-{guests.vlan_id}-GÄSTE\n")[1]
    assert block.startswith(" deny ip any any\n")
    assert text.count(" deny ip any any") == 3


def test_cisco_acl_name_replaces_spaces():
    plan = make_plan(groups=[{"name": "Mein Team", "hosts": 5, "vlan_id": 7}])
    assert cisco_acl_name(plan.subnets[0]) == "ACL-7-MEIN_TEAM"


def test_cisco_ipv6_acls():
    plan = make_plan(base_network="2001:db8::/64", groups=V6_GROUPS)
    text = render_firewall(plan, "cisco")
    assert "ipv6 access-list ACL-10-A" in text
    assert " permit ipv6 2001:db8::" in text
    assert " deny ipv6 any any" in text
    assert " ipv6 traffic-filter ACL-10-A in" in text


def test_unknown_firewall_system(plan):
    with pytest.raises(PlanError, match="Unbekanntes Firewall-System"):
        render_firewall(plan, "pf")
