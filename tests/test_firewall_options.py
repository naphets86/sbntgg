import ipaddress
import pytest

from src.config import build_config
from src.firewall import (FirewallOptions, ascii_name, cisco_acl_name, render_cisco, render_firewall,
                          render_iptables, render_nftables)
from src.models import PlanError
from src.planner import plan_subnets
from src.roundtrip import (check_roundtrip, expected_pairs, parse_cisco, parse_iptables, parse_nftables,
                           parse_rules)
from tests.helpers import make

GLIST = [
    {"name": "Entwicklung", "hosts": 60, "access": ["Server", "Drucker"]},
    {"name": "Gäste", "hosts": 20},
    {"name": "HR", "hosts": 20, "access": ["Drucker", "Server"]},
    {"name": "Server", "hosts": 10, "access": ["Entwicklung"]},
    {"name": "Drucker", "hosts": 5},
]
ALL = FirewallOptions(group_rules=True, cisco_return="established", ascii_names=True, log_drops=True)


def test_ascii_name():
    assert ascii_name("Gäste-Äß Ö") == "Gaeste-AEss OE"
    assert ascii_name("Café") == "Cafe"
    assert ascii_name("日本") == "__"


def test_options_validation():
    _, plan = make(glist=GLIST)
    with pytest.raises(PlanError, match="cisco_return"):
        FirewallOptions(cisco_return="x").validate(plan)
    with pytest.raises(PlanError, match="ICMPv6-Typ"):
        FirewallOptions(icmpv6_types=("bad type;",)).validate(plan)
    with pytest.raises(PlanError, match="nur bei einem IPv6"):
        FirewallOptions(icmpv6_types=("packet-too-big",)).validate(plan)
    with pytest.raises(PlanError, match="Unbekanntes"):
        render_firewall(plan, "pf")


def test_iptables_idempotent_and_logging():
    _, plan = make(glist=GLIST)
    text = render_iptables(plan)
    lines = text.splitlines()
    assert lines.index("iptables -N SUBNET_ACL") > lines.index("iptables -X SUBNET_ACL 2>/dev/null || true")
    assert "while iptables -D FORWARD -j SUBNET_ACL 2>/dev/null; do :; done" in lines
    plain = render_iptables(plan, FirewallOptions(idempotent=False))
    assert "-D FORWARD" not in plain and "-F SUBNET_ACL" not in plain
    logged = render_iptables(plan, FirewallOptions(log_drops=True)).splitlines()
    assert "LOG" in logged[-3] and logged[-2] == "iptables -A SUBNET_ACL -j DROP"


def test_iptables_grouped_uses_ipset():
    _, plan = make(glist=GLIST)
    text = render_iptables(plan, FirewallOptions(group_rules=True))
    assert "ipset create -exist SUBNET_ACL_S1 hash:net family inet" in text
    assert text.count("--match-set") == 2 * len(__import__("src.access", fromlist=["x"]).rule_groups(plan))
    assert "ipset" in text and "-s 10." not in text


def test_ipv6_variants():
    cfg, plan = make(base="2001:db8::/48", glist=GLIST, max_prefix=64)
    opts = FirewallOptions(group_rules=True, icmpv6_types=("packet-too-big", "nd-neighbor-solicit"))
    ipt = render_iptables(plan, opts)
    assert "ip6tables" in ipt and "family inet6" in ipt and "--icmpv6-type packet-too-big -j ACCEPT" in ipt
    nft = render_nftables(plan, opts)
    assert "ip6 saddr" in nft and "icmpv6 type { packet-too-big, nd-neighbor-solicit } accept" in nft
    cisco = render_cisco(plan, FirewallOptions(group_rules=True, cisco_return="established"))
    assert "ipv6 access-list" in cisco and "object-group" not in cisco and "deny ipv6 any any" in cisco
    assert "permit tcp 2001" in cisco and "established" in cisco
    for kind in ("iptables", "nftables", "cisco"):
        assert check_roundtrip(plan, kind, opts if kind != "cisco" else FirewallOptions(cisco_return="established")).ok


def test_nftables_grouped_and_logged():
    _, plan = make(glist=GLIST)
    nft = render_nftables(plan, ALL)
    assert "saddr {" in nft and 'log prefix "subnet_acl drop: "' in nft
    assert "Gaeste" not in nft and "Gäste" not in nft  # Gäste hat keine Regeln
    assert 'comment "Entwicklung,HR -> Server,Drucker"' in nft


def test_cisco_names_and_options():
    _, plan = make(glist=GLIST)
    gaeste = next(s for s in plan.subnets if s.group == "Gäste")
    assert cisco_acl_name(gaeste) == f"ACL-{gaeste.vlan_id}-GÄSTE"
    assert cisco_acl_name(gaeste, True) == f"ACL-{gaeste.vlan_id}-GAESTE"
    text = render_cisco(plan, ALL)
    assert "object-group network OG-TARGETS-1" in text and "permit ip 10." in text
    assert "deny ip any any log" in text and "Rueckverkehr" in text and "Ä" not in text
    plain = render_cisco(plan)
    assert "established" not in plain and "object-group" not in plain and "log" not in plain


def test_cisco_object_groups_reused():
    glist = [{"name": "A", "hosts": 5, "access": ["C", "D"]}, {"name": "B", "hosts": 5, "access": ["D", "C"]},
             {"name": "C", "hosts": 5}, {"name": "D", "hosts": 5}]
    _, plan = make(glist=glist)
    text = render_cisco(plan, FirewallOptions(group_rules=True))
    assert text.count("object-group network") == 1
    assert text.count("object-group OG-TARGETS-1") == 2


@pytest.mark.parametrize("kind", ["iptables", "nftables", "cisco"])
@pytest.mark.parametrize("opts", [FirewallOptions(), ALL, FirewallOptions(group_rules=True), FirewallOptions(idempotent=False)])
def test_roundtrip_all_variants(kind, opts):
    _, plan = make(glist=GLIST)
    result = check_roundtrip(plan, kind, opts)
    assert result.ok and not result.missing and not result.extra and result.default_deny
    if kind == "cisco" and opts.cisco_return == "established":
        assert len(result.returns) == 3


def test_roundtrip_detects_tampering():
    _, plan = make(glist=GLIST)
    want = expected_pairs(plan)
    assert len(want) == 5
    from src.firewall import render_firewall as rf
    text = rf(plan, "nftables")
    lines = [l for l in text.splitlines() if "Server -> Entwicklung" not in l]
    parsed = parse_nftables("\n".join(lines))
    assert len(want - parsed.pairs) == 1
    extra = text.replace("policy drop;", "policy accept;")
    assert not parse_nftables(extra).default_deny
    ipt = rf(plan, "iptables").replace("-A SUBNET_ACL -j DROP", "-A SUBNET_ACL -j ACCEPT")
    assert not parse_iptables(ipt).default_deny
    assert not parse_iptables("iptables -A SUBNET_ACL -j DROP").default_deny  # ohne Sprung in FORWARD
    cis = rf(plan, "cisco").replace(" deny ip any any", " remark x", 1)
    assert not parse_cisco(cis).default_deny
    assert parse_cisco("").default_deny is False


def test_parser_errors():
    with pytest.raises(PlanError, match="Unbekanntes"):
        parse_rules("", "pf")
    with pytest.raises(PlanError, match="Ungültiges Netz"):
        parse_nftables("ip saddr { nonsense } ip daddr 10.0.0.0/24 accept")
    with pytest.raises(PlanError, match="ipset"):
        parse_iptables("iptables -A SUBNET_ACL -m set --match-set X src -m set --match-set Y dst -j ACCEPT")
    with pytest.raises(PlanError, match="Unbekannte Cisco"):
        parse_cisco("ip access-list extended X\n evaluate foo")
    with pytest.raises(PlanError, match="nicht lesbar"):
        parse_cisco("ip access-list extended X\n permit ip 10.0.0.0 bogus 10.0.1.0 0.0.0.255")
    with pytest.raises(PlanError, match="nicht lesbar"):
        parse_cisco("ip access-list extended X\n permit ip 10.0.0.0 0.0.0.255 object-group NOPE")
    # Zeilen außerhalb von ACLs und Kommentare werden ignoriert
    assert parse_cisco("! c\nip routing\n x\ninterface Vlan10\n ip access-group A in\n").pairs == frozenset()
