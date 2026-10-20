"""Tests zu Kapitel "Erweiterung um Protokolle und Ports": Einbindung in Konfiguration,
Regelerzeugung, Rückübersetzung, Urteil, Plan-JSON, Verifikation und Kommandozeile."""
import json
import random
from dataclasses import replace

import pytest

from src.access import (
    clean_access, pair_services, policy_pairs, policy_services, rule_groups, services_included,
)
from src.checks import plan_warnings
from src.cli import main
from src.config import build_config, build_extension
from src.extend import double_in_place, extend_plan, plan_from_json
from src.firewall import FirewallOptions, render_cisco, render_firewall, render_iptables, render_nftables
from src.models import Group, PlanError
from src.planner import plan_subnets
from src.ports import ServiceSet
from src.render import render
from src.roundtrip import check_roundtrip, parse_rules
from src.semantics import cisco_verdict, firewall_verdict
from src.verify import verify_plan

KINDS = ("iptables", "nftables", "cisco")
OPTION_SETS = (
    FirewallOptions(),
    FirewallOptions(group_rules=True, cisco_return="established", ascii_names=True, log_drops=True),
)


def raw_config(**top):
    cfg = {
        "base_network": "10.20.0.0/16",
        "groups": [
            {"name": "Server", "hosts": 40, "vlan_id": 100, "access": ["Drucker"]},
            {
                "name": "Entwicklung",
                "hosts": 120,
                "access": [
                    {"to": "Server", "ports": ["tcp/22", "tcp/443", "tcp/8000-8099", "icmp"]},
                    {"to": "Drucker", "ports": ["tcp/631", "tcp/9100"]},
                ],
            },
            {"name": "HR", "hosts": 25, "access": [{"to": "Drucker", "ports": ["tcp/631"]}]},
            {"name": "Drucker", "hosts": 12},
            {"name": "Gäste", "hosts": 60},
        ],
    }
    cfg.update(top)
    return cfg


def v6_groups():
    """Gruppen ohne das IPv4-spezifische icmp (bei IPv6 gibt es nur icmpv6)."""
    groups = raw_config()["groups"]
    groups[1]["access"][0]["ports"].remove("icmp")
    return groups


def make(**top):
    cfg = build_config(raw_config(**top))
    return cfg, plan_subnets(cfg)


def sigma_of(plan, src, dst):
    return pair_services(next(s for s in plan.subnets if s.group == src), dst)


# --------------------------------------------------------------------------- Konfiguration
def test_config_parses_service_entries():
    cfg, plan = make()
    dev = next(g for g in cfg.groups if g.name == "Entwicklung")
    assert dev.access == ("Server", "Drucker")
    assert dict(dev.services)["Server"].specs() == ("tcp/22", "tcp/443", "tcp/8000-8099", "icmp")
    server = next(g for g in cfg.groups if g.name == "Server")
    assert server.services == ()  # bloßer Name: alle Dienste
    assert sigma_of(plan, "Server", "Drucker") is None
    assert policy_pairs(plan) == {
        ("Server", "Drucker"), ("Entwicklung", "Server"), ("Entwicklung", "Drucker"), ("HR", "Drucker")
    }


def test_access_entry_without_ports_means_all_services():
    cfg, plan = make()
    groups = raw_config()["groups"]
    groups[0]["access"] = [{"to": "Drucker"}]
    cfg = build_config({"base_network": "10.0.0.0/16", "groups": groups})
    assert cfg.groups[0].access == ("Drucker",) and cfg.groups[0].services == ()


def test_ports_may_be_a_single_string():
    groups = raw_config()["groups"]
    groups[2]["access"] = [{"to": "Drucker", "ports": "tcp/631"}]
    cfg = build_config({"base_network": "10.0.0.0/16", "groups": groups})
    assert dict(cfg.groups[2].services)["Drucker"].specs() == ("tcp/631",)


@pytest.mark.parametrize(
    "entry,message",
    [
        ({"ports": ["tcp/22"]}, "'to'"),
        ({"to": "", "ports": ["tcp/22"]}, "'to'"),
        ({"to": 5, "ports": ["tcp/22"]}, "'to'"),
        ({"to": "Drucker", "port": ["tcp/22"]}, "unbekannte Schlüssel"),
        ({"to": "Drucker", "ports": []}, "nicht leer"),
        ({"to": "Drucker", "ports": [443]}, "Protokoll"),
        ({"to": "Drucker", "ports": ["tcp/0"]}, "Port 0"),
        ({"to": "Drucker", "ports": ["tcp/9-3"]}, "hinter"),
        ({"to": "Drucker", "ports": ["icmpv6"]}, "IPv4"),
        ({"to": "Ghost", "ports": ["tcp/22"]}, "unbekannte Gruppen"),
        (7, "'access'"),
    ],
)
def test_config_rejects_bad_entries(entry, message):
    groups = raw_config()["groups"]
    groups[2]["access"] = [entry]
    with pytest.raises(PlanError, match=message):
        build_config({"base_network": "10.0.0.0/16", "groups": groups})


def test_icmp_rejected_for_ipv6_and_icmpv6_accepted():
    groups = v6_groups()
    groups[2]["access"] = [{"to": "Drucker", "ports": ["icmp"]}]
    with pytest.raises(PlanError, match="IPv6"):
        build_config({"base_network": "2001:db8::/32", "groups": groups})
    groups[2]["access"] = [{"to": "Drucker", "ports": ["icmpv6", "tcp/631"]}]
    cfg = build_config({"base_network": "2001:db8::/32", "groups": groups})
    assert dict(cfg.groups[2].services)["Drucker"].specs() == ("tcp/631", "icmpv6")


def test_overlapping_ports_give_warnings():
    groups = raw_config()["groups"]
    groups[2]["access"] = [{"to": "Drucker", "ports": ["tcp/600-700", "tcp/631"]}]
    cfg = build_config({"base_network": "10.0.0.0/16", "groups": groups})
    assert any("überlappen" in w for w in cfg.warnings)
    assert dict(cfg.groups[2].services)["Drucker"].specs() == ("tcp/600-700",)


def test_unrestricted_service_list_is_dropped():
    groups = raw_config()["groups"]
    groups[2]["access"] = [{"to": "Drucker", "ports": ["tcp", "udp", "icmp"]}]
    cfg = build_config({"base_network": "10.0.0.0/16", "groups": groups})
    assert cfg.groups[2].services == ()
    plain = [dict(g) for g in groups]
    plain[2]["access"] = ["Drucker"]
    base = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": plain}))
    assert render_firewall(plan_subnets(cfg), "nftables") == render_firewall(base, "nftables")


def test_duplicate_targets_are_merged():
    """Definition "Dienstfreigabe": Sigma_ij ist die Vereinigung aller Einträge."""
    groups = raw_config()["groups"]
    groups[2]["access"] = [
        {"to": "Drucker", "ports": ["tcp/631"]},
        {"to": "Drucker", "ports": ["tcp/9100", "udp/161"]},
    ]
    cfg = build_config({"base_network": "10.0.0.0/16", "groups": groups})
    assert cfg.groups[2].access == ("Drucker",)
    assert dict(cfg.groups[2].services)["Drucker"].specs() == ("tcp/631", "tcp/9100", "udp/161")
    assert any("steht mehrfach" in w for w in cfg.warnings)
    # ein Eintrag ohne Einschränkung macht das Ziel unbeschränkt
    groups[2]["access"] = [{"to": "Drucker", "ports": ["tcp/631"]}, "Drucker"]
    assert build_config({"base_network": "10.0.0.0/16", "groups": groups}).groups[2].services == ()


def test_self_reference_with_ports_is_removed():
    cleaned, warns = clean_access(
        [Group("A", 1, access=("A", "B"), services=(("A", ServiceSet.from_specs(["tcp/1"])),)), Group("B", 1)]
    )
    assert cleaned[0].access == ("B",) and cleaned[0].services == ()
    assert len(warns) == 1


# --------------------------------------------------------------------------- Regeln
def test_unrestricted_rules_unchanged():
    """Ohne Beschränkung bleibt die Ausgabe die der reinen Adressregeln."""
    cfg = build_config({"base_network": "10.20.0.0/16", "groups": [
        {"name": "A", "hosts": 5, "access": ["B"]}, {"name": "B", "hosts": 5}]})
    plan = plan_subnets(cfg)
    assert "ip saddr 10.20.0.0/28 ip daddr 10.20.0.16/28 accept comment \"A -> B\"" in render_nftables(plan)
    assert "-s 10.20.0.0/28 -d 10.20.0.16/28 -m comment --comment \"A -> B\" -j ACCEPT" in render_iptables(plan)
    assert " permit ip 10.20.0.0 0.0.0.15 10.20.0.16 0.0.0.15" in render_cisco(plan)


def test_iptables_rules_per_interval():
    _, plan = make()
    text = render_iptables(plan)
    base = "iptables -A SUBNET_ACL -s 10.20.0.0/24 -d 10.20.1.128/26"
    assert f'{base} -p tcp --dport 22 -m comment --comment "Entwicklung -> Server [tcp/22,tcp/443,tcp/8000-8099,icmp]" -j ACCEPT' in text
    assert f"{base} -p tcp --dport 443 " in text
    assert f"{base} -p tcp --dport 8000:8099 " in text
    assert f"{base} -p icmp " in text
    assert "-s 10.20.1.128/26 -d 10.20.2.0/27 -m comment --comment \"Server -> Drucker\" -j ACCEPT" in text
    assert text.count("--dport") == 6  # 22, 443, 8000:8099, 631, 9100 und HR 631
    # Korollar "Regelzahl": Intervalle je Paar (3 + 1 icmp) + (2) + (1) + Server->Drucker (1)
    assert text.count("-j ACCEPT") == 1 + (3 + 1) + 2 + 1 + 1


def test_nftables_rules_use_sets_per_protocol():
    _, plan = make()
    text = render_nftables(plan)
    assert 'tcp dport { 22, 443, 8000-8099 } accept comment "Entwicklung -> Server [tcp/22,tcp/443,tcp/8000-8099,icmp]"' in text
    assert "meta l4proto icmp accept" in text
    assert "tcp dport { 631, 9100 } accept" in text
    assert "ip daddr 10.20.2.0/27 tcp dport 631 accept comment \"HR -> Drucker [tcp/631]\"" in text


def test_cisco_lines_and_return_traffic():
    _, plan = make()
    text = render_cisco(plan, FirewallOptions(cisco_return="established"))
    assert " permit tcp 10.20.0.0 0.0.0.255 10.20.1.128 0.0.0.63 eq 22" in text
    assert " permit tcp 10.20.0.0 0.0.0.255 10.20.1.128 0.0.0.63 range 8000 8099" in text
    assert " permit icmp 10.20.0.0 0.0.0.255 10.20.1.128 0.0.0.63" in text
    # Rückverkehr: Quellport ist der Dienstport; ICMP erzeugt keine Zeile
    assert " permit tcp 10.20.1.128 0.0.0.63 eq 22 10.20.0.0 0.0.0.255 established" in text
    assert " permit tcp 10.20.1.128 0.0.0.63 range 8000 8099 10.20.0.0 0.0.0.255 established" in text
    assert "eq 631 10.20.0.0" not in text.replace("0.0.0.31 eq 631", "")  # Drucker antwortet von Port 631
    assert " permit tcp 10.20.2.0 0.0.0.31 eq 631 10.20.1.192 0.0.0.63 established" in text
    assert " permit tcp 10.20.2.0 0.0.0.31 eq 9100 10.20.0.0 0.0.0.255 established" in text
    # unbeschränkt: Rückverkehr wie bisher ohne Portoperator
    assert " permit tcp 10.20.2.0 0.0.0.31 10.20.1.128 0.0.0.63 established" in text


def test_cisco_return_skipped_without_tcp_and_warned():
    groups = raw_config()["groups"]
    groups[2]["access"] = [{"to": "Drucker", "ports": ["udp/161"]}]
    plan = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": groups}))
    text = render_cisco(plan, FirewallOptions(cisco_return="established"))
    assert "Rueckverkehr Drucker -> HR" not in text
    warns = plan_warnings(plan, None, firewall="cisco", cisco_return="established")
    assert any("kein TCP" in w for w in warns)
    assert any("nur für TCP" in w for w in warns)


def test_group_rules_with_services():
    cfg, plan = make()
    groups = rule_groups(plan)
    assert len(groups) <= len(plan.subnets) * 2
    by_sigma = {(tuple(s.group for s in g.sources), tuple(t.group for t in g.targets)): g.services for g in groups}
    assert by_sigma[(("Server",), ("Drucker",))] is None
    assert by_sigma[(("Entwicklung",), ("Server",))].specs() == ("tcp/22", "tcp/443", "tcp/8000-8099", "icmp")
    text = render_nftables(plan, FirewallOptions(group_rules=True))
    assert "ip saddr { 10.20.0.0/24 } ip daddr { 10.20.1.128/26 } tcp dport { 22, 443, 8000-8099 } accept" in text
    ipt = render_iptables(plan, FirewallOptions(group_rules=True))
    assert "--match-set SUBNET_ACL_D" in ipt and "-p tcp --dport 8000:8099" in ipt
    cis = render_cisco(plan, FirewallOptions(group_rules=True))
    assert "permit tcp 10.20.0.0 0.0.0.255 object-group OG-TARGETS-" in cis and " eq 22" in cis


def test_group_rules_share_object_group_for_equal_targets():
    groups = [
        {"name": "A", "hosts": 5, "access": [{"to": "B", "ports": ["tcp/1"]}, {"to": "C", "ports": ["tcp/1"]}]},
        {"name": "D", "hosts": 5, "access": [{"to": "B", "ports": ["udp/2"]}, {"to": "C", "ports": ["udp/2"]}]},
        {"name": "B", "hosts": 5},
        {"name": "C", "hosts": 5},
    ]
    plan = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": groups}))
    text = render_cisco(plan, FirewallOptions(group_rules=True))
    assert text.count("object-group network OG-TARGETS-") == 1  # gleiche Zielmenge, zwei Dienstmengen
    assert " eq 1" in text and " eq 2" in text
    for kind in KINDS:
        assert check_roundtrip(plan, kind, FirewallOptions(group_rules=True)).ok


def test_ascii_names_and_log_options_still_valid():
    _, plan = make()
    for kind in KINDS:
        text = render_firewall(plan, kind, FirewallOptions(ascii_names=True, log_drops=True))
        assert "Ä" not in text.replace("GÄSTE", "")


# --------------------------------------------------------------------------- Rückübersetzung
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("options", OPTION_SETS)
def test_roundtrip_services(kind, options):
    _, plan = make()
    result = check_roundtrip(plan, kind, options)
    assert result.ok, result
    assert not result.missing and not result.extra and not result.service_mismatch


def test_parsed_services_match_policy():
    _, plan = make()
    nets = {s.group: s.network for s in plan.subnets}
    for kind in KINDS:
        parsed = parse_rules(render_firewall(plan, kind), kind)
        want = policy_services(plan)
        for (a, b), sigma in want.items():
            assert parsed.services[(nets[a], nets[b])] == sigma


def test_roundtrip_detects_changed_services():
    _, plan = make()
    wrong = replace(
        plan,
        subnets=tuple(
            replace(s, services=(("Server", ServiceSet.from_specs(["tcp/22"])),) + s.services[1:])
            if s.group == "Entwicklung" else s
            for s in plan.subnets
        ),
    )
    # Regeln des richtigen Plans gegen die Erwartung des falschen Plans
    from src.roundtrip import expected_services

    parsed = parse_rules(render_nftables(plan), "nftables")
    nets = {s.group: s.network for s in plan.subnets}
    assert parsed.services[(nets["Entwicklung"], nets["Server"])] != expected_services(wrong)[
        (nets["Entwicklung"], nets["Server"])
    ]


def test_roundtrip_random_plans_ipv4_ipv6():
    rng = random.Random(7)
    protos = ["tcp/22", "tcp/80-90", "tcp/443", "udp/53", "udp/5000-5010", "tcp", "udp/123"]
    for version, base, icmp in ((4, "10.0.0.0/16", "icmp"), (6, "2001:db8:abcd::/48", "icmpv6")):
        for _ in range(40):
            n = rng.randint(2, 6)
            groups = []
            for i in range(n):
                access = []
                for j in range(n):
                    if i != j and rng.random() < 0.6:
                        if rng.random() < 0.6:
                            ports = rng.sample(protos + [icmp], rng.randint(1, 4))
                            access.append({"to": f"G{j}", "ports": ports})
                        else:
                            access.append(f"G{j}")
                groups.append({"name": f"G{i}", "hosts": rng.randint(1, 80), "access": access})
            plan = plan_subnets(build_config({"base_network": base, "groups": groups}))
            assert verify_plan(plan) == []
            for kind in KINDS:
                for options in OPTION_SETS:
                    assert check_roundtrip(plan, kind, options).ok, (kind, options, groups)


def test_ipv6_rules():
    groups = v6_groups()
    groups[2]["access"] = [{"to": "Drucker", "ports": ["tcp/631", "icmpv6"]}]
    plan = plan_subnets(build_config({"base_network": "2001:db8::/32", "groups": groups}))
    ipt = render_iptables(plan)
    assert "ip6tables" in ipt and "-p ipv6-icmp -m comment" in ipt and "--dport 631" in ipt
    assert "meta l4proto ipv6-icmp" in render_nftables(plan)
    cis = render_cisco(plan)
    assert "permit icmp 2001:" in cis and "permit tcp 2001:" in cis and "eq 631" in cis
    for kind in KINDS:
        assert check_roundtrip(plan, kind).ok


def test_parser_rejects_unknown_protocols():
    with pytest.raises(PlanError, match="Protokoll"):
        parse_rules("iptables -A SUBNET_ACL -s 10.0.0.0/24 -d 10.0.1.0/24 -p gre -j ACCEPT", "iptables")
    with pytest.raises(PlanError, match="Protokoll"):
        parse_rules('ip saddr 10.0.0.0/24 ip daddr 10.0.1.0/24 meta l4proto gre accept', "nftables")
    with pytest.raises(PlanError, match="Portangabe"):
        parse_rules('ip saddr 10.0.0.0/24 ip daddr 10.0.1.0/24 tcp dport abc accept', "nftables")
    with pytest.raises(PlanError, match="nicht lesbar"):
        parse_rules("ip access-list extended X\n permit tcp 10.0.0.0 0.0.0.255 10.0.1.0 0.0.0.255 eq", "cisco")


def test_comment_text_does_not_confuse_the_parser():
    groups = [
        {"name": "x -p udp", "hosts": 5, "access": [{"to": "y", "ports": ["tcp/22"]}]},
        {"name": "y", "hosts": 5},
    ]
    plan = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": groups}))
    for kind in KINDS:
        assert check_roundtrip(plan, kind).ok


# --------------------------------------------------------------------------- Urteil
def test_verdict_with_services():
    _, plan = make()
    dev, srv, dru = "10.20.0.10", "10.20.1.130", "10.20.2.5"
    assert firewall_verdict(plan, dev, srv, service="tcp/443") == "accept"
    assert firewall_verdict(plan, dev, srv, service=("tcp", 8050)) == "accept"
    assert firewall_verdict(plan, dev, srv, service="icmp") == "accept"
    assert firewall_verdict(plan, dev, srv, service="tcp/8100") == "drop"
    assert firewall_verdict(plan, dev, srv, service="udp/443") == "drop"
    assert firewall_verdict(plan, dev, srv, service="icmpv6") == "drop"
    assert firewall_verdict(plan, dev, srv) == "accept"  # ohne Dienst: irgendeine Freigabe
    assert firewall_verdict(plan, srv, dru, service="udp/9") == "accept"  # unbeschränkt
    assert firewall_verdict(plan, srv, dev, service="tcp/22") == "drop"
    assert firewall_verdict(plan, srv, dev, state="established", service="tcp/22") == "accept"
    assert cisco_verdict(plan, "Entwicklung", dev, srv, "tcp/22") == "accept"
    assert cisco_verdict(plan, "Entwicklung", dev, srv, "tcp/23") == "drop"
    assert cisco_verdict(plan, "Entwicklung", srv, srv, "tcp/22") == "drop"
    with pytest.raises(PlanError):
        firewall_verdict(plan, dev, srv, service="gre/1")
    with pytest.raises(PlanError):
        firewall_verdict(plan, srv, dev, service="nonsense")  # auch bei verworfenem Paar geprüft


def test_verdict_matches_generated_rules_exhaustively_for_ports():
    """Satz "Default-Deny-Korrektheit mit Diensten": Urteil == Mitgliedschaft in Sigma."""
    _, plan = make()
    sigma = sigma_of(plan, "Entwicklung", "Server")
    for port in list(range(0, 130)) + [8000, 8050, 8099, 8100, 9100, 65535]:
        for proto in ("tcp", "udp"):
            expected = "accept" if sigma.contains(proto, port) else "drop"
            assert firewall_verdict(plan, "10.20.0.1", "10.20.1.129", service=(proto, port)) == expected


# --------------------------------------------------------------------------- Plan, JSON, Erweitern
def test_json_roundtrip_and_extend_keep_services():
    cfg, plan = make()
    text = render(plan, "json")
    data = json.loads(text)
    dev = next(s for s in data["subnets"] if s["group"] == "Entwicklung")
    assert dev["services"]["Server"] == ["tcp/22", "tcp/443", "tcp/8000-8099", "icmp"]
    assert "services" not in next(s for s in data["subnets"] if s["group"] == "Server")
    loaded = plan_from_json(text)
    assert [s.services for s in loaded.subnets] == [s.services for s in plan.subnets]
    ext_cfg, new = build_extension(
        {"groups": [{"name": "Neu", "hosts": 10, "access": [{"to": "Server", "ports": ["tcp/22"]}]}]},
        [s.group for s in loaded.subnets], loaded.base_network,
    )
    extended = extend_plan(loaded, new, ext_cfg)
    assert sigma_of(extended, "Neu", "Server").specs() == ("tcp/22",)
    assert sigma_of(extended, "Entwicklung", "Server").specs() == ("tcp/22", "tcp/443", "tcp/8000-8099", "icmp")
    assert verify_plan(extended) == []


def test_plan_json_rejects_bad_services():
    _, plan = make()
    data = json.loads(render(plan, "json"))
    data["subnets"][1]["services"] = ["tcp/22"]
    with pytest.raises(PlanError, match="services"):
        plan_from_json(json.dumps(data))
    data["subnets"][1]["services"] = {"Server": ["tcp/0"]}
    with pytest.raises(PlanError):
        plan_from_json(json.dumps(data))


def test_double_in_place_keeps_services():
    groups = [
        {"name": "A", "hosts": 5, "access": [{"to": "B", "ports": ["tcp/80"]}]},
        {"name": "B", "hosts": 20},  # größer: liegt zuerst, A bekommt die linke Hälfte eines /27
    ]
    plan = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": groups}))
    doubled = double_in_place(plan, "A")
    assert sigma_of(doubled, "A", "B").specs() == ("tcp/80",)


def test_csv_has_services_column_only_when_needed():
    _, plan = make()
    csv_text = render(plan, "csv")
    header, *rows = csv_text.splitlines()
    assert header.endswith(",services")
    assert len(rows) == 5  # das Feld mit Kommas wird zitiert, die Zeilenzahl bleibt
    assert '"Server:tcp/22,tcp/443,tcp/8000-8099,icmp;Drucker:tcp/631,tcp/9100"' in csv_text
    plain = plan_subnets(build_config({"base_network": "10.0.0.0/16", "groups": [{"name": "A", "hosts": 5}]}))
    assert "services" not in render(plain, "csv")
    assert "services" not in render(plain, "json")


# --------------------------------------------------------------------------- Vergleich, Prüfung
def test_services_included():
    _, plan = make()
    groups = raw_config()["groups"]
    wide = json.loads(json.dumps(groups))
    wide[1]["access"][0]["ports"].append("tcp/8443")
    wide_plan = plan_subnets(build_config({"base_network": "10.20.0.0/16", "groups": wide}))
    assert services_included(plan, wide_plan)
    assert not services_included(wide_plan, plan)
    assert services_included(plan, plan)
    unrestricted = json.loads(json.dumps(groups))
    unrestricted[1]["access"] = ["Server", "Drucker"]
    unrestricted[2]["access"] = ["Drucker"]
    open_plan = plan_subnets(build_config({"base_network": "10.20.0.0/16", "groups": unrestricted}))
    assert services_included(plan, open_plan) and not services_included(open_plan, plan)
    fewer = json.loads(json.dumps(groups))
    fewer[2]["access"] = []
    fewer_plan = plan_subnets(build_config({"base_network": "10.20.0.0/16", "groups": fewer}))
    assert services_included(fewer_plan, plan) and not services_included(plan, fewer_plan)


def test_verify_reports_inconsistent_services():
    _, plan = make()
    assert verify_plan(plan) == []
    bad = replace(
        plan,
        subnets=tuple(
            replace(s, services=s.services + (("Gäste", ServiceSet.from_specs(["tcp/1"])),
                                                ("Drucker", ServiceSet()),
                                                ("Server", ServiceSet.from_specs(["icmpv6"]))))
            if s.group == "Entwicklung" else s
            for s in plan.subnets
        ),
    )
    problems = "\n".join(verify_plan(bad))
    assert "'Gäste', das nicht in access steht" in problems
    assert "leere Dienstmenge" in problems
    assert "IPv4" in problems


# --------------------------------------------------------------------------- Kommandozeile
def test_cli_with_ports(tmp_path, capsys):
    import yaml

    path = tmp_path / "ports.yaml"
    path.write_text(yaml.safe_dump(raw_config()), encoding="utf-8")
    out = tmp_path / "rules.nft"
    code = main([str(path), "--firewall", "nftables", "--firewall-output", str(out), "--roundtrip", "--verify"])
    assert code == 0
    assert "tcp dport { 22, 443, 8000-8099 }" in out.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert "Rückübersetzung nftables: P' = P" in err and "Prüfung bestanden" in err
    code = main([str(path), "--firewall", "cisco", "--cisco-return", "established", "--warnings", "--roundtrip"])
    assert code == 0
    assert "eq 22" in capsys.readouterr().out


def test_rule_groups_tolerate_raw_plans():
    """Von Hand gebaute Pläne: Selbstbezug, unbekanntes Ziel und eine Dienstmenge gleich D."""
    _, plan = make()
    full = ServiceSet.from_specs(["tcp", "udp", "icmp"])
    raw = replace(
        plan,
        subnets=tuple(
            replace(s, access=s.access + ("Server", "Ghost"), services=s.services + (("Drucker", full),))
            if s.group == "Server" else s
            for s in plan.subnets
        ),
    )
    groups = [g for g in rule_groups(raw) if [s.group for s in g.sources] == ["Server"]]
    assert len(groups) == 1 and groups[0].services is None
    assert [t.group for t in groups[0].targets] == ["Drucker"]
    assert policy_services(raw)[("Server", "Drucker")] == ServiceSet.everything()
    clean = replace(
        raw, subnets=tuple(replace(s, access=tuple(a for a in s.access if a != "Ghost")) for s in raw.subnets)
    )
    assert render_nftables(clean).count("Server -> Drucker\"") == 1  # ohne Portbedingung


def test_ports_example_configuration_is_valid():
    from pathlib import Path

    from src.config import load_config_file

    path = Path(__file__).resolve().parent.parent / "examples" / "config.ports.example.yaml"
    plan = plan_subnets(build_config(load_config_file(path)))
    assert verify_plan(plan) == []
    assert sigma_of(plan, "HR", "Drucker").specs() == ("tcp/631",)
    for kind in KINDS:
        assert check_roundtrip(plan, kind).ok
