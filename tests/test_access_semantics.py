import ipaddress
import pytest

from src.access import (access_matrix, asymmetric_pairs, clean_access, plan_access_matrix,
                        policy_pairs, rule_groups)
from src.models import Group, PlanError
from src.semantics import cisco_verdict, firewall_verdict, locate
from tests.helpers import make

GLIST = [
    {"name": "Dev", "hosts": 60, "access": ["Srv", "Prn"]},
    {"name": "HR", "hosts": 20, "access": ["Prn", "Srv"]},
    {"name": "Srv", "hosts": 10, "access": ["Dev"]},
    {"name": "Prn", "hosts": 5},
]


def test_clean_access_removes_duplicates_and_selfrefs():
    g = (Group("A", 1, access=("A", "B", "B", "C")), Group("B", 1), Group("C", 1))
    cleaned, warns = clean_access(g)
    assert cleaned[0].access == ("B", "C")
    assert len(warns) == 2 and "Selbstbezug" in warns[0] and "mehrfach" in warns[1]
    assert clean_access(cleaned)[1] == ()


def test_matrix_and_pairs():
    cfg, plan = make(glist=GLIST)
    z = access_matrix(cfg.groups)
    assert z.shape == (4, 4) and z.sum() == 5 and z[0, 2] == 1 and z[3].sum() == 0
    names, z2 = plan_access_matrix(plan)
    assert set(names) == {"Dev", "HR", "Srv", "Prn"} and z2.sum() == 5
    assert policy_pairs(plan) == {("Dev", "Srv"), ("Dev", "Prn"), ("HR", "Prn"), ("HR", "Srv"), ("Srv", "Dev")}
    assert asymmetric_pairs(plan) == (("Dev", "Prn"), ("HR", "Prn"), ("HR", "Srv"))


def test_matrix_ignores_unknown_targets():
    z = access_matrix((Group("A", 1, access=("X",)),))
    assert z.sum() == 0


def test_rule_groups_theorem():
    cfg, plan = make(glist=GLIST)
    rgs = rule_groups(plan)
    # Dev und HR haben dieselbe Zielmenge {Srv, Prn}; Srv hat {Dev}
    assert len(rgs) == 2
    by_sources = {tuple(s.group for s in rg.sources): tuple(t.group for t in rg.targets) for rg in rgs}
    assert set(by_sources) == {("Dev", "HR"), ("Srv",)}
    assert "->" in rgs[0].label
    # gleiche Paarmenge wie ohne Gruppierung
    pairs = {(s.group, t.group) for rg in rgs for s in rg.sources for t in rg.targets}
    assert pairs == policy_pairs(plan)


def test_verdicts():
    cfg, plan = make(glist=GLIST)
    dev = next(s for s in plan.subnets if s.group == "Dev")
    srv = next(s for s in plan.subnets if s.group == "Srv")
    prn = next(s for s in plan.subnets if s.group == "Prn")
    a, b, c = dev.first_host, srv.first_host, prn.first_host
    assert locate(plan, a) is dev and locate(plan, "192.168.1.1") is None
    assert locate(plan, "2001:db8::1") is None
    assert firewall_verdict(plan, a, b) == "accept"
    assert firewall_verdict(plan, c, a) == "drop"
    assert firewall_verdict(plan, "8.8.8.8", a) == "drop"
    assert firewall_verdict(plan, a, a) == "drop"
    assert firewall_verdict(plan, c, a, "established") == "accept"
    with pytest.raises(PlanError):
        firewall_verdict(plan, a, b, "invalid")
    with pytest.raises(PlanError):
        firewall_verdict(plan, "keine-ip", b)
    assert cisco_verdict(plan, "Dev", a, b) == "accept"
    assert cisco_verdict(plan, "Dev", b, c) == "drop"  # gefälschte Quelle
    assert cisco_verdict(plan, "Dev", "2001:db8::1", c) == "drop"
    assert cisco_verdict(plan, "Dev", a, "8.8.8.8") == "drop"
    with pytest.raises(PlanError):
        cisco_verdict(plan, "Nope", a, b)
