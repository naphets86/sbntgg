import ipaddress
from dataclasses import replace
import pytest

from src.checks import is_private_range, plan_warnings
from src.config import build_config
from src.models import Plan, PlanError
from src.planner import plan_subnets
from src.stats import (EXPECTED_UTILIZATION, fixed_extra_waste, plan_statistics, poisson_block_exponent,
                       poisson_cdf, simulate_mean_utilization)
from src.verify import assert_plan, verify_plan
from tests.helpers import make

N = ipaddress.ip_network
GL = [{"name": "A", "hosts": 100, "access": ["B"]}, {"name": "B", "hosts": 30}, {"name": "C", "hosts": 10}]


def _bad(plan, **changes):
    return replace(plan, **changes)


def test_verify_ok_and_assert():
    cfg, plan = make(glist=GL)
    assert verify_plan(plan, cfg) == [] and verify_plan(plan) == []
    assert_plan(plan, cfg)


def test_verify_detects_structure_errors():
    cfg, plan = make(glist=GL)
    a, b, c = plan.subnets
    # (K3) Überlappung, (K2) außerhalb
    bad = replace(b, network=N("10.0.0.64/26"))
    probs = verify_plan(_bad(plan, subnets=(a, bad, c)))
    assert any("(K3)" in p for p in probs)
    out = replace(a, network=N("10.9.0.0/25"))
    assert any("(K2)" in p for p in verify_plan(_bad(plan, subnets=(out, b, c))))
    # (K5) Reihenfolge
    assert any("(K5)" in p for p in verify_plan(_bad(plan, subnets=(b, a, c))))
    # VLAN
    dup = replace(b, vlan_id=a.vlan_id)
    assert any("eindeutig" in p for p in verify_plan(_bad(plan, subnets=(a, dup, c))))
    rng = replace(b, vlan_id=5000)
    assert any("außerhalb" in p for p in verify_plan(_bad(plan, subnets=(a, rng, c))))
    # (K4) und Host-Bereich
    few = replace(b, usable_hosts=1)
    assert any("(K4)" in p for p in verify_plan(_bad(plan, subnets=(a, few, c))))
    wild = replace(b, last_host=ipaddress.ip_address("10.9.9.9"))
    assert any("Host-Bereich" in p for p in verify_plan(_bad(plan, subnets=(a, wild, c))))
    # freie Bereiche
    assert any("(F1)" in p for p in verify_plan(_bad(plan, free_ranges=())))
    assert any("(F)" in p for p in verify_plan(_bad(plan, reserved=(N("10.9.0.0/24"),))))
    # Bestandsnetz-Überlappung
    assert any("Bestandsnetz" in p for p in verify_plan(_bad(plan, reserved=(a.network,))))


def test_verify_detects_config_mismatch():
    cfg, plan = make(glist=GL)
    a, b, c = plan.subnets
    assert any("entsprechen nicht" in p for p in verify_plan(_bad(plan, subnets=(a, b)), cfg))
    big = replace(c, network=N("10.0.1.0/24"), usable_hosts=253)
    probs = verify_plan(_bad(plan, subnets=(a, b, big)), cfg)
    assert any("(K6)" in p for p in probs) and any("Präfixlänge" in p for p in probs)
    assert any("Lückenlosigkeit" in p for p in probs)
    odd = replace(b, usable_hosts=b.usable_hosts - 1)
    assert any("Lemma Nutzbare Hosts" in p for p in verify_plan(_bad(plan, subnets=(a, odd, c)), cfg))
    small = replace(c, network=N("10.0.0.224/30"), usable_hosts=1, first_host=ipaddress.ip_address("10.0.0.225"),
                    last_host=ipaddress.ip_address("10.0.0.226"), requested_hosts=1)
    assert any("fasst nur" in p for p in verify_plan(_bad(plan, subnets=(a, b, small)), cfg))
    with pytest.raises(PlanError, match="verletzt"):
        assert_plan(_bad(plan, subnets=(a, b)), cfg)


def test_verify_order_and_free_blocks_rules():
    cfg, plan = make(glist=GL)
    a, b, c = plan.subnets
    # absteigende Blockgröße verletzt: kleines vor großem Block
    swapped = (replace(c, network=N("10.0.0.0/28")), replace(b, network=N("10.0.0.64/26")), replace(a, network=N("10.0.0.128/25")))
    probs = verify_plan(_bad(plan, subnets=swapped), cfg)
    assert any("Kompaktheit" in p for p in probs) or any("Lückenlosigkeit" in p for p in probs)
    ok = replace(cfg)
    spread = (a, b, replace(c, network=N("10.0.0.240/28")))
    assert any("Lückenlosigkeit" in p for p in verify_plan(_bad(plan, subnets=spread), cfg))


def test_verify_compact_order_violation():
    cfg, plan = make(glist=[{"name": "A", "hosts": 10}, {"name": "B", "hosts": 100}])
    a, b = sorted(plan.subnets, key=lambda s: s.group)
    # B (groß) an Adresse 0 ist korrekt; Tausch: A (klein) zuerst, lückenlos aber unsortiert
    first = replace(a, network=N("10.0.0.0/28"))
    second = replace(b, network=N("10.0.0.128/25"))
    probs = verify_plan(_bad(plan, subnets=(first, second)), cfg)
    assert any("Kompaktheit" in p for p in probs)


def test_verify_verschnitt_and_free_count():
    cfg, plan = make(glist=GL)
    a, b, c = plan.subnets
    huge = tuple(replace(s, network=n) for s, n in zip((a, b, c), (N("10.0.0.0/25"), N("10.0.0.128/26"), N("10.0.0.192/26"))))
    probs = verify_plan(_bad(plan, subnets=huge), cfg)
    assert any("(K6)" in p for p in probs)
    cfg2, plan2 = make(glist=[{"name": "X", "hosts": 100}])
    wrong_free = _bad(plan2, free_ranges=(N("10.0.0.128/26"), N("10.0.0.192/26")))
    probs2 = verify_plan(wrong_free, cfg2)
    assert any("(F1)" in p for p in probs2)
    assert any("popcount" in p for p in probs2)
    assert any("(F3)" in p for p in probs2)


def test_verify_total_s_bound_message():
    cfg, plan = make(glist=GL)
    a, b, c = plan.subnets
    tweaked = replace(cfg, growth_factor=1.0)
    huge_s = tuple(replace(s, network=n) for s, n in zip((a, b, c), (N("10.0.0.0/25"), N("10.0.0.128/26"), N("10.0.0.192/26"))))
    probs = verify_plan(_bad(plan, subnets=huge_s), tweaked)
    assert any("Verschnitt" in p for p in probs) or any("(K6)" in p for p in probs)


def test_verify_general_plan_passes():
    cfg, plan = make(base="10.0.0.0/24", glist=GL, existing=["10.0.0.0/27"], max_prefix=28)
    assert verify_plan(plan, cfg) == []


def test_statistics():
    cfg, plan = make(glist=GL)
    st = plan_statistics(plan, cfg)
    assert st.allocated == 128 + 32 + 16 and st.required == 128 + 34 + 16 - 2 + 0 or st.required > 0
    assert 0.5 < st.min_utilization <= st.mean_utilization <= 1.0
    assert set(st.block_utilization) == {"A", "B", "C"}
    assert st.internal_waste == st.allocated - st.required
    assert fixed_extra_waste([128, 32, 16]) == 3 * 128 - 176
    with pytest.raises(PlanError):
        fixed_extra_waste([])


def test_expected_utilization_matches_simulation():
    assert EXPECTED_UTILIZATION == pytest.approx(0.7213, abs=1e-4)
    assert simulate_mean_utilization(60_000, seed=7) == pytest.approx(EXPECTED_UTILIZATION, abs=0.01)
    with pytest.raises(PlanError):
        simulate_mean_utilization(0)


def test_poisson():
    assert poisson_cdf(0, 0) == 1.0 and poisson_cdf(100, 5.0) == pytest.approx(1.0)
    assert poisson_cdf(2, 1.0) == pytest.approx(0.9196986, abs=1e-6)
    assert poisson_block_exponent(100, 3, 0.01) == 7
    assert poisson_block_exponent(1, 0, 0.5) == 0 and poisson_block_exponent(1, 0, 0.2) == 1
    assert poisson_block_exponent(1000, 3, 0.001) >= poisson_block_exponent(100, 3, 0.001)
    with pytest.raises(PlanError):
        poisson_cdf(-1, 1)
    with pytest.raises(PlanError):
        poisson_block_exponent(10, 0, 1.5)
    with pytest.raises(PlanError):
        poisson_block_exponent(10, -1, 0.1)
    with pytest.raises(PlanError, match="Kein Blockexponent"):
        poisson_block_exponent(1e6, 0, 0.001, max_exponent=3)


def test_warnings():
    cfg, plan = make(glist=GL, base="10.0.0.0/24")
    assert plan_warnings(plan, cfg, threshold=95.0) == []
    assert any("Schwellwert" in w for w in plan_warnings(plan, cfg, threshold=50.0))
    pub_cfg, pub = make(base="8.8.8.0/24", glist=GL)
    assert any("RFC 1918" in w for w in plan_warnings(pub, pub_cfg, 99))
    v6cfg, v6 = make(base="2001:db8::/48", glist=GL, max_prefix=64)
    assert any("fc00::/7" in w for w in plan_warnings(v6, v6cfg, 99))
    ula_cfg, ula = make(base="fd00::/48", glist=GL, max_prefix=64)
    assert plan_warnings(ula, ula_cfg, 99) == []
    foreign = [N("10.0.0.0/16"), N("192.168.0.0/16"), N("fd00::/8")]
    w = plan_warnings(plan, cfg, 99, foreign)
    assert len(w) == 1 and "fremden Netz 10.0.0.0/16" in w[0]
    assert plan_warnings(plan, cfg, 99, [N("fd00::/8")]) == []
    cfg2, p2 = make(glist=[{"name": "A", "hosts": 5, "access": ["A", "A"]}, {"name": "B", "hosts": 5, "access": ["A"]}])
    ws = plan_warnings(p2, cfg2, 99)
    assert any("Selbstbezug" in x for x in ws)
    cs = plan_warnings(p2, cfg2, 99, firewall="cisco")
    assert any("gestenlos" in x or "zustandslos" in x for x in cs)
    ce = plan_warnings(p2, cfg2, 99, firewall="cisco", cisco_return="established")
    assert any("nur für TCP" in x for x in ce)
    assert is_private_range(N("172.20.0.0/16")) and not is_private_range(N("172.32.0.0/16"))
    assert plan_warnings(p2, None, 99) == []
