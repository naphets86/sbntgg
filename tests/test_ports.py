"""Tests zu Kapitel "Erweiterung um Protokolle und Ports": Mathematik in ``src/ports.py``.

Jede Aussage wird mit festem Startwert gegen eine Prüfung jedes einzelnen Ports verglichen,
so wie es das Kapitel für das eigenständige Prüfskript beschreibt.
"""
import ipaddress
import random

import pytest

from src import ports as P
from src.models import PlanError

RNG_SEED = 20261020
FULL = (0, 65535)


def rand_intervals(rng, count, span=65535, max_len=3000):
    out = []
    for _ in range(count):
        low = rng.randint(0, span)
        out.append((low, min(span, low + rng.randint(0, max_len))))
    return out


def brute(intervals):
    return {q for lo, hi in intervals for q in range(lo, hi + 1)}


# --------------------------------------------------------------------------- Intervalle
@pytest.mark.parametrize("bad", [(-1, 3), (3, 2), (0, 65536), (1.5, 2), (True, 2), ("1", 2)])
def test_check_interval_rejects(bad):
    with pytest.raises(PlanError):
        P.check_interval(*bad)


def test_normalize_merges_adjacent_and_overlapping():
    assert P.normalize([(5, 9), (1, 3), (4, 4), (20, 30), (25, 26)]) == ((1, 9), (20, 30))
    assert P.normalize([]) == ()
    assert P.normalize([(0, 65535), (10, 20)]) == (FULL,)


def test_normal_form_is_unique_runs_of_the_set():
    """Satz "Normalform": die Liste der Läufe, gleich für jede Darstellung derselben Menge."""
    rng = random.Random(RNG_SEED)
    for _ in range(300):
        raw = rand_intervals(rng, rng.randint(0, 12))
        norm = P.normalize(raw)
        assert brute(norm) == brute(raw)
        for (a, b), (c, d) in zip(norm, norm[1:]):
            assert c >= b + 2
        shuffled = raw[:]
        rng.shuffle(shuffled)
        assert P.normalize(shuffled) == norm
        assert P.normalize(norm) == norm
        # jedes Intervall ist ein maximaler Lauf
        ports = brute(norm)
        for lo, hi in norm:
            assert (lo == 0 or lo - 1 not in ports) and (hi == 65535 or hi + 1 not in ports)


def test_from_ports_and_bound_is_sharp():
    assert P.from_ports([3, 1, 2, 9]) == ((1, 3), (9, 9))
    evens = P.from_ports(range(0, 65536, 2))
    assert len(evens) == P.MAX_INTERVALS == 32768
    rng = random.Random(RNG_SEED)
    for _ in range(100):
        ports = rng.sample(range(65536), rng.randint(0, 400))
        norm = P.from_ports(ports)
        assert len(norm) <= P.MAX_INTERVALS
        assert P.ports_of(norm) == frozenset(ports)


def test_size_contains_union():
    norm = P.normalize([(10, 20), (30, 30)])
    assert P.size([(10, 20), (15, 25), (30, 30)]) == 17
    assert [P.contains(norm, q) for q in (9, 10, 20, 21, 30, 31)] == [False, True, True, False, True, False]
    assert not P.contains((), 5)
    assert P.union([(1, 2)], [(3, 4)]) == ((1, 4),)
    for bad in (-1, 65536, True, "1"):
        with pytest.raises(PlanError):
            P.contains(norm, bad)


def test_contains_matches_set_membership():
    rng = random.Random(RNG_SEED + 1)
    for _ in range(100):
        norm = P.normalize(rand_intervals(rng, rng.randint(0, 8)))
        ports = brute(norm)
        for q in [rng.randint(0, 65535) for _ in range(40)] + [0, 65535]:
            assert P.contains(norm, q) == (q in ports)


# --------------------------------------------------------------------------- Lücken, Überlappung
def test_gaps_complement_and_count_bound():
    """Satz "Lücken": die nicht abgedeckten Ports, höchstens m + 1 Zwischenräume."""
    rng = random.Random(RNG_SEED + 2)
    for _ in range(300):
        raw = rand_intervals(rng, rng.randint(0, 10), max_len=20000)
        gap = P.gaps(raw)
        assert brute(gap) == set(range(65536)) - brute(raw)
        assert len(gap) <= len(raw) + 1
        assert gap == P.normalize(gap)
        assert P.gaps(gap) == P.normalize(raw)  # Komplement des Komplements
    assert P.gaps([]) == (FULL,)
    assert P.gaps([FULL]) == ()
    assert P.gaps([(1, 65534)]) == ((0, 0), (65535, 65535))


def test_is_complete_corollary():
    assert not P.is_complete([])
    assert P.is_complete([(0, 100), (101, 65535)])
    assert not P.is_complete([(0, 100), (102, 65535)])
    assert not P.is_complete([(1, 65535)])
    assert not P.is_complete([(0, 65534)])
    assert P.is_complete([(0, 40000), (10, 65535), (3, 4)])


def test_overlapping_matches_pairwise_check():
    """Korollar "Überlappung": überlappungsfrei genau dann, wenn l_{k+1} > r_k."""
    rng = random.Random(RNG_SEED + 3)
    for _ in range(400):
        raw = rand_intervals(rng, rng.randint(0, 8), max_len=4000)
        pairwise = any(
            a[0] <= b[1] and b[0] <= a[1] for i, a in enumerate(raw) for b in raw[i + 1 :]
        )
        found = P.overlapping(raw)
        assert bool(found) == pairwise
        for first, second in found:
            assert first[0] <= second[0] <= first[1]
    assert P.overlapping([(1, 5), (6, 9)]) == ()
    assert P.overlapping([(1, 5), (5, 9)]) == (((1, 5), (5, 9)),)
    assert P.overlapping([(1, 100), (2, 3), (50, 60)]) == (((1, 100), (2, 3)), ((1, 100), (50, 60)))


def test_is_subset_matches_sets():
    """Satz "Teilmengenprüfung" mit zwei Zeigern."""
    rng = random.Random(RNG_SEED + 4)
    hits = 0
    for _ in range(600):
        b = rand_intervals(rng, rng.randint(0, 6), max_len=9000)
        if rng.random() < 0.5 and b:  # oft eine echte Teilmenge erzeugen
            a = []
            for lo, hi in b:
                x = rng.randint(lo, hi)
                a.append((x, rng.randint(x, hi)))
        else:
            a = rand_intervals(rng, rng.randint(0, 4), max_len=9000)
        expected = brute(a) <= brute(b)
        hits += expected
        assert P.is_subset(a, b) == expected
        assert P.is_subset(b, a) == (brute(b) <= brute(a))
    assert hits > 50
    assert P.is_subset([], [])
    assert P.is_subset([], [(1, 2)])
    assert not P.is_subset([(1, 2)], [])
    assert not P.is_subset([(1, 10)], [(1, 4), (6, 10)])  # eine Lücke genügt
    assert P.is_subset([(1, 10)], [(1, 4), (5, 10)])  # benachbart: Normalform verschmilzt


# --------------------------------------------------------------------------- Portblöcke
def test_port_block_properties():
    block = P.PortBlock(8064, 11)
    assert (block.size, block.last, block.mask) == (32, 8095, 0xFFE0)
    assert (8064 & block.mask) == 8064 and (8095 & block.mask) == 8064 and (8096 & block.mask) != 8064
    assert P.PortBlock(0, 0).size == 65536 and P.PortBlock(0, 0).mask == 0


def test_chapter_example_decompositions():
    """Beispiel "Typische Portbereiche" des Kapitels."""

    def fmt(lo, hi):
        return [f"{b.start}/{b.prefix}" for b in P.interval_blocks(lo, hi)]

    assert fmt(0, 1023) == ["0/6"]
    assert fmt(1024, 65535) == ["1024/6", "2048/5", "4096/4", "8192/3", "16384/2", "32768/1"]
    assert fmt(49152, 65535) == ["49152/2"]
    assert fmt(32768, 60999) == [
        "32768/2", "49152/3", "57344/5", "59392/6", "60416/7", "60928/10", "60992/13"
    ]
    assert fmt(8000, 8099) == ["8000/10", "8064/11", "8096/14"]
    assert fmt(0, 65535) == ["0/0"]
    assert fmt(22, 22) == ["22/16"]


def test_blocks_cover_exactly_aligned_and_minimal():
    """Satz "Zerlegung eines Intervalls": exakt, ausgerichtet, minimal, höchstens 30."""
    rng = random.Random(RNG_SEED + 5)
    cases = [(1, 65534), (0, 0), (65535, 65535), (0, 65534), (1, 65535)]
    cases += [tuple(sorted((rng.randint(0, 65535), rng.randint(0, 65535)))) for _ in range(800)]
    for lo, hi in cases:
        blocks = P.interval_blocks(lo, hi)
        assert len(blocks) <= P.MAX_BLOCKS_PER_INTERVAL == 30
        covered = []
        for b in blocks:
            assert b.start % b.size == 0  # ausgerichtet
            covered.extend(range(b.start, b.last + 1))
        assert covered == list(range(lo, hi + 1))  # lückenlos, disjunkt
        # gleiche Anzahl wie die minimale CIDR-Zerlegung der Adressen
        summary = list(
            ipaddress.summarize_address_range(ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))
        )
        assert len(blocks) == len(summary)
    assert len(P.interval_blocks(1, 65534)) == 30  # scharf


def test_upper_bound_exhaustive_small_widths():
    """Die Schranke 2w-2 ist für kleine Breiten genau erreicht; hier mit dem Hilfsalgorithmus."""

    def count(lo, hi, width):
        n = 0
        cur = lo
        while cur <= hi:
            j = width if cur == 0 else (cur & -cur).bit_length() - 1
            while cur + (1 << j) - 1 > hi:
                j -= 1
            n += 1
            cur += 1 << j
        return n

    for width in range(2, 9):
        top = (1 << width) - 1
        worst = max(count(lo, hi, width) for lo in range(top + 1) for hi in range(lo, top + 1))
        assert worst == 2 * width - 2


def test_list_blocks_uses_normal_form():
    assert [(b.start, b.prefix) for b in P.list_blocks([(8000, 8050), (8051, 8099)])] == [
        (8000, 10), (8064, 11), (8096, 14)
    ]
    assert P.list_blocks([]) == ()


# --------------------------------------------------------------------------- Dienste
@pytest.mark.parametrize(
    "spec,expected",
    [
        ("tcp/22", ("tcp", (22, 22))),
        (" TCP / 8000 - 8099 ", ("tcp", (8000, 8099))),
        ("udp", ("udp", FULL)),
        ("icmp", ("icmp", None)),
        ("icmpv6", ("icmpv6", None)),
    ],
)
def test_parse_service_entry(spec, expected):
    assert P.parse_service_entry(spec) == expected


@pytest.mark.parametrize(
    "bad", [443, None, "http/80", "tcp/0", "tcp/0-10", "tcp/x", "tcp/70000", "tcp/9-3", "icmp/3", "tcp/", "/22"]
)
def test_parse_service_entry_rejects(bad):
    with pytest.raises(PlanError):
        P.parse_service_entry(bad)


def test_parse_services_and_warnings():
    sigma, warns = P.parse_services(["tcp/22", "tcp/443", "tcp/8000-8099", "udp/53", "icmp"])
    assert sigma.specs() == ("tcp/22", "tcp/443", "tcp/8000-8099", "udp/53", "icmp")
    assert warns == ()
    sigma, warns = P.parse_services(["tcp/20-30", "tcp/25", "tcp/25", "icmp", "icmp"], "A -> B")
    assert sigma.specs() == ("tcp/20-30", "icmp")
    assert any("tcp/20-30 und tcp/25 überlappen" in w and w.startswith("A -> B: ") for w in warns)
    assert any("icmp steht mehrfach" in w for w in warns)
    for bad in ("tcp/22", [], None, 5):
        with pytest.raises(PlanError):
            P.parse_services(bad)


def test_service_set_canonical_and_equal():
    a = P.ServiceSet((("tcp", ((1, 5), (6, 9))), ("udp", ())))
    b = P.ServiceSet((("tcp", ((1, 9),)),))
    assert a == b and hash(a) == hash(b)
    assert a.ports == (("tcp", ((1, 9),)),)
    assert P.ServiceSet().is_empty and not a.is_empty
    assert str(P.ServiceSet.from_specs(["udp", "tcp/80", "icmp"])) == "tcp/80,udp,icmp"
    with pytest.raises(PlanError):
        P.ServiceSet((("sctp", ((1, 2),)),))
    with pytest.raises(PlanError):
        P.ServiceSet(others=frozenset({"gre"}))


def test_service_set_contains_union_subset():
    sigma = P.ServiceSet.from_specs(["tcp/22", "tcp/8000-8099", "icmp"])
    assert sigma.contains("tcp", 22) and sigma.contains("tcp", 8050) and not sigma.contains("tcp", 23)
    assert not sigma.contains("udp", 22)
    assert sigma.contains("icmp") and not sigma.contains("icmpv6")
    for args in (("tcp",), ("gre", 1)):
        with pytest.raises(PlanError):
            sigma.contains(*args)
    other = P.ServiceSet.from_specs(["tcp/23", "udp/53"])
    both = sigma.union(other)
    assert both.specs() == ("tcp/22-23", "tcp/8000-8099", "udp/53", "icmp")
    assert sigma.issubset(both) and other.issubset(both) and not both.issubset(sigma)
    assert P.ServiceSet().issubset(sigma)
    assert not P.ServiceSet.from_specs(["icmp"]).issubset(P.ServiceSet.from_specs(["tcp"]))


def test_service_set_random_union_subset_against_ports():
    rng = random.Random(RNG_SEED + 6)
    for _ in range(200):
        def rand_set():
            return P.ServiceSet(
                tuple((p, tuple(rand_intervals(rng, rng.randint(0, 4), max_len=500))) for p in ("tcp", "udp")),
                frozenset(x for x in ("icmp",) if rng.random() < 0.5),
            )

        a, b = rand_set(), rand_set()
        u = a.union(b)
        for proto in ("tcp", "udp"):
            assert brute(u.intervals(proto)) == brute(a.intervals(proto)) | brute(b.intervals(proto))
        expected = all(brute(a.intervals(p)) <= brute(b.intervals(p)) for p in ("tcp", "udp")) and (
            a.others <= b.others
        )
        assert a.issubset(b) == expected


def test_everything_and_covers_all():
    full = P.ServiceSet.everything()
    assert full.covers_all(4) and full.covers_all(6)
    assert P.ServiceSet.from_specs(["tcp", "udp", "icmp"]).covers_all(4)
    assert not P.ServiceSet.from_specs(["tcp", "udp", "icmp"]).covers_all(6)
    assert not P.ServiceSet.from_specs(["tcp", "udp"]).covers_all(4)
    assert not P.ServiceSet.from_specs(["tcp/1-65535", "udp", "icmp"]).covers_all(4)
    assert full.specs() == ("tcp", "udp", "icmp", "icmpv6")


def test_validate_version():
    P.ServiceSet.from_specs(["icmp"]).validate_version(4)
    P.ServiceSet.from_specs(["icmpv6"]).validate_version(6)
    with pytest.raises(PlanError, match="IPv6"):
        P.ServiceSet.from_specs(["icmp"]).validate_version(6, "A -> B")
    with pytest.raises(PlanError, match="IPv4"):
        P.ServiceSet.from_specs(["icmpv6"]).validate_version(4)


def test_parse_service_concrete():
    assert P.parse_service("tcp/443") == ("tcp", 443)
    assert P.parse_service(("UDP", 0)) == ("udp", 0)
    assert P.parse_service("icmp") == ("icmp", None)
    assert P.parse_service(("icmpv6", None)) == ("icmpv6", None)
    for bad in ("tcp", "tcp/x", "tcp/70000", "icmp/3", "gre/1", 5, ("tcp",), ("tcp", 1, 2), ("icmp", 3)):
        with pytest.raises(PlanError):
            P.parse_service(bad)
