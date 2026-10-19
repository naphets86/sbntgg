import ipaddress
from fractions import Fraction
from decimal import Decimal
import itertools
import pytest

from src.exact import ceil_product, exact_ceil, to_fraction
from src.blocks import (block_size_for, can_extend, check_occupied, free_ranges_in_pool,
                        maximal_free_blocks, pack, packable, parent_block)
from src.models import PlanError

N = ipaddress.ip_network


def test_to_fraction_and_ceil():
    assert to_fraction(1.1) == Fraction(11, 10)
    assert to_fraction(2) == 2 and to_fraction("5/4") == Fraction(5, 4) and to_fraction(Decimal("1.25")) == Fraction(5, 4)
    assert ceil_product(100, 1.1) == 110
    assert ceil_product(3, 1.25) == 4 and ceil_product(4, 1.25) == 5
    assert exact_ceil(Fraction(-3, 2)) == -1
    assert ceil_product(10**9, 1.0000000001) == 10**9 + 1  # float-Rundung würde 10**9 liefern


def test_to_fraction_rejects():
    with pytest.raises(TypeError):
        to_fraction(True)
    with pytest.raises(ValueError):
        to_fraction(float("nan"))
    with pytest.raises(ValueError):
        to_fraction(float("inf"))


def test_free_ranges_gaps():
    pool = N("10.0.0.0/24")
    free = free_ranges_in_pool(pool, [N("10.0.0.64/26")])
    assert free == (N("10.0.0.0/26"), N("10.0.0.128/25"))
    assert free_ranges_in_pool(pool, [pool]) == ()
    assert free_ranges_in_pool(pool, []) == (pool,)


def test_check_occupied_errors():
    pool = N("10.0.0.0/24")
    with pytest.raises(PlanError, match="keinem Pool"):
        check_occupied([pool], [N("10.1.0.0/24")])
    with pytest.raises(PlanError, match="überschneiden"):
        check_occupied([pool], [N("10.0.0.0/25"), N("10.0.0.0/26")])
    with pytest.raises(PlanError, match="Pools"):
        check_occupied([pool, N("10.0.0.0/25")], [])
    with pytest.raises(PlanError, match="mischen"):
        check_occupied([pool], [N("2001:db8::/64")])


def test_maximal_free_blocks_multi_pool():
    pools = [N("10.0.1.0/24"), N("10.0.0.0/24")]
    free = maximal_free_blocks(pools, [N("10.0.0.0/25")])
    assert free == (N("10.0.0.128/25"), N("10.0.1.0/24"))


def test_packable_and_pack():
    free = [N("10.0.0.128/25"), N("10.0.1.0/26")]
    assert packable(free, [128, 64])
    assert not packable(free, [128, 128])
    placed = pack(free, [("a", 32), ("b", 128), ("c", 16)])
    assert placed["b"] == N("10.0.0.128/25")
    assert placed["a"] == N("10.0.1.0/27")
    assert placed["c"] == N("10.0.1.32/28")
    with pytest.raises(PlanError, match="Platzmangel"):
        pack(free, [("a", 256)])
    with pytest.raises(PlanError, match="Zweierpotenz"):
        packable(free, [3])
    assert can_extend(free, [64]) is True


def test_packability_theorem_bruteforce():
    """Satz Packbarkeit: Bedingung (*) gilt genau dann, wenn eine Zuteilung existiert."""
    pool = N("10.0.0.0/28")  # 16 Adressen
    sizes_all = [1, 2, 4, 8]
    blocks_all = list(pool.subnets(new_prefix=30))  # 4 Blöcke zu je 4
    for mask in range(1 << len(blocks_all)):
        occupied = [b for i, b in enumerate(blocks_all) if mask >> i & 1]
        free = maximal_free_blocks([pool], occupied)
        for combo in itertools.chain.from_iterable(itertools.combinations_with_replacement(sizes_all, k) for k in range(0, 4)):
            ok = packable(free, list(combo))
            try:
                res = pack(free, [(str(i), s) for i, s in enumerate(combo)])
                nets = list(res.values())
                assert all(any(n.subnet_of(f) for f in free) for n in nets)
                assert not any(a.overlaps(b) for a, b in itertools.combinations(nets, 2))
                got = True
            except PlanError:
                got = False
            assert got == ok


def test_block_size_and_parent():
    assert block_size_for(1) == 1 and block_size_for(5) == 8 and block_size_for(64) == 64
    with pytest.raises(PlanError):
        block_size_for(0)
    assert parent_block(N("10.0.0.0/25")) == N("10.0.0.0/24")
    assert parent_block(N("0.0.0.0/0")) is None
