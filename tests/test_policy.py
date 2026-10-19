import numpy as np
import pytest

from src.models import PlanError
from src.policy import (compare_matrices, compare_policies, format_comparison, matrix_included,
                        more_general_policy, rotation_containment, subgraph_relation)
from tests.helpers import make

BASE = [
    {"name": "A", "hosts": 100, "access": ["B"]},
    {"name": "B", "hosts": 50, "access": ["C"]},
    {"name": "C", "hosts": 20},
    {"name": "D", "hosts": 10},
]


def _plan(extra=None):
    glist = [dict(g) for g in BASE]
    for name, access in (extra or {}).items():
        next(g for g in glist if g["name"] == name)["access"] = access
    return make(base="10.0.0.0/16", glist=glist)[1]


def test_lemma_componentwise_inclusion():
    a, b = _plan(), _plan({"C": ["A"]})
    c = compare_policies(a, b)
    assert c.relation == "a_in_b" and c.same_groups and c.keep == "b"
    assert more_general_policy(a, b) is b
    back = compare_policies(b, a)
    assert back.relation == "b_in_a" and back.keep == "a" and more_general_policy(b, a) is b


def test_equal_and_incomparable():
    a = _plan()
    c = compare_policies(a, _plan())
    assert c.relation == "equal" and c.keep == "a" and c.rotation_relation == "equal"
    assert more_general_policy(a, _plan()) is a
    x, y = _plan({"C": ["A"]}), _plan({"D": ["A"]})
    inc = compare_policies(x, y)
    assert inc.relation == "incomparable" and inc.keep == "both" and more_general_policy(x, y) is None


def test_different_groups_flagged():
    other = make(base="10.0.0.0/16", glist=BASE[:3])[1]
    assert compare_policies(_plan(), other).same_groups is False


def test_rotation_exact():
    z = np.array([[0, 1, 0], [0, 0, 1], [0, 0, 0]])
    rolled = np.roll(np.roll(z, 1, axis=0), 1, axis=1)
    assert not matrix_included(z, rolled) and matrix_included(z, z)
    assert rotation_containment(z, rolled) is not None
    assert rotation_containment(z, np.zeros((3, 3), dtype=int)) is None
    assert rotation_containment(np.zeros((4, 4), dtype=int), z) is None  # größer als B
    sub = np.array([[0, 1], [0, 0]])
    assert rotation_containment(sub, z) == 0
    assert matrix_included(sub, z) is False  # unterschiedliche Form


def test_matrix_validation():
    with pytest.raises(PlanError, match="quadratisch"):
        matrix_included(np.zeros((2, 3), dtype=int), np.zeros((2, 2), dtype=int))
    with pytest.raises(PlanError, match="0 und 1"):
        rotation_containment(np.full((2, 2), 2), np.zeros((2, 2), dtype=int))
    with pytest.raises(PlanError):
        subgraph_relation(np.zeros((2, 2), dtype=int), np.full((2, 2), 3))


def test_subgraph_is_a_heuristic_exact_check_is_authoritative():
    """Der Subgraph Algorithmus meldet bei echter Teilmenge nicht immer 'enthalten'."""
    rng = np.random.default_rng(3)
    missed = wrong = 0
    for _ in range(400):
        n = int(rng.integers(3, 7))
        b = (rng.random((n, n)) < 0.4).astype(int)
        a = b * (rng.random((n, n)) < 0.6)
        np.fill_diagonal(a, 0)
        np.fill_diagonal(b, 0)
        *_, exact, _, norm, agrees = compare_matrices(a, b)
        assert exact in ("equal", "a_in_b")  # a ist Teilmenge von b
        missed += not agrees
        c = (rng.random((n, n)) < 0.4).astype(int)
        np.fill_diagonal(c, 0)
        *_, exact2, _, norm2, _ = compare_matrices(a, c)
        wrong += (norm2 in ("a_in_b", "equal") and exact2 not in ("a_in_b", "equal"))
    assert missed > 0  # Heuristik: übersieht echte Enthaltensein-Fälle


def test_format_report():
    a, b = _plan(), _plan({"C": ["A"]})
    text = format_comparison(compare_policies(a, b))
    assert "A ist in B enthalten" in text and "Empfehlung: B behalten, A verwerfen" in text
    assert "Subgraph Algorithmus:" in text
    inc = format_comparison(compare_policies(_plan({"C": ["A"]}), _plan({"D": ["A"]})))
    assert "beide behalten" in inc and "unvergleichbar" in inc
    other = make(base="10.0.0.0/16", glist=BASE[:3])[1]
    assert "nein (Lemma" in format_comparison(compare_policies(_plan(), other))
    eq = format_comparison(compare_policies(_plan(), _plan()))
    assert "A behalten, B verwerfen" in eq and "gleich" in eq
    assert "B ist in A enthalten" in format_comparison(compare_policies(b, a))
