"""Richtlinienvergleich über den Zugriffsgraphen (Abschnitt "Verbindung zum Subgraph Algorithmus").

Die Zugriffsmatrix Z ist die Adjazenzmatrix des Zugriffsgraphen G_Z. Zwei Richtlinien über
denselben Subnetzen vergleicht Lemma "Richtlinienvergleich bei gleichen Subnetzen" exakt:
P' ⊆ P genau dann, wenn Z' <= Z komponentenweise. Beschreiben zwei Konfigurationen dieselbe
Struktur in zyklisch verschobener Gruppenreihenfolge, kommt der Subgraph Algorithmus
(Abhängigkeit ``subgraph``, ``pip install`` über die pyproject.toml) zum Einsatz.

Sicherheitshinweis: Der Algorithmus entscheidet über Signaturen von Spalten und liefert damit
eine *Heuristik*; sie kann eine enthaltene Richtlinie übersehen oder eine nicht enthaltene
melden. Verbindlich für Entscheidungen, welche Richtlinie verworfen werden darf, ist deshalb
immer die exakte Prüfung (``relation`` beziehungsweise ``rotation_relation``). Das Ergebnis des
Subgraph Algorithmus steht gesondert in ``subgraph_relation`` und wird gegen die exakte
Prüfung abgeglichen (``subgraph_agrees``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

from subgraph import Subgraph  # Dependency aus der pyproject.toml (https://github.com/naphets86/subgraph)

from .access import plan_access_matrix, policy_pairs
from .models import Plan, PlanError

RELATIONS = ("equal", "a_in_b", "b_in_a", "incomparable")
_DECISIONS = {
    "keep_B": "a_in_b",
    "keep_A": "b_in_a",
    "equal_keep_A": "equal",
    "equal_keep_B": "equal",
    "equal": "equal",
    "keep_both": "incomparable",
}


@dataclass(frozen=True)
class PolicyComparison:
    relation: str  # exakt, über Gruppennamen: A ⊆ B ("a_in_b"), B ⊆ A, gleich oder unvergleichbar
    same_groups: bool  # beide Richtlinien nennen dieselben Gruppen (Voraussetzung des Lemmas)
    rotation_a_in_b: Optional[int]  # Startposition, ab der Z_A zyklisch in Z_B enthalten ist
    rotation_b_in_a: Optional[int]
    rotation_relation: str  # exakte Relation bis auf zyklische Verschiebung
    subgraph_decision: str  # Rohentscheidung des Subgraph Algorithmus
    subgraph_relation: str  # normalisiert auf RELATIONS
    subgraph_agrees: bool  # Heuristik stimmt mit der exakten Rotationsprüfung überein
    keep: str  # "a", "b" oder "both": die allgemeinere (enthaltende) Richtlinie bleibt


def _relation(a_in_b: bool, b_in_a: bool) -> str:
    if a_in_b and b_in_a:
        return "equal"
    if a_in_b:
        return "a_in_b"
    if b_in_a:
        return "b_in_a"
    return "incomparable"


def _check_matrix(z: np.ndarray, label: str) -> None:
    if z.ndim != 2 or z.shape[0] != z.shape[1]:
        raise PlanError(f"Matrix {label} muss quadratisch sein, erhalten Form {z.shape}")
    if not np.isin(z, (0, 1)).all():
        raise PlanError(f"Matrix {label} darf nur 0 und 1 enthalten")


def matrix_included(a: np.ndarray, b: np.ndarray) -> bool:
    """Z_A <= Z_B komponentenweise bei gleicher Beschriftung (Lemma, O(n²))."""
    _check_matrix(a, "A")
    _check_matrix(b, "B")
    if a.shape != b.shape:
        return False
    return bool(np.all(a <= b))


def rotation_containment(a: np.ndarray, b: np.ndarray) -> Optional[int]:
    """Kleinste Startposition s, sodass Z_A im zyklischen Fenster von Z_B ab s enthalten ist.

    Fenster: die Indizes s, s+1, ..., s+n_A-1 (modulo n_B) von Zeilen *und* Spalten.
    Exakte Entsprechung der Rotationssuche des Subgraph Algorithmus, aber mit echter
    Teilmengenprüfung der Kanten (O(n_B · n_A²)). ``None``, wenn es keine Position gibt.
    """
    _check_matrix(a, "A")
    _check_matrix(b, "B")
    n_a, n_b = a.shape[0], b.shape[0]
    if n_a > n_b:
        return None
    for start in range(n_b):
        idx = [(start + k) % n_b for k in range(n_a)]
        if bool(np.all(a <= b[np.ix_(idx, idx)])):
            return start
    return None


def subgraph_relation(a: np.ndarray, b: np.ndarray) -> Tuple[str, str]:
    """Rohentscheidung und normalisierte Relation des Subgraph Algorithmus."""
    _check_matrix(a, "A")
    _check_matrix(b, "B")
    decision, _ = Subgraph().compare_graphs(a, b)
    return decision, _DECISIONS[decision]


def compare_matrices(a: np.ndarray, b: np.ndarray) -> Tuple[Optional[int], Optional[int], str, str, str, bool]:
    """Vergleicht zwei Zugriffsmatrizen exakt (Rotation) und mit dem Subgraph Algorithmus."""
    rot_ab = rotation_containment(a, b)
    rot_ba = rotation_containment(b, a)
    exact = _relation(rot_ab is not None, rot_ba is not None)
    decision, normalized = subgraph_relation(a, b)
    return rot_ab, rot_ba, exact, decision, normalized, normalized == exact


def compare_policies(plan_a: Plan, plan_b: Plan) -> PolicyComparison:
    """Vergleicht die Zugriffsrichtlinien zweier Pläne."""
    pairs_a, pairs_b = policy_pairs(plan_a), policy_pairs(plan_b)
    names_a = {s.group for s in plan_a.subnets}
    names_b = {s.group for s in plan_b.subnets}
    relation = _relation(pairs_a <= pairs_b, pairs_b <= pairs_a)
    _, za = plan_access_matrix(plan_a)
    _, zb = plan_access_matrix(plan_b)
    rot_ab, rot_ba, rot_rel, decision, normalized, agrees = compare_matrices(za, zb)
    keep = {"equal": "a", "a_in_b": "b", "b_in_a": "a", "incomparable": "both"}[relation]
    return PolicyComparison(
        relation, names_a == names_b, rot_ab, rot_ba, rot_rel, decision, normalized, agrees, keep
    )


def more_general_policy(plan_a: Plan, plan_b: Plan) -> Optional[Plan]:
    """Die Richtlinie, die die andere enthält (die allgemeinere), bei Gleichheit ``plan_a``.

    Bei unvergleichbaren Richtlinien ``None``: beide müssen behalten werden.
    """
    keep = compare_policies(plan_a, plan_b).keep
    return {"a": plan_a, "b": plan_b, "both": None}[keep]


def format_comparison(c: PolicyComparison) -> str:
    """Lesbarer Bericht für die Kommandozeile."""
    names = {
        "equal": "gleich",
        "a_in_b": "A ist in B enthalten (B ist allgemeiner)",
        "b_in_a": "B ist in A enthalten (A ist allgemeiner)",
        "incomparable": "unvergleichbar",
    }
    keep = {"a": "A behalten, B verwerfen", "b": "B behalten, A verwerfen", "both": "beide behalten"}[c.keep]
    lines = [
        f"Richtlinienvergleich (exakt, nach Gruppennamen): {names[c.relation]}",
        f"Gleiche Gruppen: {'ja' if c.same_groups else 'nein (Lemma gilt nur bei gleichen Subnetzen)'}",
        f"Bis auf zyklische Verschiebung (exakt): {names[c.rotation_relation]}",
        f"Subgraph Algorithmus: {c.subgraph_decision} -> {names[c.subgraph_relation]}",
        "Subgraph Algorithmus stimmt mit der exakten Prüfung überein: "
        + ("ja" if c.subgraph_agrees else "nein (Heuristik, exakte Prüfung ist maßgeblich)"),
        f"Empfehlung: {keep}",
    ]
    return "\n".join(lines)
