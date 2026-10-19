"""Zugriffsmatrix, Bereinigung von ``access`` und Regelgruppierung.

Umgesetzt werden
  * Definition "Zugriffsmatrix und Zugriffsgraph" (``access_matrix``, ``policy_pairs``),
  * Satz "Bereinigung von access" (``clean_access``),
  * Satz "Regelgruppierung" (``rule_groups``),
  * Satz "Cisco-Semantik", Teil Rückverkehr (``asymmetric_pairs``).
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, List, Sequence, Tuple

import numpy as np

from .models import Group, Plan, Subnet


def clean_access(groups: Sequence[Group]) -> Tuple[Tuple[Group, ...], Tuple[str, ...]]:
    """Entfernt Wiederholungen und Selbstbezüge aus allen ``access``-Listen.

    Nach Satz "Bereinigung von access" ändert das das Urteil keines Pakets; die Zahl der
    Freigaben sinkt auf genau |P|. Die Reihenfolge der verbleibenden Ziele bleibt erhalten.
    Rückgabe: die bereinigten Gruppen und eine Warnung je gefundenem Problem.
    """
    cleaned: List[Group] = []
    warnings: List[str] = []
    for g in groups:
        seen: List[str] = []
        for target in g.access:
            if target == g.name:
                warnings.append(f"Gruppe {g.name!r}: Selbstbezug in access wurde entfernt")
            elif target in seen:
                warnings.append(f"Gruppe {g.name!r}: {target!r} steht mehrfach in access")
            else:
                seen.append(target)
        cleaned.append(replace(g, access=tuple(seen)))
    return tuple(cleaned), tuple(warnings)


def access_matrix(groups: Sequence[Group]) -> np.ndarray:
    """Zugriffsmatrix Z in Dateireihenfolge: Z[i, j] = 1, wenn g_j in acc(g_i) vorkommt."""
    index: Dict[str, int] = {g.name: i for i, g in enumerate(groups)}
    z = np.zeros((len(groups), len(groups)), dtype=int)
    for i, g in enumerate(groups):
        for target in g.access:
            if target in index:
                z[i, index[target]] = 1
    return z


def plan_access_matrix(plan: Plan) -> Tuple[Tuple[str, ...], np.ndarray]:
    """Zugriffsmatrix eines Plans (Zeilen und Spalten in Adressreihenfolge) mit Namen."""
    names = tuple(s.group for s in plan.subnets)
    index = {n: i for i, n in enumerate(names)}
    z = np.zeros((len(names), len(names)), dtype=int)
    for i, s in enumerate(plan.subnets):
        for target in s.access:
            if target in index:
                z[i, index[target]] = 1
    return names, z


def policy_pairs(plan: Plan) -> FrozenSet[Tuple[str, str]]:
    """Menge P der Zugriffspaare (Quelle, Ziel) mit Quelle != Ziel."""
    names = {s.group for s in plan.subnets}
    return frozenset(
        (s.group, t) for s in plan.subnets for t in s.access if t != s.group and t in names
    )


@dataclass(frozen=True)
class RuleGroup:
    """Eine gruppierte Regel R_T: Quellen S_T und Ziele T (Satz "Regelgruppierung")."""

    sources: Tuple[Subnet, ...]
    targets: Tuple[Subnet, ...]

    @property
    def label(self) -> str:
        src = ",".join(s.group for s in self.sources)
        dst = ",".join(t.group for t in self.targets)
        return f"{src} -> {dst}"


def rule_groups(plan: Plan) -> Tuple[RuleGroup, ...]:
    """Fasst Gruppen mit gleicher nichtleerer Zielmenge T(i) zu einer Regel zusammen.

    Die Zahl der Regeln ist |T| <= n. Das Urteil für neue Pakete bleibt dasselbe wie bei
    einer Regel je Zugriffspaar (Satz "Regelgruppierung").
    """
    by_name = {s.group: s for s in plan.subnets}
    order = {s.group: i for i, s in enumerate(plan.subnets)}
    targets_of: Dict[str, FrozenSet[str]] = {}
    for s in plan.subnets:
        targets = frozenset(t for t in s.access if t != s.group and t in by_name)
        if targets:
            targets_of[s.group] = targets
    grouped: Dict[FrozenSet[str], List[str]] = {}
    for s in plan.subnets:  # Adressreihenfolge -> deterministische Ausgabe
        if s.group in targets_of:
            grouped.setdefault(targets_of[s.group], []).append(s.group)
    result = []
    for targets, sources in grouped.items():
        result.append(
            RuleGroup(
                tuple(by_name[n] for n in sources),
                tuple(by_name[n] for n in sorted(targets, key=order.__getitem__)),
            )
        )
    return tuple(result)


def asymmetric_pairs(plan: Plan) -> Tuple[Tuple[str, str], ...]:
    """Paare (i, j) in P ohne Gegenpaar (j, i).

    Bei zustandslosen Cisco-ACLs wird Rückverkehr nur bei symmetrischem Zugriff
    weitergeleitet (Satz "Cisco-Semantik"); diese Paare brauchen Rückverkehrsregeln.
    """
    pairs = policy_pairs(plan)
    return tuple(sorted(p for p in pairs if (p[1], p[0]) not in pairs))
