"""Zugriffsmatrix, Bereinigung von ``access`` und Regelgruppierung.

Umgesetzt werden
  * Definition "Zugriffsmatrix und Zugriffsgraph" (``access_matrix``, ``policy_pairs``),
  * Satz "Bereinigung von access" (``clean_access``),
  * Satz "Regelgruppierung" (``rule_groups``),
  * Satz "Cisco-Semantik", Teil Rückverkehr (``asymmetric_pairs``),
  * Kapitel "Protokolle und Ports": Dienstmengen je Zugriffspaar (``pair_services``,
    ``policy_services``, ``services_included``) und Regelgruppierung nach Diensten.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

import numpy as np

from .models import Group, Plan, Subnet
from .ports import ServiceSet


def _merge_services(group: Group, kept: Sequence[str]) -> Tuple[Tuple[str, ServiceSet], ...]:
    """Dienstmengen der behaltenen Ziele nach Definition "Dienstfreigabe".

    ``group.access`` darf ein Ziel mehrfach nennen; jede eingeschränkte Nennung steht zusätzlich
    in ``group.services``. Gibt es für ein Ziel mindestens eine Nennung *ohne* Einschränkung, gilt
    das Ziel für alle Dienste; sonst ist ``Sigma_ij`` die Vereinigung aller Dienstmengen.
    """
    mentions = {t: group.access.count(t) for t in kept}
    restricted: Dict[str, List[ServiceSet]] = {}
    for target, sigma in group.services:
        restricted.setdefault(target, []).append(sigma)
    merged: List[Tuple[str, ServiceSet]] = []
    for target in kept:
        sigmas = restricted.get(target, [])
        if not sigmas or len(sigmas) < mentions[target]:
            continue  # mindestens eine Nennung ohne Einschränkung: alle Dienste
        total = sigmas[0]
        for sigma in sigmas[1:]:
            total = total.union(sigma)
        merged.append((target, total))
    return tuple(merged)


def clean_access(groups: Sequence[Group]) -> Tuple[Tuple[Group, ...], Tuple[str, ...]]:
    """Entfernt Wiederholungen und Selbstbezüge aus allen ``access``-Listen.

    Nach Satz "Bereinigung von access" ändert das das Urteil keines Pakets; die Zahl der
    Freigaben sinkt auf genau |P|. Die Reihenfolge der verbleibenden Ziele bleibt erhalten.
    Mehrfach genannte Ziele mit Dienstbeschränkung werden zur Vereinigung ihrer Dienstmengen
    zusammengefasst (ohne Beschränkung bei einer der Nennungen: alle Dienste).
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
        cleaned.append(replace(g, access=tuple(seen), services=_merge_services(g, seen)))
    return tuple(cleaned), tuple(warnings)


def drop_unrestricted_services(groups: Sequence[Group], version: int) -> Tuple[Group, ...]:
    """Entfernt Dienstmengen, die für die IP-Version alles erlauben (gleich ``D``).

    Ein Ziel, dessen Dienstmenge so viel freigibt wie keine Angabe, wird wie ein Ziel ohne
    Einschränkung behandelt; die Regeln bleiben dann die einfachen Adressregeln.
    """
    return tuple(
        replace(g, services=tuple((t, sigma) for t, sigma in g.services if not sigma.covers_all(version)))
        for g in groups
    )


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


def pair_services(subnet: Subnet, target: str) -> Optional[ServiceSet]:
    """Dienstmenge der Freigabe ``subnet -> target``; ``None`` heißt: alle Dienste."""
    return dict(subnet.services).get(target)


def policy_services(plan: Plan) -> Dict[Tuple[str, str], ServiceSet]:
    """Dienstmenge ``Sigma_ij`` je Zugriffspaar (i, j) in P; ohne Einschränkung ``D`` insgesamt."""
    version = plan.base_network.version
    result: Dict[Tuple[str, str], ServiceSet] = {}
    for pair in policy_pairs(plan):
        sigma = pair_services(next(s for s in plan.subnets if s.group == pair[0]), pair[1])
        result[pair] = ServiceSet.everything() if sigma is None or sigma.covers_all(version) else sigma
    return result


def services_included(plan_a: Plan, plan_b: Plan) -> bool:
    """Ob jede Freigabe von ``plan_a`` auch in ``plan_b`` erlaubt ist (Dienstebene).

    Nach Kapitel "Vergleich von Freigabemengen" ist das genau dann der Fall, wenn
    ``Sigma_ij ⊆ Sigma'_ij`` für alle Paare gilt; Paare ohne Freigabe haben die leere Menge.
    """
    wanted = policy_services(plan_b)
    return all(
        pair in wanted and sigma.issubset(wanted[pair]) for pair, sigma in policy_services(plan_a).items()
    )


def service_differences(
    plan_a: Plan, plan_b: Plan
) -> Tuple[Tuple[str, str, ServiceSet, ServiceSet], ...]:
    """Paare, deren Dienstmengen sich unterscheiden: (Quelle, Ziel, Sigma in A, Sigma in B).

    Ein Paar, das nur in einem der Pläne freigegeben ist, hat im anderen die leere Menge.
    Die Reihenfolge ist deterministisch (nach Gruppennamen sortiert).
    """
    a, b = policy_services(plan_a), policy_services(plan_b)
    empty = ServiceSet()
    return tuple(
        (src, dst, a.get((src, dst), empty), b.get((src, dst), empty))
        for src, dst in sorted(set(a) | set(b))
        if a.get((src, dst), empty) != b.get((src, dst), empty)
    )


@dataclass(frozen=True)
class RuleGroup:
    """Eine gruppierte Regel R_T: Quellen S_T und Ziele T (Satz "Regelgruppierung").

    ``services`` ist die gemeinsame Dienstmenge aller Paare der Regel; ``None`` heißt: alle
    Dienste (so wie bisher).
    """

    sources: Tuple[Subnet, ...]
    targets: Tuple[Subnet, ...]
    services: Optional[ServiceSet] = None

    @property
    def label(self) -> str:
        src = ",".join(s.group for s in self.sources)
        dst = ",".join(t.group for t in self.targets)
        return f"{src} -> {dst}"


def rule_groups(plan: Plan) -> Tuple[RuleGroup, ...]:
    """Fasst Gruppen mit gleicher nichtleerer Zielmenge T(i) zu einer Regel zusammen.

    Die Zahl der Regeln ist |T| <= n. Das Urteil für neue Pakete bleibt dasselbe wie bei
    einer Regel je Zugriffspaar (Satz "Regelgruppierung").

    Mit Dienstbeschränkungen zerfällt die Zielmenge einer Quelle nach gleicher Dienstmenge in
    Einheiten (T, sigma); gruppiert wird nach (T, sigma). Ohne Beschränkungen ist das genau die
    bisherige Gruppierung; die Vereinigung der Regeln erlaubt dieselben Paare und Dienste.
    """
    version = plan.base_network.version
    by_name = {s.group: s for s in plan.subnets}
    order = {s.group: i for i, s in enumerate(plan.subnets)}
    grouped: Dict[Tuple[FrozenSet[str], Optional[ServiceSet]], List[str]] = {}
    for s in plan.subnets:  # Adressreihenfolge -> deterministische Ausgabe
        by_sigma: Dict[Optional[ServiceSet], set] = {}
        for t in s.access:
            if t == s.group or t not in by_name:
                continue
            sigma = pair_services(s, t)
            if sigma is not None and sigma.covers_all(version):
                sigma = None
            by_sigma.setdefault(sigma, set()).add(t)
        for sigma, targets in by_sigma.items():
            grouped.setdefault((frozenset(targets), sigma), []).append(s.group)
    result = []
    for (targets, sigma), sources in grouped.items():
        result.append(
            RuleGroup(
                tuple(by_name[n] for n in sources),
                tuple(by_name[n] for n in sorted(targets, key=order.__getitem__)),
                sigma,
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
