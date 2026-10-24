"""Sequenzprüfung für die JSON-API: zustandslos, opt-in, verifizierbar.

Ein einzelner Request an einen einzelnen Endpunkt hat kein Davor und kein Danach. Ein Prozess
dagegen ist eine *Folge* von Requests (Plan berechnen, prüfen, Regeln erzeugen, zurückprüfen,
erweitern, vergleichen). Dieses Modul bildet die zulässigen Folgen als gerichteten Graphen ab
(Soll-Graph) und prüft je Request, ob er an der richtigen Stelle der Folge steht.

Zwei Fehler gibt es nur bei Folgen:

* **Unzulässiges Betreten** (``entry_invalid``): die Folge beginnt mit einem Endpunkt, der nicht
  Nachfolger von ``START`` ist.
* **Unzulässiger Übergang** (``transition_invalid``) und **Ablauf der Frist**
  (``abandoned_late``): die Folge weicht vom Soll-Graphen ab oder wurde zu spät fortgesetzt.

Die Prüfung bleibt zustandslos: Der Zustand der Folge steckt in einem signierten Token, das der
Client mitführt. ``advance`` ist eine reine Funktion von (Endpunkt, Kopfzeilen, Zeit). Der Server
speichert nichts. Das Token ist **signiert, nicht verschlüsselt**, und beweist nur die Ordnung der
bisherigen Schritte, nicht deren Fachlichkeit.

Die Verifikation (``verify_traces``) prüft beobachtete Spuren gegen den Soll-Graphen als exakte
Kanteninklusion Ist ⊆ Soll, das ist die Teilgraph-Beziehung auf benannten Knoten.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

import numpy as np

START = "START"
ENDE = "ENDE"
DEFAULT_TTL = 600  # Sekunden zwischen zwei Schritten einer Folge
_SEQUENCE_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_TOKEN_VERSION = 1

Edge = tuple[str, str]


class SequenceError(Exception):
    """Fehler der Folge (nicht des einzelnen Requests): Betreten, Übergang, Frist, Token."""

    def __init__(self, kind: str, message: str, status: int = 409, **detail: Any) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.detail = detail

    @property
    def body(self) -> dict[str, Any]:
        """Antwortkörper im Schema der API: ``{"status": ..., "error": {"type": ..., ...}}``."""
        return {
            "status": self.status,
            "error": {"type": f"sequence/{self.kind}", "message": str(self), **self.detail},
        }


def _reachable(adjacency: dict[str, set[str]], origin: str) -> set[str]:
    seen = {origin}
    todo = [origin]
    while todo:
        for follower in adjacency.get(todo.pop(), ()):
            if follower not in seen:
                seen.add(follower)
                todo.append(follower)
    return seen


@dataclass(frozen=True)
class SequenceGraph:
    """Soll-Graph: Knoten sind Endpunkt-Namen sowie ``START`` und ``ENDE``, Kanten zulässige Übergänge."""

    edges: frozenset[Edge]

    def __post_init__(self) -> None:
        if not any(a == START for a, _ in self.edges):
            raise ValueError("Der Soll-Graph braucht mindestens eine Kante von START")
        if any(b == START for _, b in self.edges):
            raise ValueError("In START darf keine Kante münden")
        if any(a == ENDE for a, _ in self.edges):
            raise ValueError("Von ENDE darf keine Kante ausgehen")
        forward: dict[str, set[str]] = {}
        backward: dict[str, set[str]] = {}
        for a, b in self.edges:
            forward.setdefault(a, set()).add(b)
            backward.setdefault(b, set()).add(a)
        if ENDE not in _reachable(forward, START):
            raise ValueError("ENDE ist von START aus nicht erreichbar")
        nodes = {n for edge in self.edges for n in edge}
        unreachable = nodes - _reachable(forward, START)
        if unreachable:
            raise ValueError(f"Von START aus nicht erreichbar: {sorted(unreachable)}")
        dead_ends = nodes - _reachable(backward, ENDE)
        if dead_ends:
            raise ValueError(f"Ohne Weg nach ENDE: {sorted(dead_ends)}")

    @classmethod
    def from_pairs(cls, pairs: Iterable[Sequence[str]]) -> "SequenceGraph":
        return cls(frozenset((a, b) for a, b in pairs))

    @classmethod
    def from_json(cls, text: str) -> "SequenceGraph":
        """Liest ``{"edges": [["START", "plans"], ...]}``."""
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"Soll-Graph ist kein gültiges JSON: {exc}") from exc
        edges = data.get("edges") if isinstance(data, dict) else None
        if not isinstance(edges, list) or not all(
            isinstance(e, list) and len(e) == 2 and all(isinstance(n, str) for n in e) for e in edges
        ):
            raise ValueError('Soll-Graph muss die Form {"edges": [["A", "B"], ...]} haben')
        return cls.from_pairs(edges)

    @property
    def nodes(self) -> tuple[str, ...]:
        return tuple(sorted({n for edge in self.edges for n in edge}))

    def successors(self, node: str) -> list[str]:
        return sorted(b for a, b in self.edges if a == node)

    def fingerprint(self) -> str:
        """Kurzer Hash der Kantenmenge; Tokens einer anderen Fassung des Graphen werden abgewiesen."""
        text = "\n".join(f"{a}>{b}" for a, b in sorted(self.edges))
        return hashlib.sha256(text.encode()).hexdigest()[:12]


def load_graph(path: str) -> SequenceGraph:
    with open(path, encoding="utf-8") as handle:
        return SequenceGraph.from_json(handle.read())


_ANALYSIS = ("verify", "stats", "warnings", "verdict")

#: Standard-Soll-Graph für den Prozess "Planen, prüfen, Regeln erzeugen, zurückprüfen, erweitern".
#: `firewall` folgt nicht auf `extend`: Die Analyse-Endpunkte berechnen den Plan aus der
#: Konfiguration neu, ein erweiterter Plan wird dort nicht übergeben (siehe README).
DEFAULT_GRAPH = SequenceGraph.from_pairs(
    [(START, "plans")]
    + [("plans", n) for n in (*_ANALYSIS, "firewall", "extend", ENDE)]
    + [(a, n) for a in _ANALYSIS for n in (*_ANALYSIS, "firewall", "extend", ENDE)]
    + [("firewall", "roundtrip")]
    + [("roundtrip", n) for n in ("verdict", "extend", "compare", "compare-services", ENDE)]
    + [("extend", n) for n in (*_ANALYSIS, "extend", ENDE)]
    + [("compare", ENDE), ("compare-services", ENDE)]
)


def _sign(key: bytes, payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, text, hashlib.sha256).hexdigest()[:32]


def _encode(key: bytes, payload: dict[str, Any]) -> str:
    raw = json.dumps({**payload, "h": _sign(key, payload)}, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode(key: bytes, token: str) -> dict[str, Any]:
    try:
        payload = json.loads(base64.urlsafe_b64decode(token.encode()))
        mac = payload.pop("h")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SequenceError("context_invalid", "Das Sequenz-Token ist nicht lesbar") from None
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _sign(key, payload)):
        raise SequenceError("context_invalid", "Das Sequenz-Token ist verändert oder nicht echt") from None
    return payload


@dataclass(frozen=True)
class Advance:
    """Ergebnis eines gültigen Schritts: neues Token (``None`` nach Ende), Kennung, Schrittzahl."""

    token: Optional[str]
    seq: str
    steps: int
    closed: bool


def advance(
    graph: SequenceGraph,
    key: bytes,
    endpoint: str,
    *,
    start: Optional[str],
    token: Optional[str],
    end: bool,
    now: float,
    ttl: int = DEFAULT_TTL,
) -> Advance:
    """Prüft einen Schritt der Folge. Reine Funktion von (Endpunkt, Kopfzeilen, Zeit).

    ``start`` ist die Kennung beim Betreten, ``token`` das zuletzt erhaltene Token, ``end`` markiert
    diesen Schritt als letzten der Folge. Bei einem Verstoß wird :class:`SequenceError` ausgelöst.
    """
    if token is None:
        if start is None or not _SEQUENCE_ID.fullmatch(start):
            raise SequenceError(
                "start_invalid",
                "Beim Betreten ist eine Sequenzkennung aus 1 bis 64 Zeichen [A-Za-z0-9._-] nötig",
                status=422,
            )
        if (START, endpoint) not in graph.edges:
            raise SequenceError(
                "entry_invalid",
                f"Die Folge darf nicht mit '{endpoint}' beginnen",
                endpoint=endpoint,
                allowed_entries=graph.successors(START),
            )
        seq, steps = start, 1
    else:
        payload = _decode(key, token)
        if payload["g"] != graph.fingerprint():
            raise SequenceError("context_invalid", "Das Token stammt aus einer anderen Fassung des Soll-Graphen")
        if start is not None and start != payload["seq"]:
            raise SequenceError("context_invalid", "Die Sequenzkennung passt nicht zum Token")
        if now > payload["deadline"]:
            raise SequenceError(
                "abandoned_late",
                "Die Folge wurde nach Ablauf der Frist fortgesetzt; ein neuer Beginn ist nötig",
                last_valid_step=payload["last"],
                expired_at=payload["deadline"],
                steps_done=payload["n"],
            )
        if (payload["last"], endpoint) not in graph.edges:
            raise SequenceError(
                "transition_invalid",
                f"Nach '{payload['last']}' ist '{endpoint}' nicht zulässig",
                last_valid_step=payload["last"],
                endpoint=endpoint,
                expected_next=graph.successors(payload["last"]),
            )
        seq, steps = payload["seq"], payload["n"] + 1
    if end:
        if (endpoint, ENDE) not in graph.edges:
            raise SequenceError(
                "end_invalid",
                f"Die Folge darf nicht nach '{endpoint}' enden",
                endpoint=endpoint,
                expected_next=graph.successors(endpoint),
            )
        return Advance(None, seq, steps, True)
    fresh = {"v": _TOKEN_VERSION, "g": graph.fingerprint(), "seq": seq, "n": steps, "last": endpoint,
             "deadline": now + ttl}
    return Advance(_encode(key, fresh), seq, steps, False)


# --- Verifikation -------------------------------------------------------------------------

@dataclass(frozen=True)
class Verification:
    """Ergebnis von :func:`verify_traces`: ``outside`` sind Ist-Kanten außerhalb des Soll-Graphen,
    ``uncovered`` Soll-Kanten, die keine Spur durchläuft (Kantenabdeckung)."""

    ok: bool
    outside: tuple[Edge, ...]
    uncovered: tuple[Edge, ...]


def trace_edges(trace: Sequence[str]) -> set[Edge]:
    """Kanten einer Spur ``[e1, e2, ...]``: ``START -> e1``, ``e1 -> e2``, ..."""
    return set(zip([START, *trace], trace))


def verify_traces(graph: SequenceGraph, traces: Iterable[Sequence[str]]) -> Verification:
    """Alle beobachteten Spuren sind planmäßig genau dann, wenn der Ist-Graph Teilgraph des Soll-Graphen ist.

    Das ist die exakte Kanteninklusion auf benannten Knoten. Spuren ohne ``ENDE`` (offene Folgen)
    sind zulässig, solange ihre Kanten im Soll-Graphen liegen.
    """
    actual: set[Edge] = set()
    for trace in traces:
        actual |= trace_edges(trace)
    outside = tuple(sorted(actual - graph.edges))
    uncovered = tuple(sorted(graph.edges - actual))
    return Verification(not outside, outside, uncovered)


def missing_after_update(old: SequenceGraph, new: SequenceGraph) -> tuple[Edge, ...]:
    """Kanten des alten Soll-Graphen, die der neue nicht mehr enthält. Leer heißt: alle bisherigen
    Folgen bleiben zulässig (der alte Soll-Graph ist Teilgraph des neuen)."""
    return tuple(sorted(old.edges - new.edges))


def adjacency(graph: SequenceGraph, nodes: Sequence[str]) -> np.ndarray:
    """Adjazenzmatrix über einer vorgegebenen Knotenfolge, z. B. für einen Vergleich mit dem
    Subgraph Algorithmus (Zeile = Quelle, Spalte = Ziel)."""
    index = {name: i for i, name in enumerate(nodes)}
    matrix = np.zeros((len(nodes), len(nodes)), dtype=int)
    for a, b in graph.edges:
        if a in index and b in index:
            matrix[index[a], index[b]] = 1
    return matrix
