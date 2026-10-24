"""Tests der Sequenzprüfung (src/sequence.py): Soll-Graph, zustandsloses Token, Verifikation."""
import base64
import json
import os
import random
import tempfile

import numpy as np
import pytest

from src.sequence import (
    DEFAULT_GRAPH,
    ENDE,
    START,
    SequenceError,
    SequenceGraph,
    adjacency,
    advance,
    load_graph,
    missing_after_update,
    trace_edges,
    verify_traces,
)

pytestmark = pytest.mark.unit

KEY = b"test-key"
SMALL = SequenceGraph.from_pairs([(START, "a"), ("a", "b"), ("b", "b"), ("b", ENDE), ("a", ENDE)])


def step(graph, endpoint, token=None, *, start=None, end=False, now=0.0, key=KEY, ttl=600):
    return advance(graph, key, endpoint, start=start, token=token, end=end, now=now, ttl=ttl)


def walk(graph, path, *, start="s1", now=0.0, dt=1.0, key=KEY):
    """Läuft einen Weg Schritt für Schritt und gibt das Ergebnis des letzten Schritts zurück."""
    result = None
    for i, endpoint in enumerate(path):
        if i == 0:
            result = step(graph, endpoint, start=start, now=now, key=key)
        else:
            result = step(graph, endpoint, result.token, now=now + i * dt, key=key)
    return result


def path_to(graph, target):
    """Kürzester Weg START -> target als Liste von Endpunkten (ohne START)."""
    queue = [[START]]
    seen = {START}
    while queue:
        path = queue.pop(0)
        if path[-1] == target:
            return path[1:]
        for follower in graph.successors(path[-1]):
            if follower not in seen:
                seen.add(follower)
                queue.append(path + [follower])
    raise AssertionError(f"{target} nicht erreichbar")


def error_of(call):
    with pytest.raises(SequenceError) as info:
        call()
    return info.value


def forged(token, **changes):
    """Verändert die Nutzlast eines Tokens, ohne die Signatur neu zu berechnen."""
    payload = json.loads(base64.urlsafe_b64decode(token.encode()))
    payload.update(changes)
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


# --- Soll-Graph ---------------------------------------------------------------------------

def test_graph_rejects_missing_entry():
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([("a", ENDE)])
    assert "START" in str(info.value)


def test_graph_rejects_edge_into_start_and_out_of_end():
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([(START, "a"), ("a", START), ("a", ENDE)])
    assert "START" in str(info.value)
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([(START, "a"), ("a", ENDE), (ENDE, "a")])
    assert "ENDE" in str(info.value)


def test_graph_rejects_unreachable_end_unreachable_node_and_dead_end():
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([(START, "a"), ("a", "a")])
    assert "ENDE" in str(info.value)
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([(START, "a"), ("a", ENDE), ("b", ENDE)])
    assert "'b'" in str(info.value) and "nicht erreichbar" in str(info.value)
    with pytest.raises(ValueError) as info:
        SequenceGraph.from_pairs([(START, "a"), ("a", ENDE), ("a", "c")])
    assert "'c'" in str(info.value) and "Weg nach ENDE" in str(info.value)


def test_graph_accessors_and_fingerprint():
    assert SMALL.nodes == (ENDE, START, "a", "b")
    assert SMALL.successors("a") == ["ENDE", "b"]
    assert SMALL.successors("unbekannt") == []
    same = SequenceGraph.from_pairs(reversed(sorted(SMALL.edges)))
    assert same.fingerprint() == SMALL.fingerprint()
    other = SequenceGraph.from_pairs(sorted(SMALL.edges) + [("b", "a")])
    assert other.fingerprint() != SMALL.fingerprint()


def test_graph_from_json_and_file():
    text = json.dumps({"edges": [[START, "x"], ["x", ENDE]]})
    graph = SequenceGraph.from_json(text)
    assert graph.successors(START) == ["x"]
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "graph.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        assert load_graph(path) == graph


def test_graph_from_json_rejects_bad_input():
    for bad in ("{", "[]", '{"edges": 3}', '{"edges": [["a"]]}', '{"edges": [["a", 1]]}', '{"edges": [[1, 2]]}'):
        with pytest.raises(ValueError):
            SequenceGraph.from_json(bad)


def test_default_graph_encodes_the_intended_process():
    assert DEFAULT_GRAPH.successors(START) == ["plans"]
    assert ("extend", "firewall") not in DEFAULT_GRAPH.edges        # Analyse-Endpunkte planen neu
    assert [a for a, b in DEFAULT_GRAPH.edges if b == "roundtrip"] == ["firewall"]
    for node in ("plans", "extend", "verify", "stats", "warnings", "firewall", "roundtrip",
                 "compare", "compare-services", "verdict"):
        assert node in DEFAULT_GRAPH.nodes


# --- Betreten, Fortsetzen, Beenden --------------------------------------------------------

def test_planned_sequence_is_accepted_and_counts_steps():
    first = step(SMALL, "a", start="s1")
    second = step(SMALL, "b", first.token, now=5)
    third = step(SMALL, "b", second.token, now=6)
    closed = step(SMALL, "b", third.token, end=True, now=7)
    assert (first.steps, second.steps, third.steps, closed.steps) == (1, 2, 3, 4)
    assert first.seq == closed.seq == "s1"
    assert closed.closed and closed.token is None and not first.closed


def test_single_step_sequence_with_end():
    result = step(SMALL, "a", start="s1", end=True)
    assert result.closed and result.token is None and result.steps == 1


def test_entry_invalid_names_allowed_entries():
    error = error_of(lambda: step(SMALL, "b", start="s1"))
    assert (error.kind, error.status) == ("entry_invalid", 409)
    assert error.body["error"]["allowed_entries"] == ["a"]
    assert error.body["error"]["type"] == "sequence/entry_invalid"
    assert error.body["status"] == 409 and error.body["error"]["message"]


def test_start_invalid_requires_a_clean_identifier():
    for start in (None, "", "mit leerzeichen", "ä", "x" * 65):
        error = error_of(lambda start=start: step(SMALL, "a", start=start))
        assert (error.kind, error.status) == ("start_invalid", 422)
    assert step(SMALL, "a", start="x" * 64).seq == "x" * 64


def test_transition_invalid_names_last_step_and_successors():
    token = step(SMALL, "a", start="s1").token
    error = error_of(lambda: step(SMALL, "a", token, now=1))
    assert error.kind == "transition_invalid"
    assert error.body["error"]["last_valid_step"] == "a"
    assert error.body["error"]["endpoint"] == "a"
    assert error.body["error"]["expected_next"] == ["ENDE", "b"]


def test_end_invalid_when_end_is_not_a_successor():
    graph = SequenceGraph.from_pairs([(START, "a"), ("a", "b"), ("b", "c"), ("c", ENDE)])
    error = error_of(lambda: step(graph, "a", start="s1", end=True))            # beim Betreten
    assert error.kind == "end_invalid" and error.body["error"]["expected_next"] == ["b"]
    token = step(graph, "a", start="s1").token
    error = error_of(lambda: step(graph, "b", token, now=1, end=True))          # beim Fortsetzen
    assert error.kind == "end_invalid" and error.body["error"]["expected_next"] == ["c"]
    assert step(graph, "b", token, now=1).token is not None                     # ohne Ende bleibt es zulässig


def test_deadline_is_inclusive_and_late_steps_are_rejected():
    token = step(SMALL, "a", start="s1", now=100, ttl=60).token
    assert step(SMALL, "b", token, now=160, ttl=60).steps == 2          # genau an der Frist
    error = error_of(lambda: step(SMALL, "b", token, now=160.5, ttl=60))
    assert error.kind == "abandoned_late"
    assert error.body["error"]["last_valid_step"] == "a"
    assert error.body["error"]["expired_at"] == 160
    assert error.body["error"]["steps_done"] == 1


def test_each_step_renews_the_deadline():
    token = step(SMALL, "a", start="s1", now=0, ttl=10).token
    for i in range(1, 6):
        token = step(SMALL, "b", token, now=i * 9, ttl=10).token       # jeweils vor Ablauf


# --- Token: Echtheit, Kennung, Fassung des Graphen ---------------------------------------

def test_tampered_or_foreign_tokens_are_rejected():
    token = step(SMALL, "a", start="s1").token
    for bad in (
        forged(token, n=99),
        forged(token, last="b"),
        forged(token, deadline=10 ** 9),
    ):
        assert error_of(lambda bad=bad: step(SMALL, "b", bad, now=1)).kind == "context_invalid"
    assert error_of(lambda: step(SMALL, "b", token, now=1, key=b"anderer-schluessel")).kind == "context_invalid"


def test_unreadable_tokens_are_rejected():
    garbage = base64.urlsafe_b64encode
    for bad in (
        "!!!",
        "",
        garbage(b"[1]").decode(),                       # keine Nutzlast als Objekt
        garbage(b"{}").decode(),                        # Signatur fehlt
        garbage(b'{"h": 5}').decode(),                  # Signatur kein Text
        garbage(b"nicht json").decode(),
    ):
        error = error_of(lambda bad=bad: step(SMALL, "b", bad, now=1))
        assert error.kind == "context_invalid", bad


def test_token_of_another_graph_version_is_rejected():
    token = step(SMALL, "a", start="s1").token
    changed = SequenceGraph.from_pairs(sorted(SMALL.edges) + [("a", "a")])
    error = error_of(lambda: step(changed, "b", token, now=1))
    assert error.kind == "context_invalid" and "Fassung" in str(error)


def test_start_must_match_token_when_both_are_given():
    token = step(SMALL, "a", start="s1").token
    assert step(SMALL, "b", token, start="s1", now=1).seq == "s1"
    assert error_of(lambda: step(SMALL, "b", token, start="s2", now=1)).kind == "context_invalid"


# --- Eigenschaften -----------------------------------------------------------------------

def test_every_edge_decision_is_exact_for_the_default_graph():
    """Satz (Kantenaussage): Ein Schritt ist zulässig genau dann, wenn die Kante im Soll-Graphen liegt."""
    names = list(DEFAULT_GRAPH.nodes) + ["unbekannt"]
    for node in names:                                  # Betreten
        allowed = (START, node) in DEFAULT_GRAPH.edges
        if allowed:
            assert step(DEFAULT_GRAPH, node, start="s").steps == 1
        else:
            assert error_of(lambda node=node: step(DEFAULT_GRAPH, node, start="s")).kind == "entry_invalid"
    for last in DEFAULT_GRAPH.nodes:
        if last in (START, ENDE):
            continue
        token = walk(DEFAULT_GRAPH, path_to(DEFAULT_GRAPH, last)).token
        for node in names:                              # Fortsetzen
            if (last, node) in DEFAULT_GRAPH.edges:
                assert step(DEFAULT_GRAPH, node, token, now=100).steps >= 2
            else:
                error = error_of(lambda node=node: step(DEFAULT_GRAPH, node, token, now=100))
                assert error.kind == "transition_invalid"
                assert error.body["error"]["expected_next"] == DEFAULT_GRAPH.successors(last)
        for node in DEFAULT_GRAPH.successors(last):     # Beenden: nur wo eine Kante nach ENDE führt
            if (node, ENDE) in DEFAULT_GRAPH.edges:
                assert step(DEFAULT_GRAPH, node, token, end=True, now=100).closed
            else:
                error = error_of(lambda node=node: step(DEFAULT_GRAPH, node, token, end=True, now=100))
                assert error.kind == "end_invalid"


def test_advance_is_a_pure_function_and_sequences_are_independent():
    assert step(SMALL, "a", start="s1", now=3).token == step(SMALL, "a", start="s1", now=3).token
    solo_1 = walk(SMALL, ["a", "b", "b"], start="one")
    solo_2 = walk(SMALL, ["a", "b"], start="two")
    one = step(SMALL, "a", start="one")                 # verschränkt ausgeführt
    two = step(SMALL, "a", start="two")
    one = step(SMALL, "b", one.token, now=1.0)
    two = step(SMALL, "b", two.token, now=1.0)
    one = step(SMALL, "b", one.token, now=2.0)
    assert (one.token, two.token) == (solo_1.token, solo_2.token)


def test_guard_and_verifier_agree_on_random_traces():
    """Dieselbe Spur ist beim Wiederabspielen zulässig genau dann, wenn sie planmäßig im Sinne der Verifikation ist."""
    rng = random.Random(7)
    names = list(DEFAULT_GRAPH.nodes) + ["unbekannt"]
    for _ in range(400):
        length = rng.randint(1, 6)
        if rng.random() < 0.5:                          # Irrläufer über beliebige Namen
            trace = [rng.choice(names) for _ in range(length)]
        else:                                           # Zufallsweg im Soll-Graphen, gelegentlich gestört
            trace, node = [], START
            for _ in range(length):
                options = DEFAULT_GRAPH.successors(node)
                if node == ENDE or not options:
                    break
                node = rng.choice(options)
                trace.append(node)
            if trace and rng.random() < 0.3:
                trace[rng.randrange(len(trace))] = rng.choice(names)
        if not trace:
            continue
        accepted = True
        token = None
        for i, endpoint in enumerate(trace):
            try:
                token = step(DEFAULT_GRAPH, endpoint, token, start="s" if i == 0 else None, now=i).token
            except SequenceError:
                accepted = False
                break
        assert accepted == verify_traces(DEFAULT_GRAPH, [trace]).ok, trace


# --- Verifikation: Ist-Graph gegen Soll-Graph ---------------------------------------------

def test_trace_edges_start_at_start():
    assert trace_edges(["a", "b", "b"]) == {(START, "a"), ("a", "b"), ("b", "b")}
    assert trace_edges([]) == set()


def test_verify_accepts_planned_and_open_traces_and_reports_coverage():
    result = verify_traces(SMALL, [["a", "b", ENDE], ["a"]])
    assert result.ok and result.outside == ()
    assert result.uncovered == (("a", ENDE), ("b", "b"))


def test_verify_reports_edges_outside_the_target_graph():
    result = verify_traces(SMALL, [["a", "b"], ["b", "a"], ["a", "c"]])
    assert not result.ok
    assert result.outside == ((START, "b"), ("a", "c"), ("b", "a"))


def test_verify_without_traces_is_ok_but_covers_nothing():
    result = verify_traces(SMALL, [])
    assert result.ok and set(result.uncovered) == SMALL.edges


def test_edge_coverage_of_the_default_graph_by_one_trace_per_edge():
    traces = [path_to(DEFAULT_GRAPH, a)[:] + [b] for a, b in sorted(DEFAULT_GRAPH.edges) if a != START]
    traces += [[b] for a, b in DEFAULT_GRAPH.edges if a == START]
    result = verify_traces(DEFAULT_GRAPH, traces)
    assert result.ok and result.uncovered == ()


def test_update_keeps_all_old_sequences_iff_no_edge_is_lost():
    grown = SequenceGraph.from_pairs(sorted(SMALL.edges) + [("a", "a")])
    assert missing_after_update(SMALL, grown) == ()
    assert missing_after_update(grown, SMALL) == (("a", "a"),)


def test_adjacency_matrix_matches_edge_inclusion():
    nodes = [START, "a", "b", ENDE]
    matrix = adjacency(SMALL, nodes)
    assert matrix.shape == (4, 4) and matrix.sum() == len(SMALL.edges)
    assert matrix[0, 1] == 1 and matrix[1, 3] == 1 and matrix[2, 1] == 0
    grown = SequenceGraph.from_pairs(sorted(SMALL.edges) + [("a", "a")])
    assert np.all(matrix <= adjacency(grown, nodes))                 # SMALL ist Teilgraph von grown
    assert not np.all(adjacency(grown, nodes) <= matrix)
    assert adjacency(SMALL, ["a"]).tolist() == [[0]]                 # unbekannte Knoten entfallen


def test_error_body_has_the_api_shape():
    body = SequenceError("transition_invalid", "Text", last_valid_step="a", expected_next=["b"]).body
    assert body == {"status": 409, "error": {"type": "sequence/transition_invalid", "message": "Text",
                                            "last_valid_step": "a", "expected_next": ["b"]}}
