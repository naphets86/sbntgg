"""Tests der optionalen Sequenzprüfung in der JSON API (Kopfzeilen X-Sequence-*)."""
import pytest
from fastapi.testclient import TestClient

import web.api as api
from subnetplan.sequence import SequenceGraph
from web.api import app

pytestmark = pytest.mark.integration

CONFIG = {
    "base_network": "10.0.0.0/24",
    "groups": [
        {"name": "A", "hosts": 50, "access": ["B"]},
        {"name": "B", "hosts": 10},
    ],
}
EXTENSION = {"groups": [{"name": "C", "hosts": 20, "access": ["A"]}]}
PLANS = "/api/v1/plans"
VERIFY = "/api/v1/plans/verify"
EXTEND = "/api/v1/plans/extend"
FIREWALL = "/api/v1/plans/firewall"
ROUNDTRIP = "/api/v1/plans/roundtrip"

client = TestClient(app)


@pytest.fixture
def clock(monkeypatch):
    """Feste Uhr und ein Schlüssel; die Zeit lässt sich über ``clock["t"]`` vorstellen."""
    state = {"t": 1000.0}
    monkeypatch.setattr(api, "SEQUENCE_KEY", b"test-key")
    monkeypatch.setattr(api, "_now", lambda: state["t"])
    return state


def headers(token=None, start=None, end=False):
    result = {}
    if start is not None:
        result["X-Sequence-Start"] = start
    if token is not None:
        result["X-Sequence-Token"] = token
    if end:
        result["X-Sequence-End"] = "true"
    return result


def error_type(response):
    return response.json()["error"]["type"]


def test_requests_without_sequence_headers_are_unchanged(monkeypatch):
    monkeypatch.setattr(api, "SEQUENCE_KEY", None)          # auch ohne eingerichtete Prüfung
    for path in (PLANS, VERIFY, FIREWALL, ROUNDTRIP):
        body = {"config": CONFIG, "firewall": "nftables"} if path == FIREWALL else {"config": CONFIG}
        response = client.post(path, json=body)
        assert response.status_code == 200
        assert "x-sequence-token" not in response.headers


def test_planned_sequence_runs_from_start_to_end(clock):
    first = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    assert first.status_code == 200 and first.headers["x-sequence-token"]
    second = client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=first.headers["x-sequence-token"]))
    assert second.status_code == 200 and second.json()["valid"] is True
    third = client.post(
        FIREWALL,
        json={"config": CONFIG, "firewall": "nftables"},
        headers=headers(token=second.headers["x-sequence-token"]),
    )
    assert third.status_code == 200
    last = client.post(
        ROUNDTRIP, json={"config": CONFIG}, headers=headers(token=third.headers["x-sequence-token"], end=True)
    )
    assert last.status_code == 200
    assert "x-sequence-token" not in last.headers          # nach dem Ende gibt es kein Token mehr


def test_entering_with_the_wrong_endpoint_is_an_error(clock):
    response = client.post(VERIFY, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    assert response.status_code == 409
    assert error_type(response) == "sequence/entry_invalid"
    assert response.json()["status"] == 409
    assert response.json()["error"]["allowed_entries"] == ["plans"]


def test_leaving_the_planned_path_names_last_step_and_successors(clock):
    original = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    extended = client.post(
        EXTEND,
        json={"plan": original.json(), "config": EXTENSION},
        headers=headers(token=original.headers["x-sequence-token"]),
    )
    assert extended.status_code == 200
    response = client.post(
        FIREWALL,
        json={"config": CONFIG, "firewall": "nftables"},
        headers=headers(token=extended.headers["x-sequence-token"]),
    )
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["type"] == "sequence/transition_invalid"
    assert error["last_valid_step"] == "extend" and error["endpoint"] == "firewall"
    assert error["expected_next"] == api.SEQUENCE_GRAPH.successors("extend")


def test_tampered_token_is_rejected(clock):
    first = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    token = first.headers["x-sequence-token"]
    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    response = client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=forged))
    assert response.status_code == 409
    assert error_type(response) == "sequence/context_invalid"


def test_continuing_after_the_deadline_is_an_error(clock):
    first = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    clock["t"] += api.SEQUENCE_TTL + 1
    response = client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=first.headers["x-sequence-token"]))
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["type"] == "sequence/abandoned_late"
    assert error["last_valid_step"] == "plans" and error["steps_done"] == 1


def test_invalid_sequence_id_is_an_input_error(clock):
    response = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="kein gültiger name"))
    assert response.status_code == 422
    assert error_type(response) == "sequence/start_invalid"


def test_sequence_headers_without_configured_key_give_503(monkeypatch):
    monkeypatch.setattr(api, "SEQUENCE_KEY", None)
    response = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    assert response.status_code == 503
    assert error_type(response) == "sequence/not_configured"


def test_a_failed_step_does_not_advance_the_sequence(clock):
    first = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1"))
    token = first.headers["x-sequence-token"]
    failed = client.post(VERIFY, json={"config": {"groups": []}}, headers=headers(token=token))
    assert failed.status_code == 422 and error_type(failed) == "plan_error"
    assert "x-sequence-token" not in failed.headers
    retry = client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=token))   # altes Token gilt weiter
    assert retry.status_code == 200 and retry.headers["x-sequence-token"]


def test_interleaved_sequences_are_independent(clock):
    def run(ids):
        tokens = {i: client.post(PLANS, json={"config": CONFIG}, headers=headers(start=i)).headers["x-sequence-token"]
                  for i in ids}
        return {i: client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=t)).headers["x-sequence-token"]
                for i, t in tokens.items()}

    alone = {**run(["a"]), **run(["b"])}
    together = run(["a", "b"])
    assert together == alone


def test_a_custom_graph_replaces_the_default(clock, monkeypatch):
    monkeypatch.setattr(api, "SEQUENCE_GRAPH", SequenceGraph.from_pairs([("START", "plans"), ("plans", "ENDE")]))
    closed = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1", end=True))
    assert closed.status_code == 200 and "x-sequence-token" not in closed.headers
    first = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-2"))
    response = client.post(VERIFY, json={"config": CONFIG}, headers=headers(token=first.headers["x-sequence-token"]))
    assert response.status_code == 409
    assert response.json()["error"]["expected_next"] == ["ENDE"]


def test_ending_where_the_graph_does_not_allow_it_is_an_error(clock, monkeypatch):
    monkeypatch.setattr(
        api, "SEQUENCE_GRAPH",
        SequenceGraph.from_pairs([("START", "plans"), ("plans", "verify"), ("verify", "ENDE")]),
    )
    response = client.post(PLANS, json={"config": CONFIG}, headers=headers(start="lauf-1", end=True))
    assert response.status_code == 409
    assert error_type(response) == "sequence/end_invalid"


def test_openapi_documents_the_sequence_headers_and_the_conflict_response():
    schema = app.openapi()
    operations = [
        operation
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "summary" in operation
    ]
    assert len(operations) == 12
    names = {p["name"].lower() for p in schema["paths"][PLANS]["post"]["parameters"]}
    assert {"x-sequence-start", "x-sequence-token", "x-sequence-end"} <= names
    assert "409" in schema["paths"][PLANS]["post"]["responses"]
    assert "parameters" not in schema["paths"]["/api/v1/health"]["get"]
