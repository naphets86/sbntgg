import pytest
from fastapi.testclient import TestClient

from web.api import app

pytestmark = pytest.mark.integration

CONFIG = {
    "base_network": "10.0.0.0/24",
    "groups": [
        {"name": "A", "hosts": 50, "access": ["B"]},
        {"name": "B", "hosts": 10},
    ],
}

client = TestClient(app)


def test_openapi_has_descriptive_operations_and_examples():
    schema = app.openapi()
    operations = [
        operation
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "summary" in operation
    ]

    assert len(operations) == 11
    assert all(operation.get("description") for operation in operations)
    assert "application/json" in schema["paths"]["/api/v1/plans"]["post"]["requestBody"]["content"]
    assert schema["paths"]["/api/v1/plans"]["post"]["responses"]["422"]["description"]
    assert schema["paths"]["/api/v1/plans/compare"]["post"]["responses"]["503"]["description"]


def test_meta_and_plan_analysis_routes():
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    options = client.get("/api/v1/options").json()
    assert "nftables" in options["firewalls"]

    plan = client.post("/api/v1/plans", json={"config": CONFIG})
    assert plan.status_code == 200
    assert [item["group"] for item in plan.json()["subnets"]] == ["A", "B"]

    verified = client.post("/api/v1/plans/verify", json={"config": CONFIG}).json()
    assert verified["valid"] is True
    stats = client.post("/api/v1/plans/stats", json={"config": CONFIG}).json()
    assert stats["allocated"] > 0
    warnings = client.post(
        "/api/v1/plans/warnings", json={"config": CONFIG, "vpn_networks": ["10.0.0.0/8"]}
    ).json()
    assert any("fremden Netz" in warning for warning in warnings["warnings"])


def test_firewall_roundtrip_and_verdict_routes():
    firewall = client.post(
        "/api/v1/plans/firewall",
        json={"config": CONFIG, "firewall": "nftables", "options": {"group_rules": True}},
    )
    assert firewall.status_code == 200
    assert "policy drop" in firewall.json()["rules"]

    roundtrip = client.post("/api/v1/plans/roundtrip", json={"config": CONFIG}).json()
    assert all(result["ok"] for result in roundtrip["results"].values())

    verdict = client.post(
        "/api/v1/plans/verdict",
        json={"config": CONFIG, "source": "10.0.0.2", "target": "10.0.0.130", "ingress_group": "A"},
    ).json()
    assert verdict == {"firewall": "accept", "source_group": "A", "target_group": "B", "cisco": "accept"}


def test_extend_and_compare_routes():
    original = client.post("/api/v1/plans", json={"config": CONFIG}).json()
    extension = client.post(
        "/api/v1/plans/extend",
        json={
            "plan": original,
            "config": {"groups": [{"name": "C", "hosts": 20, "access": ["A"]}]},
        },
    )
    assert extension.status_code == 200
    assert {item["group"] for item in extension.json()["subnets"]} == {"A", "B", "C"}

    comparison = client.post(
        "/api/v1/plans/compare", json={"config_a": CONFIG, "config_b": CONFIG}
    )
    assert comparison.status_code == 200
    assert comparison.json()["relation"] == "equal"


def test_domain_errors_have_consistent_json_response():
    response = client.post("/api/v1/plans", json={"config": {"groups": []}})
    assert response.status_code == 422
    assert response.json()["error"]["type"] == "plan_error"
    assert "base_network" in response.json()["error"]["message"]
