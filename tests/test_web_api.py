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

    assert len(operations) == 12
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


def _ports_config(ports):
    return {
        "base_network": "10.0.0.0/24",
        "groups": [
            {"name": "A", "hosts": 100, "access": [{"to": "B", "ports": ports}]},
            {"name": "B", "hosts": 100},
        ],
    }


def test_openapi_documents_compare_services_and_service_mismatch():
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/plans/compare-services"]["post"]
    assert operation["summary"] and operation["description"]
    assert operation["responses"]["422"]["description"]
    assert "service_mismatch" in schema["components"]["schemas"]["RoundtripCheck"]["properties"]


def test_plan_response_contains_services_only_when_restricted():
    plain = client.post("/api/v1/plans", json={"config": CONFIG}).json()
    assert all(not item.get("services") for item in plain["subnets"])

    plan = client.post("/api/v1/plans", json={"config": _ports_config(["tcp/443", "tcp/22"])})
    assert plan.status_code == 200
    by_group = {item["group"]: item for item in plan.json()["subnets"]}
    assert by_group["A"]["services"] == {"B": ["tcp/22", "tcp/443"]}
    assert not by_group["B"].get("services")


def test_roundtrip_reports_empty_service_mismatch_for_all_firewalls():
    config = _ports_config(["tcp/22", "tcp/8000-8099", "udp/53"])
    response = client.post("/api/v1/plans/roundtrip", json={"config": config})
    assert response.status_code == 200
    results = response.json()["results"]
    assert set(results) == {"iptables", "nftables", "cisco"}
    for result in results.values():
        assert result["ok"] is True
        assert result["service_mismatch"] == []


def test_firewall_rules_contain_ports():
    rules = client.post(
        "/api/v1/plans/firewall",
        json={"config": _ports_config(["tcp/22", "tcp/8000-8099"]), "firewall": "iptables"},
    ).json()["rules"]
    assert "--dport 22" in rules
    assert "8000:8099" in rules


def test_verdict_with_service():
    body = {
        "config": _ports_config(["tcp/443"]),
        "source": "10.0.0.2",
        "target": "10.0.0.130",
        "ingress_group": "A",
    }
    allowed = client.post("/api/v1/plans/verdict", json={**body, "service": "tcp/443"}).json()
    denied = client.post("/api/v1/plans/verdict", json={**body, "service": "tcp/80"}).json()
    assert allowed["firewall"] == "accept"
    assert allowed["cisco"] == "accept"
    assert denied["firewall"] == "drop"
    assert denied["cisco"] == "drop"


def test_compare_services_equal():
    config = _ports_config(["tcp/22", "tcp/443"])
    response = client.post(
        "/api/v1/plans/compare-services", json={"config_a": config, "config_b": config}
    )
    assert response.status_code == 200
    assert response.json() == {
        "relation": "equal",
        "a_in_b": True,
        "b_in_a": True,
        "differences": [],
    }


def test_compare_services_subset_and_differences():
    narrow = _ports_config(["tcp/443"])
    wide = _ports_config(["tcp/443", "tcp/8000-8099"])
    body = client.post(
        "/api/v1/plans/compare-services", json={"config_a": narrow, "config_b": wide}
    ).json()
    assert body["relation"] == "a_in_b"
    assert body["a_in_b"] is True and body["b_in_a"] is False
    assert body["differences"] == [
        {"source": "A", "target": "B", "a": ["tcp/443"], "b": ["tcp/443", "tcp/8000-8099"]}
    ]

    reverse = client.post(
        "/api/v1/plans/compare-services", json={"config_a": wide, "config_b": narrow}
    ).json()
    assert reverse["relation"] == "b_in_a"


def test_compare_services_unrestricted_contains_restricted():
    restricted = _ports_config(["tcp/22"])
    unrestricted = {
        "base_network": "10.0.0.0/24",
        "groups": [
            {"name": "A", "hosts": 100, "access": ["B"]},
            {"name": "B", "hosts": 100},
        ],
    }
    body = client.post(
        "/api/v1/plans/compare-services",
        json={"config_a": restricted, "config_b": unrestricted},
    ).json()
    assert body["relation"] == "a_in_b"
    assert body["differences"][0]["b"] == ["all"]
    assert body["differences"][0]["a"] == ["tcp/22"]


def test_compare_services_incomparable_and_missing_pair():
    a = _ports_config(["tcp/22"])
    b = _ports_config(["tcp/443"])
    assert client.post(
        "/api/v1/plans/compare-services", json={"config_a": a, "config_b": b}
    ).json()["relation"] == "incomparable"

    no_access = {
        "base_network": "10.0.0.0/24",
        "groups": [{"name": "A", "hosts": 100}, {"name": "B", "hosts": 100}],
    }
    body = client.post(
        "/api/v1/plans/compare-services", json={"config_a": a, "config_b": no_access}
    ).json()
    assert body["relation"] == "b_in_a"
    assert body["differences"] == [{"source": "A", "target": "B", "a": ["tcp/22"], "b": []}]


def test_compare_services_invalid_config_returns_plan_error():
    response = client.post(
        "/api/v1/plans/compare-services",
        json={"config_a": _ports_config(["tcp/99999"]), "config_b": CONFIG},
    )
    assert response.status_code == 422
    assert response.json()["error"]["type"] == "plan_error"
