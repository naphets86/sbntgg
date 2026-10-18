import csv
import io
import json
import re

import pytest

from src.config import build_config
from src.models import CSV_FIELDS, PlanError
from src.planner import plan_subnets
from src.render import render

pytestmark = pytest.mark.unit


def make_plan(**overrides):
    data = {
        "base_network": "10.0.0.0/24",
        "groups": [
            {"name": "A", "hosts": 50, "access": ["B"]},
            {"name": "B", "hosts": 10},
        ],
    }
    data.update(overrides)
    return plan_subnets(build_config(data))


def test_json_output():
    data = json.loads(render(make_plan(), "json"))
    assert data["base_network"] == "10.0.0.0/24"
    assert data["total_addresses"] == 256
    assert data["allocated_addresses"] == 144
    assert data["free_addresses"] == 112
    assert data["utilization_percent"] == 56.25
    assert data["free_ranges"] == ["10.0.0.144/28", "10.0.0.160/27", "10.0.0.192/26"]
    assert [s["group"] for s in data["subnets"]] == ["A", "B"]


def test_json_keeps_umlauts():
    plan = make_plan(groups=[{"name": "Gäste", "hosts": 5}])
    assert "Gäste" in render(plan, "json")


def test_csv_roundtrip_with_empty_gateway():
    text = render(make_plan(gateway_position="none"), "csv")
    assert not text.endswith("\n")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert tuple(rows[0].keys()) == CSV_FIELDS
    assert rows[0]["network"] == "10.0.0.0/25"
    assert rows[0]["gateway"] == ""
    assert rows[0]["access"] == "B"
    assert rows[1]["access"] == ""


def test_csv_joins_multiple_access_targets():
    groups = [
        {"name": "A", "hosts": 5, "access": ["B", "C"]},
        {"name": "B", "hosts": 5},
        {"name": "C", "hosts": 5},
    ]
    rows = list(csv.DictReader(io.StringIO(render(make_plan(groups=groups), "csv"))))
    assert rows[0]["access"] == "B;C"


def test_table_ipv4_content_and_layout():
    text = render(make_plan(), "table")
    assert "Netz/CIDR" in text
    assert "10.0.0.0/25" in text
    assert "10.0.0.2 - 10.0.0.126" in text
    assert "10.0.0.127" in text
    assert "Basisnetz: 10.0.0.0/24 (256 Adressen)" in text
    assert "Belegt: 144 (56.25 %), frei: 112" in text
    assert "Freie Bereiche: 10.0.0.144/28, 10.0.0.160/27, 10.0.0.192/26" in text
    assert all(line == line.rstrip() for line in text.splitlines())


def test_table_shows_dash_for_missing_gateway():
    text = render(make_plan(gateway_position="none"), "table")
    first_row = re.split(r"\s{2,}", text.splitlines()[2])
    assert first_row[4] == "-"


def test_table_ipv6_shows_dash_for_missing_broadcast():
    text = render(make_plan(base_network="2001:db8::/64", groups=[{"name": "A", "hosts": 5}]), "table")
    first_row = re.split(r"\s{2,}", text.splitlines()[2])
    assert "2001:db8::/" in first_row[2]
    assert first_row[6] == "-"


def test_table_without_free_space():
    text = render(make_plan(groups=[{"name": "G", "hosts": 200}]), "table")
    assert "Freie Bereiche: -" in text


def test_unknown_format():
    with pytest.raises(PlanError, match="Unbekanntes Format"):
        render(make_plan(), "xml")
