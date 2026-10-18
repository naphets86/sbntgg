import ipaddress
import json

import pytest

from src.config import build_config, load_config_file
from src.models import PlanError

pytestmark = pytest.mark.unit


def cfg_dict(**overrides):
    data = {
        "base_network": "10.0.0.0/24",
        "groups": [
            {"name": "A", "hosts": 50, "access": ["B"]},
            {"name": "B", "hosts": 10},
        ],
    }
    data.update(overrides)
    return data


def one_group(**fields):
    return cfg_dict(groups=[{"name": "A", "hosts": 1, **fields}])


def test_valid_config_uses_defaults():
    cfg = build_config(cfg_dict())
    assert cfg.base_network == ipaddress.ip_network("10.0.0.0/24")
    assert cfg.growth_factor == 1.25
    assert cfg.allocation_strategy == "vlsm"
    assert cfg.gateway_position == "first"
    assert cfg.groups[0].access == ("B",)
    assert cfg.groups[1].access == ()
    assert cfg.groups[1].priority == 0
    assert cfg.groups[1].vlan_id is None


def test_integer_growth_factor_is_converted_to_float():
    cfg = build_config(cfg_dict(growth_factor=2))
    assert cfg.growth_factor == 2.0
    assert isinstance(cfg.growth_factor, float)


@pytest.mark.parametrize("raw", [None, [1], "text", 5])
def test_config_must_be_a_mapping(raw):
    with pytest.raises(PlanError, match="Mapping"):
        build_config(raw)


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(PlanError, match="Unbekannte Schlüssel"):
        build_config(cfg_dict(typo=1))


def test_missing_base_network():
    raw = cfg_dict()
    del raw["base_network"]
    with pytest.raises(PlanError, match="base_network"):
        build_config(raw)


@pytest.mark.parametrize("bad", ["nonsense", "10.0.0.1/24", None, 12])
def test_invalid_base_network(bad):
    with pytest.raises(PlanError, match="ungültig"):
        build_config(cfg_dict(base_network=bad))


@pytest.mark.parametrize("bad", [0.9, "1.2", True, float("nan"), float("inf")])
def test_invalid_growth_factor(bad):
    with pytest.raises(PlanError, match="growth_factor"):
        build_config(cfg_dict(growth_factor=bad))


def test_invalid_strategy():
    with pytest.raises(PlanError, match="allocation_strategy"):
        build_config(cfg_dict(allocation_strategy="random"))


def test_invalid_gateway_position():
    with pytest.raises(PlanError, match="gateway_position"):
        build_config(cfg_dict(gateway_position="middle"))


@pytest.mark.parametrize("bad", [None, [], "x", {"name": "A"}])
def test_groups_must_be_a_non_empty_list(bad):
    with pytest.raises(PlanError, match="groups"):
        build_config(cfg_dict(groups=bad))


def test_group_must_be_a_mapping():
    with pytest.raises(PlanError, match="Mapping erwartet"):
        build_config(cfg_dict(groups=["A"]))


def test_group_with_unknown_key():
    with pytest.raises(PlanError, match="unbekannte Schlüssel"):
        build_config(one_group(foo=1))


@pytest.mark.parametrize("bad", [None, "", "   ", 5])
def test_group_name_missing_or_empty(bad):
    with pytest.raises(PlanError, match="'name'"):
        build_config(cfg_dict(groups=[{"name": bad, "hosts": 1}]))


@pytest.mark.parametrize("bad", ['Evil"; rm -rf /', "a\nb", "x;y", "$(id)"])
def test_group_name_with_forbidden_characters(bad):
    with pytest.raises(PlanError, match="unzulässige Zeichen"):
        build_config(cfg_dict(groups=[{"name": bad, "hosts": 1}]))


def test_group_name_allows_umlauts_and_is_stripped():
    cfg = build_config(cfg_dict(groups=[{"name": " Gäste-WLAN_1 ", "hosts": 1}]))
    assert cfg.groups[0].name == "Gäste-WLAN_1"


@pytest.mark.parametrize("bad", [None, 0, -3, 1.5, "10", True])
def test_invalid_hosts(bad):
    with pytest.raises(PlanError, match="hosts"):
        build_config(cfg_dict(groups=[{"name": "A", "hosts": bad}]))


@pytest.mark.parametrize("bad", [0, 4095, "10", 1.5, True])
def test_invalid_vlan_id(bad):
    with pytest.raises(PlanError, match="vlan_id"):
        build_config(one_group(vlan_id=bad))


def test_vlan_id_bounds_are_accepted():
    for vlan in (1, 4094):
        assert build_config(one_group(vlan_id=vlan)).groups[0].vlan_id == vlan


def test_invalid_priority():
    with pytest.raises(PlanError, match="priority"):
        build_config(one_group(priority=-1))


@pytest.mark.parametrize("bad", ["B", [1], {"B": 1}])
def test_invalid_access_type(bad):
    with pytest.raises(PlanError, match="'access'"):
        build_config(one_group(access=bad))


def test_duplicate_group_names():
    groups = [{"name": "A", "hosts": 1}, {"name": "A", "hosts": 2}]
    with pytest.raises(PlanError, match="Doppelte Gruppennamen"):
        build_config(cfg_dict(groups=groups))


def test_duplicate_vlan_ids():
    groups = [
        {"name": "A", "hosts": 1, "vlan_id": 5},
        {"name": "B", "hosts": 1, "vlan_id": 5},
    ]
    with pytest.raises(PlanError, match="Doppelte VLAN-IDs"):
        build_config(cfg_dict(groups=groups))


def test_access_refers_to_unknown_group():
    with pytest.raises(PlanError, match="unbekannte Gruppen"):
        build_config(one_group(access=["Ghost"]))


def test_overrides_replace_values_and_none_is_ignored():
    cfg = build_config(
        cfg_dict(),
        {"base_network": "192.168.0.0/16", "growth_factor": None, "allocation_strategy": "fixed"},
    )
    assert str(cfg.base_network) == "192.168.0.0/16"
    assert cfg.growth_factor == 1.25
    assert cfg.allocation_strategy == "fixed"


def test_load_yaml_file(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("base_network: 10.0.0.0/24\ngroups:\n  - {name: A, hosts: 5}\n", encoding="utf-8")
    assert load_config_file(path)["base_network"] == "10.0.0.0/24"


def test_load_json_file(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(cfg_dict()), encoding="utf-8")
    assert load_config_file(str(path))["groups"][0]["name"] == "A"


def test_load_missing_file(tmp_path):
    with pytest.raises(PlanError, match="nicht lesbar"):
        load_config_file(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "name, text",
    [("bad.yaml", "a: [1, 2\n"), ("bad.json", "{not json")],
)
def test_load_invalid_yaml_or_json(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PlanError, match="kein gültiges YAML/JSON"):
        load_config_file(path)
