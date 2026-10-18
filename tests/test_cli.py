import json
from pathlib import Path

import pytest

from src.cli import main
from src.config import build_config, load_config_file
from src.planner import plan_subnets

pytestmark = pytest.mark.integration

CONFIG_TEXT = (
    "base_network: 10.0.0.0/24\n"
    "groups:\n"
    "  - {name: A, hosts: 50, access: [B]}\n"
    "  - {name: B, hosts: 10}\n"
)


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(CONFIG_TEXT, encoding="utf-8")
    return str(path)


def test_table_to_stdout(config, capsys):
    assert main([config]) == 0
    captured = capsys.readouterr()
    assert "10.0.0.0/25" in captured.out
    assert captured.out.endswith("\n")
    assert captured.err == ""


def test_json_and_csv_to_stdout(config, capsys):
    assert main([config, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["base_network"] == "10.0.0.0/24"
    assert main([config, "--format", "csv"]) == 0
    assert capsys.readouterr().out.startswith("group,vlan_id,network")


def test_overrides_are_applied(config, capsys):
    argv = [
        config, "--base-network", "172.16.0.0/16", "--growth-factor", "1.0",
        "--strategy", "fixed", "--gateway", "none", "--format", "json",
    ]
    assert main(argv) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["base_network"] == "172.16.0.0/16"
    assert data["subnets"][0]["gateway"] is None
    assert {s["network"].split("/")[1] for s in data["subnets"]} == {"26"}


def test_plan_is_written_to_output_file(config, tmp_path, capsys):
    target = tmp_path / "plan.csv"
    assert main([config, "--format", "csv", "-o", str(target)]) == 0
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "")
    assert target.read_text(encoding="utf-8").startswith("group,")


def test_firewall_rules_follow_the_table_on_stdout(config, capsys):
    assert main([config, "--firewall", "iptables"]) == 0
    out = capsys.readouterr().out
    assert out.index("Freie Bereiche") < out.index("iptables -N SUBNET_ACL")


def test_firewall_rules_to_own_file(config, tmp_path, capsys):
    rules = tmp_path / "rules.nft"
    assert main([config, "--firewall", "nftables", "--firewall-output", str(rules)]) == 0
    assert "nftables" not in capsys.readouterr().out
    assert "table inet subnet_acl" in rules.read_text(encoding="utf-8")


def test_json_with_firewall_needs_a_target(config, capsys):
    assert main([config, "--format", "json", "--firewall", "cisco"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--output oder --firewall-output" in captured.err


def test_json_with_firewall_when_plan_goes_to_file(config, tmp_path, capsys):
    target = tmp_path / "p.json"
    assert main([config, "--format", "json", "-o", str(target), "--firewall", "cisco"]) == 0
    assert "ip access-list extended" in capsys.readouterr().out
    json.loads(target.read_text(encoding="utf-8"))


def test_json_with_firewall_when_rules_go_to_file(config, tmp_path, capsys):
    rules = tmp_path / "r.txt"
    argv = [config, "--format", "json", "--firewall", "cisco", "--firewall-output", str(rules)]
    assert main(argv) == 0
    json.loads(capsys.readouterr().out)
    assert "ip access-list extended" in rules.read_text(encoding="utf-8")


def test_plan_error_returns_exit_code_1(config, capsys):
    assert main([config, "--growth-factor", "0.5"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("Fehler: ")


def test_missing_config_file(tmp_path, capsys):
    assert main([str(tmp_path / "missing.yaml")]) == 1
    assert "nicht lesbar" in capsys.readouterr().err


def test_unwritable_output_path(config, tmp_path, capsys):
    assert main([config, "-o", str(tmp_path)]) == 1  # ein Verzeichnis ist keine Datei
    assert "konnte nicht geschrieben werden" in capsys.readouterr().err


def test_argparse_rejects_unknown_format(config, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main([config, "--format", "xml"])
    assert excinfo.value.code == 2


def test_example_configuration_is_valid():
    example = Path(__file__).resolve().parent.parent / "examples" / "config.example.yaml"
    plan = plan_subnets(build_config(load_config_file(example)))
    assert len(plan.subnets) == 5
    assert next(s for s in plan.subnets if s.group == "Server").vlan_id == 100
