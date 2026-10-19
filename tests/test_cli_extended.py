import json
from pathlib import Path

import pytest

from src.cli import main
from src.config import build_config, load_config_file
from src.models import Group, PlanConfig
from src.planner import plan_subnets
from src.render import render

pytestmark = pytest.mark.integration

TEXT = (
    "base_network: 10.0.0.0/24\n"
    "groups:\n"
    "  - {name: A, hosts: 50, access: [B]}\n"
    "  - {name: B, hosts: 10}\n"
)


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


@pytest.fixture
def config(tmp_path):
    return write(tmp_path, "c.yaml", TEXT)


def test_verify_ok_and_roundtrip(config, capsys):
    assert main([config, "--verify", "--roundtrip"]) == 0
    err = capsys.readouterr().err
    assert "Prüfung bestanden" in err and err.count("P' = P") == 3


def test_roundtrip_single_system_with_options(config, capsys):
    assert main([config, "--firewall", "cisco", "--cisco-return", "established", "--group-rules",
                 "--ascii-names", "--log-drops", "--roundtrip"]) == 0
    captured = capsys.readouterr()
    assert "object-group" in captured.out and captured.err.count("Rückübersetzung") == 1


def test_roundtrip_and_verify_failure_exit_codes(config, capsys, monkeypatch):
    import src.cli as cli
    monkeypatch.setattr(cli, "verify_plan", lambda plan, cfg: ["(K3) kaputt"])
    assert main([config, "--verify"]) == 1
    assert "kaputt" in capsys.readouterr().err
    from src.roundtrip import RoundtripResult
    bad = RoundtripResult(False, frozenset({1}), frozenset(), True, frozenset())
    monkeypatch.setattr(cli, "check_roundtrip", lambda plan, kind, opts: bad)
    assert main([config, "--roundtrip", "--firewall", "nftables"]) == 1
    assert "fehlgeschlagen" in capsys.readouterr().err


def test_warnings_and_stats(config, capsys):
    assert main([config, "--warnings", "--warn-threshold", "10", "--vpn-network", "10.0.0.0/8",
                 "--firewall", "cisco", "--stats"]) == 0
    err = capsys.readouterr().err
    assert "Schwellwert" in err and "fremden Netz" in err and "zustandslos" in err
    assert "Mittlere Blockauslastung" in err


def test_invalid_vpn_network(config, capsys):
    assert main([config, "--warnings", "--vpn-network", "kein-netz"]) == 1
    assert "--vpn-network" in capsys.readouterr().err


def test_max_prefix_override_and_icmpv6(tmp_path, capsys):
    cfg = write(tmp_path, "v6.yaml", "base_network: 2001:db8::/48\ngroups:\n  - {name: A, hosts: 10}\n")
    assert main([cfg, "--max-prefix", "64", "--format", "json", "--firewall", "nftables",
                 "--firewall-output", str(tmp_path / "r.nft"), "--icmpv6", "packet-too-big, nd-neighbor-advert"]) == 0
    assert json.loads(capsys.readouterr().out)["subnets"][0]["network"] == "2001:db8::/64"
    assert "icmpv6 type { packet-too-big, nd-neighbor-advert } accept" in (tmp_path / "r.nft").read_text()
    assert main([cfg, "--icmpv6", "bad type", "--firewall", "nftables"]) == 1
    assert "Ungültiger ICMPv6-Typ" in capsys.readouterr().err


def test_icmpv6_on_ipv4_is_error(config, capsys):
    assert main([config, "--firewall", "nftables", "--icmpv6", "packet-too-big"]) == 1
    assert "nur bei einem IPv6" in capsys.readouterr().err


def test_no_idempotent_flag(config, capsys):
    assert main([config, "--firewall", "iptables", "--no-idempotent"]) == 0
    assert "-D FORWARD" not in capsys.readouterr().out


def test_extend_flow(tmp_path, config, capsys):
    plan_file = tmp_path / "plan.json"
    assert main([config, "--format", "json", "-o", str(plan_file)]) == 0
    new = write(tmp_path, "new.yaml", "groups:\n  - {name: C, hosts: 20, access: [A]}\n")
    capsys.readouterr()
    assert main([new, "--extend", str(plan_file), "--verify", "--format", "json"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert [s["group"] for s in data["subnets"]] == ["A", "B", "C"]
    assert data["subnets"][0]["network"] == "10.0.0.0/25"
    assert "Prüfung bestanden" in captured.err


def test_extend_errors(tmp_path, config, capsys):
    plan_file = tmp_path / "plan.json"
    main([config, "--format", "json", "-o", str(plan_file)])
    new = write(tmp_path, "new.yaml", "groups:\n  - {name: C, hosts: 20}\n")
    assert main([new, "--extend", str(plan_file), "--base-network", "10.1.0.0/24"]) == 1
    assert main([new, "--extend", str(tmp_path / "fehlt.json")]) == 1
    assert main([new, "--extend", str(plan_file), "--stats"]) == 1
    assert "--stats ist mit --extend nicht verfügbar" in capsys.readouterr().err


def test_compare(tmp_path, config, capsys):
    other = write(tmp_path, "o.yaml", TEXT.replace("access: [B]", "access: [B]").replace("{name: B, hosts: 10}", "{name: B, hosts: 10, access: [A]}"))
    assert main([config, "--compare", other]) == 0
    err = capsys.readouterr().err
    assert "A ist in B enthalten" in err and "Empfehlung: B behalten" in err


def test_compare_without_subgraph_dependency(config, capsys, monkeypatch):
    import builtins
    import sys
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "subgraph" or name.endswith(".policy"):
            raise ImportError("kein subgraph")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    sys.modules.pop("src.policy", None)
    try:
        assert main([config, "--compare", config]) == 1
    finally:
        monkeypatch.undo()
    assert "subgraph" in capsys.readouterr().err
