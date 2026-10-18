"""Kommandozeile: ``python -m src.cli config.yaml [Optionen]``."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .config import build_config, load_config_file
from .firewall import render_firewall
from .models import FIREWALLS, FORMATS, GATEWAY_POSITIONS, STRATEGIES, PlanError
from .planner import plan_subnets
from .render import render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subnetplan",
        description="Berechnet Subnetze für Gruppen und erzeugt optional Firewall-Regeln.",
    )
    parser.add_argument("config", help="Konfigurationsdatei (.yaml/.yml/.json)")
    parser.add_argument("--base-network", help="überschreibt base_network, z. B. 10.20.0.0/16")
    parser.add_argument("--growth-factor", type=float, help="überschreibt growth_factor")
    parser.add_argument("--strategy", dest="allocation_strategy", choices=STRATEGIES)
    parser.add_argument("--gateway", dest="gateway_position", choices=GATEWAY_POSITIONS)
    parser.add_argument("--format", choices=FORMATS, default="table", help="Ausgabeformat (Standard: table)")
    parser.add_argument("-o", "--output", help="Plan in diese Datei schreiben statt auf stdout")
    parser.add_argument("--firewall", choices=FIREWALLS, default="none", help="Firewall-Regeln erzeugen")
    parser.add_argument("--firewall-output", help="Firewall-Regeln in diese Datei schreiben")
    return parser


def _write_file(path: str, text: str) -> None:
    try:
        Path(path).write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"Datei {path} konnte nicht geschrieben werden: {exc}") from exc


def _run(args: argparse.Namespace) -> None:
    wants_rules = args.firewall != "none"
    if wants_rules and args.format != "table" and args.output is None and args.firewall_output is None:
        raise PlanError(
            f"Bei --format {args.format} und --firewall muss --output oder --firewall-output angegeben werden"
        )

    overrides = {
        "base_network": args.base_network,
        "growth_factor": args.growth_factor,
        "allocation_strategy": args.allocation_strategy,
        "gateway_position": args.gateway_position,
    }
    cfg = build_config(load_config_file(args.config), overrides)
    plan = plan_subnets(cfg)

    parts: List[str] = []
    rendered = render(plan, args.format)
    if args.output is None:
        parts.append(rendered)
    else:
        _write_file(args.output, rendered)

    if wants_rules:
        rules = render_firewall(plan, args.firewall)
        if args.firewall_output is None:
            parts.append(rules)
        else:
            _write_file(args.firewall_output, rules)

    if parts:
        sys.stdout.write("\n\n".join(parts) + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _run(args)
    except PlanError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - dünner Einstiegspunkt
    sys.exit(main(sys.argv[1:]))
