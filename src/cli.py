"""Kommandozeile: ``python -m src.cli config.yaml [Optionen]``."""
from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .checks import plan_warnings
from .config import build_config, build_extension, load_config_file
from .extend import extend_plan, plan_from_json
from .firewall import CISCO_RETURN_MODES, FirewallOptions, render_firewall
from .models import FIREWALLS, FORMATS, GATEWAY_POSITIONS, STRATEGIES, Plan, PlanConfig, PlanError
from .planner import plan_subnets
from .render import render
from .roundtrip import check_roundtrip
from .stats import plan_statistics
from .verify import verify_plan


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
    parser.add_argument("--max-prefix", type=int, help="längste erlaubte Präfixlänge (Mindestblockgröße), z. B. 64 bei IPv6")
    parser.add_argument("--format", choices=FORMATS, default="table", help="Ausgabeformat (Standard: table)")
    parser.add_argument("-o", "--output", help="Plan in diese Datei schreiben statt auf stdout")
    parser.add_argument("--firewall", choices=FIREWALLS, default="none", help="Firewall-Regeln erzeugen")
    parser.add_argument("--firewall-output", help="Firewall-Regeln in diese Datei schreiben")
    parser.add_argument("--group-rules", action="store_true", help="Regeln mit gleicher Zielmenge zusammenfassen")
    parser.add_argument("--cisco-return", choices=CISCO_RETURN_MODES, default="none", help="Rückverkehr in Cisco-ACLs")
    parser.add_argument("--ascii-names", action="store_true", help="Namen in ACLs und Kommentaren nach ASCII wandeln")
    parser.add_argument("--log-drops", action="store_true", help="verworfene Pakete protokollieren")
    parser.add_argument("--icmpv6", default="", help="Kommagetrennte ICMPv6-Typen, die weitergeleitet werden")
    parser.add_argument("--no-idempotent", action="store_true", help="iptables-Skript ohne vorheriges Entfernen der Kette")
    parser.add_argument("--extend", metavar="PLAN_JSON", help="bestehenden Plan (JSON) um die Gruppen der Konfiguration ergänzen")
    parser.add_argument("--verify", action="store_true", help="Plan gegen die Sätze der Arbeit prüfen (Fehlercode 1 bei Verletzung)")
    parser.add_argument("--roundtrip", action="store_true", help="Regeln zurücklesen und mit der Zugriffsmatrix vergleichen")
    parser.add_argument("--warnings", action="store_true", help="Hinweise zu Adressbereich, Auslastung und Zugriffen ausgeben")
    parser.add_argument("--warn-threshold", type=float, default=80.0, help="Auslastungsschwelle in Prozent (Standard: 80)")
    parser.add_argument("--vpn-network", action="append", default=[], help="fremdes Netz, mit dem keine Überschneidung bestehen soll")
    parser.add_argument("--stats", action="store_true", help="Auslastungskennzahlen ausgeben")
    parser.add_argument("--compare", metavar="OTHER_CONFIG", help="Zugriffsrichtlinie mit einer zweiten Konfiguration vergleichen")
    return parser


def _write_file(path: str, text: str) -> None:
    try:
        Path(path).write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"Datei {path} konnte nicht geschrieben werden: {exc}") from exc


def _firewall_options(args: argparse.Namespace) -> FirewallOptions:
    types = tuple(t.strip() for t in args.icmpv6.split(",") if t.strip())
    return FirewallOptions(
        idempotent=not args.no_idempotent,
        group_rules=args.group_rules,
        cisco_return=args.cisco_return,
        ascii_names=args.ascii_names,
        log_drops=args.log_drops,
        icmpv6_types=types,
    )


def _make_plan(args: argparse.Namespace):
    overrides = {
        "base_network": args.base_network,
        "growth_factor": args.growth_factor,
        "allocation_strategy": args.allocation_strategy,
        "gateway_position": args.gateway_position,
        "max_prefix": args.max_prefix,
    }
    raw = load_config_file(args.config)
    if args.extend is None:
        cfg = build_config(raw, overrides)
        return cfg, plan_subnets(cfg), True
    if args.base_network is not None:
        raise PlanError("--base-network kann nicht mit --extend kombiniert werden")
    try:
        text = Path(args.extend).read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"Plan-Datei nicht lesbar: {exc}") from exc
    old = plan_from_json(text)
    overrides.pop("base_network")
    cfg, new_groups = build_extension(raw, [s.group for s in old.subnets], old.base_network, overrides)
    return cfg, extend_plan(old, new_groups, cfg), False


def _reports(args: argparse.Namespace, cfg: PlanConfig, plan: Plan, full_config: bool, options: FirewallOptions) -> int:
    """Zusatzberichte auf stderr; Rückgabe 1, wenn eine Prüfung fehlschlägt."""
    status = 0
    if args.verify:
        problems = verify_plan(plan, cfg if full_config else None)
        if problems:
            status = 1
            print("Prüfung fehlgeschlagen:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
        else:
            print("Prüfung bestanden: alle Eigenschaften aus den Sätzen der Arbeit sind erfüllt.", file=sys.stderr)
    if args.roundtrip:
        kinds = [args.firewall] if args.firewall != "none" else ["iptables", "nftables", "cisco"]
        for kind in kinds:
            result = check_roundtrip(plan, kind, options)
            if result.ok:
                print(f"Rückübersetzung {kind}: P' = P, Standard ist Verwerfen.", file=sys.stderr)
            else:
                status = 1
                print(
                    f"Rückübersetzung {kind} fehlgeschlagen: {len(result.missing)} fehlen, "
                    f"{len(result.extra)} zusätzlich, Default-Deny: {result.default_deny}",
                    file=sys.stderr,
                )
    if args.warnings:
        foreign = [ipaddress.ip_network(n, strict=False) for n in _checked_networks(args.vpn_network)]
        for w in plan_warnings(plan, cfg, args.warn_threshold, foreign, args.firewall, args.cisco_return):
            print(f"Warnung: {w}", file=sys.stderr)
    if args.stats:
        if not full_config:
            raise PlanError("--stats ist mit --extend nicht verfügbar")
        stats = plan_statistics(plan, cfg)
        print(
            f"Mittlere Blockauslastung: {stats.mean_utilization:.3f} (Minimum {stats.min_utilization:.3f}), "
            f"belegt {stats.allocated}, Bedarf {stats.required}, interner Verschnitt {stats.internal_waste}",
            file=sys.stderr,
        )
    return status


def _checked_networks(values: Sequence[str]) -> List[str]:
    for value in values:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise PlanError(f"--vpn-network {value!r} ist ungültig: {exc}") from exc
    return list(values)


def _compare(args: argparse.Namespace, plan: Plan) -> None:
    try:
        from .policy import compare_policies, format_comparison
    except ImportError as exc:
        raise PlanError(
            "Für --compare wird das Paket 'subgraph' benötigt (pip install, siehe pyproject.toml)"
        ) from exc
    other = plan_subnets(build_config(load_config_file(args.compare)))
    print(format_comparison(compare_policies(plan, other)), file=sys.stderr)


def _run(args: argparse.Namespace) -> int:
    wants_rules = args.firewall != "none"
    if wants_rules and args.format != "table" and args.output is None and args.firewall_output is None:
        raise PlanError(
            f"Bei --format {args.format} und --firewall muss --output oder --firewall-output angegeben werden"
        )

    cfg, plan, full_config = _make_plan(args)
    options = _firewall_options(args)

    parts: List[str] = []
    rendered = render(plan, args.format)
    if args.output is None:
        parts.append(rendered)
    else:
        _write_file(args.output, rendered)

    if wants_rules:
        rules = render_firewall(plan, args.firewall, options)
        if args.firewall_output is None:
            parts.append(rules)
        else:
            _write_file(args.firewall_output, rules)

    if parts:
        sys.stdout.write("\n\n".join(parts) + "\n")

    status = _reports(args, cfg, plan, full_config, options)
    if args.compare:
        _compare(args, plan)
    return status


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except PlanError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - dünner Einstiegspunkt
    sys.exit(main(sys.argv[1:]))
