"""Rückübersetzung als Test (Ausblick, "Rückübersetzung als Test").

Die erzeugten Regeln werden wieder eingelesen und die daraus rekonstruierte Menge P' der
Zugriffspaare mit P verglichen. Gilt immer P' = P (und das Regelwerk verwirft den Rest), ist
der Generator korrekt im Sinne von Satz "Default-Deny-Korrektheit".
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Set, Tuple

from .access import policy_pairs
from .firewall import FirewallOptions, render_firewall
from .models import IPNetwork, Plan, PlanError

NetPair = Tuple[IPNetwork, IPNetwork]

_SET_RE = r"(\{[^}]*\}|\S+)"
_NFT_RE = re.compile(rf"\bip6? saddr {_SET_RE} ip6? daddr {_SET_RE} accept\b")


@dataclass(frozen=True)
class ParsedRules:
    """Aus einem Regelwerk gelesene Freigaben."""

    pairs: FrozenSet[NetPair]  # neue Verbindungen (Quelle, Ziel)
    returns: FrozenSet[NetPair]  # nur Rückverkehr (Cisco ``established``)
    default_deny: bool  # alles Übrige wird verworfen


@dataclass(frozen=True)
class RoundtripResult:
    ok: bool
    missing: FrozenSet[NetPair]  # in P, aber nicht im Regelwerk
    extra: FrozenSet[NetPair]  # im Regelwerk, aber nicht in P
    default_deny: bool
    returns: FrozenSet[NetPair]


def expected_pairs(plan: Plan) -> FrozenSet[NetPair]:
    """P als Menge von Netzpaaren (Quellnetz, Zielnetz)."""
    nets = {s.group: s.network for s in plan.subnets}
    return frozenset((nets[a], nets[b]) for a, b in policy_pairs(plan))


def _nets(token: str) -> List[IPNetwork]:
    token = token.strip()
    if token.startswith("{"):
        parts = [p.strip() for p in token.strip("{}").split(",") if p.strip()]
    else:
        parts = [token]
    try:
        return [ipaddress.ip_network(p) for p in parts]
    except ValueError as exc:
        raise PlanError(f"Ungültiges Netz im Regelwerk: {exc}") from exc


def _product(sources: List[IPNetwork], targets: List[IPNetwork]) -> Set[NetPair]:
    return {(s, t) for s in sources for t in targets}


def parse_iptables(text: str) -> ParsedRules:
    sets: Dict[str, List[IPNetwork]] = {}
    pairs: Set[NetPair] = set()
    chain_rules: List[str] = []
    jumps_in = False
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"ipset add (\S+) (\S+)$", line)
        if m:
            sets.setdefault(m.group(1), []).extend(_nets(m.group(2)))
            continue
        if re.match(r"ip6?tables -I FORWARD 1 -j SUBNET_ACL$", line):
            jumps_in = True
            continue
        m = re.match(r"ip6?tables -A SUBNET_ACL (.*)$", line)
        if not m:
            continue
        rule = m.group(1)
        chain_rules.append(rule)
        direct = re.match(r"-s (\S+) -d (\S+) .*-j ACCEPT$", rule)
        grouped = re.match(r"-m set --match-set (\S+) src -m set --match-set (\S+) dst .*-j ACCEPT$", rule)
        if direct:
            pairs |= _product(_nets(direct.group(1)), _nets(direct.group(2)))
        elif grouped:
            src, dst = grouped.group(1), grouped.group(2)
            if src not in sets or dst not in sets:
                raise PlanError(f"Regelwerk verweist auf unbekannte ipset-Menge {src!r}/{dst!r}")
            pairs |= _product(sets[src], sets[dst])
    default_deny = bool(chain_rules) and chain_rules[-1] == "-j DROP" and jumps_in
    return ParsedRules(frozenset(pairs), frozenset(), default_deny)


def parse_nftables(text: str) -> ParsedRules:
    pairs: Set[NetPair] = set()
    for line in text.splitlines():
        m = _NFT_RE.search(line)
        if m:
            pairs |= _product(_nets(m.group(1)), _nets(m.group(2)))
    default_deny = "policy drop;" in text
    return ParsedRules(frozenset(pairs), frozenset(), default_deny)


def _cisco_net(tokens: List[str], i: int, v4: bool) -> Tuple[IPNetwork, int]:
    if v4:
        return ipaddress.ip_network(f"{tokens[i]}/{tokens[i + 1]}"), i + 2
    return ipaddress.ip_network(tokens[i]), i + 1


def parse_cisco(text: str) -> ParsedRules:
    objects: Dict[str, List[IPNetwork]] = {}
    pairs: Set[NetPair] = set()
    returns: Set[NetPair] = set()
    current_object = None
    in_acl = False
    acl_closed: List[bool] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("!") or not line.strip():
            continue
        stripped = line.strip()
        if line.startswith("object-group network "):
            current_object = stripped.split()[2]
            objects[current_object] = []
            in_acl = False
            continue
        if line.startswith(("ip access-list extended ", "ipv6 access-list ")):
            current_object = None
            in_acl = True
            acl_closed.append(False)
            continue
        if line.startswith("interface "):
            current_object = None
            in_acl = False
            continue
        if current_object is not None and line.startswith(" "):
            a, mask = stripped.split()
            objects[current_object].append(ipaddress.ip_network(f"{a}/{mask}"))
            continue
        if not in_acl or not line.startswith(" "):
            continue
        tokens = stripped.split()
        if tokens[0] == "remark":
            continue
        if tokens[0] == "deny":
            if tokens[1:3] in (["ip", "any"], ["ipv6", "any"]):
                acl_closed[-1] = True
            continue
        if tokens[0] != "permit":
            raise PlanError(f"Unbekannte Cisco-Zeile: {stripped!r}")
        proto = tokens[1]
        v4 = proto in ("ip", "tcp") and "." in tokens[2]
        try:
            src, i = _cisco_net(tokens, 2, v4)
            if tokens[i] == "object-group":
                dsts = objects[tokens[i + 1]]
                i += 2
            else:
                dst, i = _cisco_net(tokens, i, v4)
                dsts = [dst]
        except (ValueError, KeyError, IndexError) as exc:
            raise PlanError(f"Cisco-Zeile nicht lesbar: {stripped!r}") from exc
        found = {(src, d) for d in dsts}
        if proto == "tcp" and tokens[i:] == ["established"]:
            returns |= found
        else:
            pairs |= found
    return ParsedRules(frozenset(pairs), frozenset(returns), bool(acl_closed) and all(acl_closed))


def parse_rules(text: str, kind: str) -> ParsedRules:
    parsers = {"iptables": parse_iptables, "nftables": parse_nftables, "cisco": parse_cisco}
    if kind not in parsers:
        raise PlanError(f"Unbekanntes Firewall-System {kind!r}, erlaubt: {sorted(parsers)}")
    return parsers[kind](text)


def check_roundtrip(plan: Plan, kind: str, options: FirewallOptions = FirewallOptions()) -> RoundtripResult:
    """Erzeugt die Regeln, liest sie zurück und vergleicht P' mit P."""
    parsed = parse_rules(render_firewall(plan, kind, options), kind)
    want = expected_pairs(plan)
    missing = want - parsed.pairs
    extra = parsed.pairs - want
    return RoundtripResult(not missing and not extra and parsed.default_deny, missing, extra, parsed.default_deny, parsed.returns)
