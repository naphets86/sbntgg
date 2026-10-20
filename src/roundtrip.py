"""Rückübersetzung als Test (Ausblick, "Rückübersetzung als Test").

Die erzeugten Regeln werden wieder eingelesen und die daraus rekonstruierte Menge P' der
Zugriffspaare mit P verglichen. Gilt immer P' = P (und das Regelwerk verwirft den Rest), ist
der Generator korrekt im Sinne von Satz "Default-Deny-Korrektheit".

Mit Protokollen und Ports (Kapitel "Erweiterung um Protokolle und Ports") wird zusätzlich je
Paar die Dienstmenge ``Sigma'`` aus den Regeln rekonstruiert und mit ``Sigma`` verglichen
(Satz "Default-Deny-Korrektheit mit Diensten").
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .access import policy_pairs, policy_services
from .firewall import FirewallOptions, render_firewall
from .models import IPNetwork, Plan, PlanError
from .ports import PORT_MAX, PORT_MIN, ServiceSet

NetPair = Tuple[IPNetwork, IPNetwork]

_SET_RE = r"(\{[^}]*\}|\S+)"
_NFT_RE = re.compile(rf"\bip6? saddr {_SET_RE} ip6? daddr {_SET_RE}(.*?)\baccept\b")
_COMMENT_RE = re.compile(r'-m comment --comment "[^"]*"')
_IPT_PROTO_RE = re.compile(r"-p (\S+)(?: --dport (\d+)(?::(\d+))?)?")
_NFT_PORTS_RE = re.compile(r"\b(tcp|udp) dport (\{[^}]*\}|\S+)")
_NFT_PROTO_RE = re.compile(r"meta l4proto (\S+)")
_FULL = (PORT_MIN, PORT_MAX)


@dataclass(frozen=True)
class ParsedRules:
    """Aus einem Regelwerk gelesene Freigaben."""

    pairs: FrozenSet[NetPair]  # neue Verbindungen (Quelle, Ziel)
    returns: FrozenSet[NetPair]  # nur Rückverkehr (Cisco ``established``)
    default_deny: bool  # alles Übrige wird verworfen
    # Dienstmenge je freigegebenem Paar (Vereinigung über alle Regeln des Paares)
    services: Dict[NetPair, ServiceSet] = field(default_factory=dict)


@dataclass(frozen=True)
class RoundtripResult:
    ok: bool
    missing: FrozenSet[NetPair]  # in P, aber nicht im Regelwerk
    extra: FrozenSet[NetPair]  # im Regelwerk, aber nicht in P
    default_deny: bool
    returns: FrozenSet[NetPair]
    service_mismatch: FrozenSet[NetPair] = frozenset()  # Paare mit abweichender Dienstmenge


def expected_pairs(plan: Plan) -> FrozenSet[NetPair]:
    """P als Menge von Netzpaaren (Quellnetz, Zielnetz)."""
    nets = {s.group: s.network for s in plan.subnets}
    return frozenset((nets[a], nets[b]) for a, b in policy_pairs(plan))


def expected_services(plan: Plan) -> Dict[NetPair, ServiceSet]:
    """Dienstmenge ``Sigma_ij`` je Paar von Netzen (ohne Beschränkung: alle Dienste)."""
    nets = {s.group: s.network for s in plan.subnets}
    return {(nets[a], nets[b]): sigma for (a, b), sigma in policy_services(plan).items()}


def _add_services(
    table: Dict[NetPair, ServiceSet], sources: List[IPNetwork], targets: List[IPNetwork], sigma: ServiceSet
) -> None:
    for pair in _product(sources, targets):
        table[pair] = table[pair].union(sigma) if pair in table else sigma


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


def _ipt_services(rest: str) -> ServiceSet:
    """Dienstmenge einer iptables-Regel aus dem Teil zwischen Ziel und ``-j ACCEPT``."""
    match = _IPT_PROTO_RE.search(_COMMENT_RE.sub("", rest))
    if match is None:
        return ServiceSet.everything()
    proto = match.group(1)
    if proto in ("tcp", "udp"):
        low = int(match.group(2)) if match.group(2) is not None else None
        if low is None:
            return ServiceSet(((proto, (_FULL,)),))
        high = int(match.group(3)) if match.group(3) is not None else low
        return ServiceSet(((proto, ((low, high),)),))
    if proto == "icmp":
        return ServiceSet(others=frozenset({"icmp"}))
    if proto in ("ipv6-icmp", "icmpv6"):
        return ServiceSet(others=frozenset({"icmpv6"}))
    raise PlanError(f"Unbekanntes Protokoll im Regelwerk: {proto!r}")


def parse_iptables(text: str) -> ParsedRules:
    sets: Dict[str, List[IPNetwork]] = {}
    pairs: Set[NetPair] = set()
    services: Dict[NetPair, ServiceSet] = {}
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
        direct = re.match(r"-s (\S+) -d (\S+)(.*)-j ACCEPT$", rule)
        grouped = re.match(r"-m set --match-set (\S+) src -m set --match-set (\S+) dst(.*)-j ACCEPT$", rule)
        if direct:
            sources, targets, rest = _nets(direct.group(1)), _nets(direct.group(2)), direct.group(3)
        elif grouped:
            src, dst = grouped.group(1), grouped.group(2)
            if src not in sets or dst not in sets:
                raise PlanError(f"Regelwerk verweist auf unbekannte ipset-Menge {src!r}/{dst!r}")
            sources, targets, rest = sets[src], sets[dst], grouped.group(3)
        else:
            continue
        pairs |= _product(sources, targets)
        _add_services(services, sources, targets, _ipt_services(rest))
    default_deny = bool(chain_rules) and chain_rules[-1] == "-j DROP" and jumps_in
    return ParsedRules(frozenset(pairs), frozenset(), default_deny, services)


def _nft_ports(token: str) -> Tuple[Tuple[int, int], ...]:
    """Ports aus ``22``, ``8000-8099`` oder ``{ 22, 443, 8000-8099 }``."""
    items = [p.strip() for p in token.strip("{}").split(",") if p.strip()]
    try:
        return tuple(
            (int(a), int(b)) for a, _, b in (item.partition("-") for item in items) for b in [b or a]
        )
    except ValueError as exc:
        raise PlanError(f"Ungültige Portangabe im Regelwerk: {token!r}") from exc


def _nft_services(rest: str) -> ServiceSet:
    """Dienstmenge einer nftables-Regel aus dem Teil zwischen Ziel und ``accept``."""
    ports = _NFT_PORTS_RE.search(rest)
    if ports is not None:
        return ServiceSet(((ports.group(1), _nft_ports(ports.group(2))),))
    proto = _NFT_PROTO_RE.search(rest)
    if proto is None:
        return ServiceSet.everything()
    name = proto.group(1)
    if name in ("tcp", "udp"):
        return ServiceSet(((name, (_FULL,)),))
    if name in ("icmp", "ipv6-icmp"):
        return ServiceSet(others=frozenset({"icmp" if name == "icmp" else "icmpv6"}))
    raise PlanError(f"Unbekanntes Protokoll im Regelwerk: {name!r}")


def parse_nftables(text: str) -> ParsedRules:
    pairs: Set[NetPair] = set()
    services: Dict[NetPair, ServiceSet] = {}
    for line in text.splitlines():
        m = _NFT_RE.search(line)
        if m:
            sources, targets = _nets(m.group(1)), _nets(m.group(2))
            pairs |= _product(sources, targets)
            _add_services(services, sources, targets, _nft_services(m.group(3)))
    default_deny = "policy drop;" in text
    return ParsedRules(frozenset(pairs), frozenset(), default_deny, services)


def _cisco_net(tokens: List[str], i: int, v4: bool) -> Tuple[IPNetwork, int]:
    if v4:
        return ipaddress.ip_network(f"{tokens[i]}/{tokens[i + 1]}"), i + 2
    return ipaddress.ip_network(tokens[i]), i + 1


def _cisco_port(tokens: List[str], i: int) -> Tuple[Optional[Tuple[int, int]], int]:
    """Optionaler Portoperator (``eq P`` oder ``range A B``) an Position ``i``."""
    if i < len(tokens) and tokens[i] == "eq":
        return (int(tokens[i + 1]), int(tokens[i + 1])), i + 2
    if i < len(tokens) and tokens[i] == "range":
        return (int(tokens[i + 1]), int(tokens[i + 2])), i + 3
    return None, i


def _cisco_sigma(proto: str, port: Optional[Tuple[int, int]], v4: bool) -> ServiceSet:
    """Dienstmenge einer ``permit``-Zeile (``ip``/``ipv6`` ohne Einschränkung: alle Dienste)."""
    if proto in ("ip", "ipv6"):
        return ServiceSet.everything()
    if proto == "icmp":
        return ServiceSet(others=frozenset({"icmp" if v4 else "icmpv6"}))
    return ServiceSet(((proto, (port or _FULL,)),))


def parse_cisco(text: str) -> ParsedRules:
    objects: Dict[str, List[IPNetwork]] = {}
    pairs: Set[NetPair] = set()
    returns: Set[NetPair] = set()
    services: Dict[NetPair, ServiceSet] = {}
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
        v4 = proto in ("ip", "tcp", "udp", "icmp") and "." in tokens[2]
        try:
            src, i = _cisco_net(tokens, 2, v4)
            src_port, i = _cisco_port(tokens, i)
            if tokens[i] == "object-group":
                dsts = objects[tokens[i + 1]]
                i += 2
            else:
                dst, i = _cisco_net(tokens, i, v4)
                dsts = [dst]
            dst_port, i = _cisco_port(tokens, i)
        except (ValueError, KeyError, IndexError) as exc:
            raise PlanError(f"Cisco-Zeile nicht lesbar: {stripped!r}") from exc
        found = {(src, d) for d in dsts}
        if proto == "tcp" and tokens[i:] == ["established"]:
            returns |= found
        else:
            pairs |= found
            _add_services(services, [src], dsts, _cisco_sigma(proto, dst_port, v4))
    return ParsedRules(frozenset(pairs), frozenset(returns), bool(acl_closed) and all(acl_closed), services)


def parse_rules(text: str, kind: str) -> ParsedRules:
    parsers = {"iptables": parse_iptables, "nftables": parse_nftables, "cisco": parse_cisco}
    if kind not in parsers:
        raise PlanError(f"Unbekanntes Firewall-System {kind!r}, erlaubt: {sorted(parsers)}")
    return parsers[kind](text)


def check_roundtrip(plan: Plan, kind: str, options: FirewallOptions = FirewallOptions()) -> RoundtripResult:
    """Erzeugt die Regeln, liest sie zurück und vergleicht P' mit P (und ``Sigma'`` mit ``Sigma``)."""
    parsed = parse_rules(render_firewall(plan, kind, options), kind)
    want = expected_pairs(plan)
    missing = want - parsed.pairs
    extra = parsed.pairs - want
    wanted_services = expected_services(plan)
    mismatch = frozenset(
        pair for pair in want & parsed.pairs if parsed.services.get(pair) != wanted_services[pair]
    )
    ok = not missing and not extra and not mismatch and parsed.default_deny
    return RoundtripResult(ok, missing, extra, parsed.default_deny, parsed.returns, mismatch)
