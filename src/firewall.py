"""Firewall-Regeln aus der Zugriffsmatrix (iptables, nftables, Cisco-ACL).

Zusätzlich zu den Grundregeln der Arbeit (Satz "Default-Deny-Korrektheit", Satz
"Cisco-Semantik") sind die Verbesserungen aus dem Ausblick umgesetzt:
idempotente iptables-Skripte, ASCII-Namen mit Transliteration, Rückverkehr für Cisco über
``established``, Regelgruppierung (nftables-Mengen, ipset, Cisco-Objektgruppen), ICMPv6-Typen
und Protokollierung verworfener Pakete.
"""
from __future__ import annotations

import re
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Iterator, List, Tuple

from .access import asymmetric_pairs, rule_groups
from .models import Plan, PlanError, Subnet

ICMPV6_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
CISCO_RETURN_MODES = ("none", "established")
_TRANSLIT = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "Ä": "AE", "Ö": "OE", "Ü": "UE"}


@dataclass(frozen=True)
class FirewallOptions:
    """Optionen der Regelerzeugung (Standard: Verhalten der Grundversion plus Idempotenz)."""

    idempotent: bool = True  # iptables: vorhandene Kette zuerst entfernen
    group_rules: bool = False  # Regeln mit gleicher Zielmenge zusammenfassen
    cisco_return: str = "none"  # "established": Rückverkehr für TCP in Cisco-ACLs
    ascii_names: bool = False  # Namen in ACLs und Kommentaren nach ASCII transliterieren
    log_drops: bool = False  # verworfene Pakete protokollieren
    icmpv6_types: Tuple[str, ...] = ()  # weitergeleitete ICMPv6-Typen (nur IPv6)

    def validate(self, plan: Plan) -> None:
        if self.cisco_return not in CISCO_RETURN_MODES:
            raise PlanError(
                f"cisco_return {self.cisco_return!r} ungültig, erlaubt: {list(CISCO_RETURN_MODES)}"
            )
        for t in self.icmpv6_types:
            if not ICMPV6_RE.fullmatch(t):
                raise PlanError(f"Ungültiger ICMPv6-Typ {t!r}")
        if self.icmpv6_types and plan.base_network.version != 6:
            raise PlanError("ICMPv6-Typen sind nur bei einem IPv6-Basisnetz möglich")


def ascii_name(text: str) -> str:
    """Transliteriert nach ASCII (Ä -> AE, ß -> ss, é -> e); Übriges wird zu ``_``."""
    out = []
    for ch in text:
        if ch in _TRANSLIT:
            out.append(_TRANSLIT[ch])
            continue
        base = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode("ascii")
        out.append(base if base else "_")
    return "".join(out)


def _label(name: str, options: FirewallOptions) -> str:
    return ascii_name(name) if options.ascii_names else name


def _access_pairs(plan: Plan) -> Iterator[Tuple[Subnet, Subnet]]:
    """(Quelle, Ziel)-Paare; Zugriff auf das eigene Netz braucht keine Regel."""
    by_name = {s.group: s for s in plan.subnets}
    for source in plan.subnets:
        for target in source.access:
            if target != source.group:
                yield source, by_name[target]


def _pairs_by_source(plan: Plan) -> Dict[str, List[Subnet]]:
    """Zugriffspaare einmal nach Quelle gruppiert: Cisco-Ausgabe in O(n + a)."""
    grouped: Dict[str, List[Subnet]] = {s.group: [] for s in plan.subnets}
    for src, dst in _access_pairs(plan):
        grouped[src.group].append(dst)
    return grouped


def _icmp_lines_nft(plan: Plan, options: FirewallOptions) -> List[str]:
    if not options.icmpv6_types:
        return []
    return [f"        icmpv6 type {{ {', '.join(options.icmpv6_types)} }} accept"]


# --------------------------------------------------------------------------- iptables
def render_iptables(plan: Plan, options: FirewallOptions = FirewallOptions()) -> str:
    options.validate(plan)
    tool = "iptables" if plan.base_network.version == 4 else "ip6tables"
    lines = [
        "#!/bin/sh",
        "# Generiert von subnetplan: Standard ist Verwerfen, erlaubt sind nur die Gruppenzugriffe.",
    ]
    if options.idempotent:
        lines += [
            f"while {tool} -D FORWARD -j SUBNET_ACL 2>/dev/null; do :; done",
            f"{tool} -F SUBNET_ACL 2>/dev/null || true",
            f"{tool} -X SUBNET_ACL 2>/dev/null || true",
        ]
    lines += [
        f"{tool} -N SUBNET_ACL",
        f"{tool} -A SUBNET_ACL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for icmp in options.icmpv6_types:
        lines.append(f"{tool} -A SUBNET_ACL -p ipv6-icmp --icmpv6-type {icmp} -j ACCEPT")
    if options.group_rules:
        family = "inet" if plan.base_network.version == 4 else "inet6"
        for k, rg in enumerate(rule_groups(plan), start=1):
            for tag, subnets in (("S", rg.sources), ("D", rg.targets)):
                name = f"SUBNET_ACL_{tag}{k}"
                lines.append(f"ipset create -exist {name} hash:net family {family}")
                lines.append(f"ipset flush {name}")
                lines += [f"ipset add {name} {s.network}" for s in subnets]
            label = _label(rg.label, options)
            lines.append(
                f"{tool} -A SUBNET_ACL -m set --match-set SUBNET_ACL_S{k} src "
                f"-m set --match-set SUBNET_ACL_D{k} dst "
                f'-m comment --comment "{label}" -j ACCEPT'
            )
    else:
        for src, dst in _access_pairs(plan):
            lines.append(
                f"{tool} -A SUBNET_ACL -s {src.network} -d {dst.network} "
                f'-m comment --comment "{_label(src.group, options)} -> {_label(dst.group, options)}" -j ACCEPT'
            )
    if options.log_drops:
        lines.append(f'{tool} -A SUBNET_ACL -m limit --limit 5/min -j LOG --log-prefix "SUBNET_ACL drop: "')
    lines += [f"{tool} -A SUBNET_ACL -j DROP", f"{tool} -I FORWARD 1 -j SUBNET_ACL"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- nftables
def render_nftables(plan: Plan, options: FirewallOptions = FirewallOptions()) -> str:
    options.validate(plan)
    family = "ip" if plan.base_network.version == 4 else "ip6"
    lines = [
        "# Generiert von subnetplan: Standard ist Verwerfen, erlaubt sind nur die Gruppenzugriffe.",
        "table inet subnet_acl",
        "delete table inet subnet_acl",
        "table inet subnet_acl {",
        "    chain forward {",
        "        type filter hook forward priority 0; policy drop;",
        "        ct state established,related accept",
    ]
    lines += _icmp_lines_nft(plan, options)
    if options.group_rules:
        for rg in rule_groups(plan):
            src = ", ".join(str(s.network) for s in rg.sources)
            dst = ", ".join(str(t.network) for t in rg.targets)
            lines.append(
                f"        {family} saddr {{ {src} }} {family} daddr {{ {dst} }} "
                f'accept comment "{_label(rg.label, options)}"'
            )
    else:
        for src_net, dst_net in _access_pairs(plan):
            lines.append(
                f"        {family} saddr {src_net.network} {family} daddr {dst_net.network} "
                f'accept comment "{_label(src_net.group, options)} -> {_label(dst_net.group, options)}"'
            )
    if options.log_drops:
        lines.append('        limit rate 5/minute log prefix "subnet_acl drop: "')
    lines += ["    }", "}"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- Cisco
def cisco_acl_name(subnet: Subnet, ascii_names: bool = False) -> str:
    """ACL-Name ``ACL-<VLAN>-<NAME>``; eindeutig, weil die VLAN-ID im Namen steht."""
    name = subnet.group.upper().replace(" ", "_")
    if ascii_names:
        name = ascii_name(name).upper()
    return f"ACL-{subnet.vlan_id}-{name}"


def _cisco_net(net, v4: bool) -> str:
    return f"{net.network_address} {net.hostmask}" if v4 else str(net)


def render_cisco(plan: Plan, options: FirewallOptions = FirewallOptions()) -> str:
    options.validate(plan)
    v4 = plan.base_network.version == 4
    lines = [
        "! Generiert von subnetplan: je Gruppe eine eingehende ACL auf dem VLAN-Interface.",
        "! Hinweis: ACLs sind zustandslos; Rückverkehr muss durch die Gegenregeln erlaubt sein.",
    ]
    by_source = _pairs_by_source(plan)
    by_name = {s.group: s for s in plan.subnets}
    use_objects = options.group_rules and v4

    object_names: "OrderedDict[Tuple[str, ...], str]" = OrderedDict()
    if use_objects:
        for rg in rule_groups(plan):
            # Zielmengen sind je Regelgruppe eindeutig, also ist jeder Schlüssel neu.
            object_names[tuple(t.group for t in rg.targets)] = f"OG-TARGETS-{len(object_names) + 1}"
        for key, name in object_names.items():
            lines.append(f"object-group network {name}")
            for target in key:
                net = by_name[target].network
                lines.append(f" {net.network_address} {net.netmask}")

    returns: Dict[str, List[Subnet]] = {s.group: [] for s in plan.subnets}
    if options.cisco_return == "established":
        for src_name, dst_name in asymmetric_pairs(plan):
            returns[dst_name].append(by_name[src_name])

    for src in plan.subnets:
        name = cisco_acl_name(src, options.ascii_names)
        lines.append(f"ip access-list extended {name}" if v4 else f"ipv6 access-list {name}")
        targets = by_source[src.group]
        if use_objects and targets:
            key = tuple(sorted({t.group for t in targets}, key=[s.group for s in plan.subnets].index))
            lines.append(f" remark {_label(src.group, options)} -> {_label(','.join(key), options)}")
            lines.append(f" permit ip {_cisco_net(src.network, True)} object-group {object_names[key]}")
        else:
            for dst in targets:
                lines.append(f" remark {_label(src.group, options)} -> {_label(dst.group, options)}")
                if v4:
                    lines.append(
                        f" permit ip {src.network.network_address} {src.network.hostmask} "
                        f"{dst.network.network_address} {dst.network.hostmask}"
                    )
                else:
                    lines.append(f" permit ipv6 {src.network} {dst.network}")
        for origin in returns[src.group]:  # Antworten an Gruppen, die auf uns zugreifen dürfen
            lines.append(f" remark Rueckverkehr {_label(src.group, options)} -> {_label(origin.group, options)}")
            lines.append(f" permit tcp {_cisco_net(src.network, v4)} {_cisco_net(origin.network, v4)} established")
        deny = " deny ip any any" if v4 else " deny ipv6 any any"
        lines.append(deny + (" log" if options.log_drops else ""))
        lines.append(f"interface Vlan{src.vlan_id}")
        lines.append(f" ip access-group {name} in" if v4 else f" ipv6 traffic-filter {name} in")
    return "\n".join(lines)


def render_firewall(plan: Plan, kind: str, options: FirewallOptions = FirewallOptions()) -> str:
    renderers = {"iptables": render_iptables, "nftables": render_nftables, "cisco": render_cisco}
    if kind not in renderers:
        raise PlanError(f"Unbekanntes Firewall-System {kind!r}, erlaubt: {sorted(renderers)}")
    return renderers[kind](plan, options)
