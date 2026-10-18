"""Firewall-Regeln aus der Zugriffsmatrix (iptables, nftables, Cisco-ACL)."""
from __future__ import annotations

from typing import Iterator, Tuple

from .models import Plan, PlanError, Subnet


def _access_pairs(plan: Plan) -> Iterator[Tuple[Subnet, Subnet]]:
    """(Quelle, Ziel)-Paare; Zugriff auf das eigene Netz braucht keine Regel."""
    by_name = {s.group: s for s in plan.subnets}
    for source in plan.subnets:
        for target in source.access:
            if target != source.group:
                yield source, by_name[target]


def render_iptables(plan: Plan) -> str:
    tool = "iptables" if plan.base_network.version == 4 else "ip6tables"
    lines = [
        "#!/bin/sh",
        "# Generiert von subnetplan: Standard ist Verwerfen, erlaubt sind nur die Gruppenzugriffe.",
        f"{tool} -N SUBNET_ACL",
        f"{tool} -A SUBNET_ACL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for src, dst in _access_pairs(plan):
        lines.append(
            f'{tool} -A SUBNET_ACL -s {src.network} -d {dst.network} '
            f'-m comment --comment "{src.group} -> {dst.group}" -j ACCEPT'
        )
    lines += [f"{tool} -A SUBNET_ACL -j DROP", f"{tool} -I FORWARD 1 -j SUBNET_ACL"]
    return "\n".join(lines)


def render_nftables(plan: Plan) -> str:
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
    for src, dst in _access_pairs(plan):
        lines.append(
            f'        {family} saddr {src.network} {family} daddr {dst.network} '
            f'accept comment "{src.group} -> {dst.group}"'
        )
    lines += ["    }", "}"]
    return "\n".join(lines)


def cisco_acl_name(subnet: Subnet) -> str:
    return f"ACL-{subnet.vlan_id}-{subnet.group.upper().replace(' ', '_')}"


def render_cisco(plan: Plan) -> str:
    v4 = plan.base_network.version == 4
    lines = [
        "! Generiert von subnetplan: je Gruppe eine eingehende ACL auf dem VLAN-Interface.",
        "! Hinweis: ACLs sind zustandslos; Rückverkehr muss durch die Gegenregeln erlaubt sein.",
    ]
    for src in plan.subnets:
        name = cisco_acl_name(src)
        lines.append(f"ip access-list extended {name}" if v4 else f"ipv6 access-list {name}")
        for source, dst in _access_pairs(plan):
            if source is not src:
                continue
            lines.append(f" remark {src.group} -> {dst.group}")
            if v4:
                lines.append(
                    f" permit ip {src.network.network_address} {src.network.hostmask} "
                    f"{dst.network.network_address} {dst.network.hostmask}"
                )
            else:
                lines.append(f" permit ipv6 {src.network} {dst.network}")
        lines.append(" deny ip any any" if v4 else " deny ipv6 any any")
        lines.append(f"interface Vlan{src.vlan_id}")
        lines.append(f" ip access-group {name} in" if v4 else f" ipv6 traffic-filter {name} in")
    return "\n".join(lines)


def render_firewall(plan: Plan, kind: str) -> str:
    renderers = {"iptables": render_iptables, "nftables": render_nftables, "cisco": render_cisco}
    if kind not in renderers:
        raise PlanError(f"Unbekanntes Firewall-System {kind!r}, erlaubt: {sorted(renderers)}")
    return renderers[kind](plan)
