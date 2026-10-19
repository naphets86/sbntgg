"""Warnungen zu einem Plan (Ausblick, "Warnungen"): Adressbereich, VPN-Überschneidung, Auslastung."""
from __future__ import annotations

import ipaddress
from typing import List, Optional, Sequence

from .access import asymmetric_pairs
from .models import IPNetwork, Plan, PlanConfig

PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)  # Unique Local Addresses


def is_private_range(net: IPNetwork) -> bool:
    """Liegt das Netz vollständig in RFC 1918 (IPv4) beziehungsweise fc00::/7 (IPv6)?"""
    ranges = PRIVATE_V4 if net.version == 4 else PRIVATE_V6
    return any(net.subnet_of(r) for r in ranges)  # type: ignore[arg-type]


def plan_warnings(
    plan: Plan,
    cfg: Optional[PlanConfig] = None,
    threshold: float = 80.0,
    foreign_networks: Sequence[IPNetwork] = (),
    firewall: str = "none",
    cisco_return: str = "none",
) -> List[str]:
    """Sammelt Hinweise: access-Bereinigung, nicht privater Bereich, VPN-Überschneidung,
    hohe Auslastung und (bei Cisco) fehlender Rückverkehr."""
    warnings: List[str] = list(cfg.warnings) if cfg is not None else []
    for pool in plan.all_pools:
        if not is_private_range(pool):
            kind = "RFC 1918" if pool.version == 4 else "fc00::/7"
            warnings.append(f"Das Netz {pool} liegt nicht im privaten Adressbereich ({kind})")
    for foreign in foreign_networks:
        for net in list(plan.all_pools) + [s.network for s in plan.subnets]:
            if net.version == foreign.version and net.overlaps(foreign):
                warnings.append(f"Das Netz {net} überschneidet sich mit dem fremden Netz {foreign}")
                break
    if plan.utilization >= threshold:
        warnings.append(f"Auslastung {plan.utilization:.2f} % erreicht den Schwellwert {threshold:g} %")
    if firewall == "cisco":
        for src, dst in asymmetric_pairs(plan):
            if cisco_return == "established":
                warnings.append(
                    f"Rückverkehr {dst} -> {src} ist nur für TCP über 'established' abgedeckt (UDP und ICMP nicht)"
                )
            else:
                warnings.append(f"Cisco-ACLs sind zustandslos: Rückverkehr {dst} -> {src} braucht eine Gegenregel")
    return warnings
