"""Urteilsfunktionen der erzeugten Regeln (Sätze "Default-Deny-Korrektheit" und "Cisco-Semantik").

Die Funktionen berechnen das Urteil, das die erzeugten Regelwerke nach den Sätzen der Arbeit
fällen. Sie dienen als Referenz für Tests und für die Rückübersetzung (``roundtrip``).
"""
from __future__ import annotations

import ipaddress
from typing import Optional, Union

from .models import IPAddress, Plan, PlanError, Subnet

AddressLike = Union[str, IPAddress]


def _addr(value: AddressLike) -> IPAddress:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise PlanError(f"Ungültige Adresse {value!r}: {exc}") from exc


def locate(plan: Plan, address: AddressLike) -> Optional[Subnet]:
    """Das Subnetz, das die Adresse enthält (nach (K3) höchstens eines), sonst None."""
    addr = _addr(address)
    for subnet in plan.subnets:
        if subnet.network.version == addr.version and addr in subnet.network:
            return subnet
    return None


def _permitted(src: Subnet, dst: Subnet) -> bool:
    return src.group != dst.group and dst.group in src.access


def firewall_verdict(plan: Plan, source: AddressLike, target: AddressLike, state: str = "new") -> str:
    """Urteil von iptables/nftables: ``accept`` oder ``drop``.

    ``state`` ist ``new`` oder ``established`` (umfasst auch *related*). Etablierte Pakete
    werden immer angenommen; neue nur, wenn es Gruppen i != j mit Quelle in N_i, Ziel in N_j
    und g_j in acc(g_i) gibt. Alles andere, auch Verkehr ins Internet, wird verworfen.
    """
    if state not in ("new", "established"):
        raise PlanError(f"Unbekannter Zustand {state!r}, erlaubt: ['established', 'new']")
    if state == "established":
        return "accept"
    src = locate(plan, source)
    dst = locate(plan, target)
    if src is not None and dst is not None and _permitted(src, dst):
        return "accept"
    return "drop"


def cisco_verdict(plan: Plan, ingress_group: str, source: AddressLike, target: AddressLike) -> str:
    """Urteil der eingehenden Cisco-ACL am Interface der Gruppe ``ingress_group``.

    Weitergeleitet wird genau dann, wenn die Quelle im eigenen Subnetz liegt (Schutz vor
    gefälschten Quellen) und das Ziel in einer freigegebenen anderen Gruppe.
    """
    own = next((s for s in plan.subnets if s.group == ingress_group), None)
    if own is None:
        raise PlanError(f"Unbekannte Gruppe {ingress_group!r}")
    src_addr = _addr(source)
    if src_addr.version != own.network.version or src_addr not in own.network:
        return "drop"
    dst = locate(plan, target)
    if dst is not None and _permitted(own, dst):
        return "accept"
    return "drop"
