"""Datenmodell, Konstanten und Fehlertyp von subnetplan."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

STRATEGIES = ("vlsm", "fixed")
GATEWAY_POSITIONS = ("first", "last", "none")
FORMATS = ("table", "csv", "json")
FIREWALLS = ("none", "iptables", "nftables", "cisco")

TOP_KEYS = frozenset(
    {"base_network", "growth_factor", "allocation_strategy", "gateway_position", "groups"}
)
GROUP_KEYS = frozenset({"name", "hosts", "vlan_id", "access", "priority"})

# Gruppennamen landen in Firewall-Kommentaren und ACL-Namen: nur harmlose Zeichen.
NAME_RE = re.compile(r"^[\w\- ]+$")

VLAN_MIN = 1
VLAN_MAX = 4094
AUTO_VLAN_START = 10
AUTO_VLAN_STEP = 10

CSV_FIELDS = (
    "group",
    "vlan_id",
    "network",
    "netmask",
    "gateway",
    "first_host",
    "last_host",
    "broadcast",
    "usable_hosts",
    "requested_hosts",
    "access",
)


class PlanError(ValueError):
    """Fehler in Konfiguration, Planung oder Ausgabe."""


@dataclass(frozen=True)
class Group:
    name: str
    hosts: int
    vlan_id: Optional[int] = None
    access: Tuple[str, ...] = ()
    priority: int = 0


@dataclass(frozen=True)
class PlanConfig:
    base_network: IPNetwork
    groups: Tuple[Group, ...]
    growth_factor: float = 1.25
    allocation_strategy: str = "vlsm"
    gateway_position: str = "first"


@dataclass(frozen=True)
class Subnet:
    group: str
    vlan_id: int
    requested_hosts: int
    network: IPNetwork
    gateway: Optional[IPAddress]
    first_host: IPAddress
    last_host: IPAddress
    broadcast: Optional[IPAddress]
    usable_hosts: int
    access: Tuple[str, ...]

    @property
    def netmask(self) -> str:
        return str(self.network.netmask)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group": self.group,
            "vlan_id": self.vlan_id,
            "network": str(self.network),
            "netmask": self.netmask,
            "gateway": None if self.gateway is None else str(self.gateway),
            "first_host": str(self.first_host),
            "last_host": str(self.last_host),
            "broadcast": None if self.broadcast is None else str(self.broadcast),
            "usable_hosts": self.usable_hosts,
            "requested_hosts": self.requested_hosts,
            "access": list(self.access),
        }


@dataclass(frozen=True)
class Plan:
    base_network: IPNetwork
    subnets: Tuple[Subnet, ...]
    free_ranges: Tuple[IPNetwork, ...]

    @property
    def total_addresses(self) -> int:
        return self.base_network.num_addresses

    @property
    def allocated_addresses(self) -> int:
        return sum(s.network.num_addresses for s in self.subnets)

    @property
    def free_addresses(self) -> int:
        return self.total_addresses - self.allocated_addresses

    @property
    def utilization(self) -> float:
        """Belegung des Basisnetzes in Prozent."""
        return 100.0 * self.allocated_addresses / self.total_addresses
