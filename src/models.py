"""Datenmodell, Konstanten und Fehlertyp von subnetplan."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Union

if TYPE_CHECKING:  # pragma: no cover - nur für Typangaben, vermeidet den Importzyklus mit ports.py
    from .ports import ServiceSet

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

STRATEGIES = ("vlsm", "fixed")
GATEWAY_POSITIONS = ("first", "last", "none")
FORMATS = ("table", "csv", "json")
FIREWALLS = ("none", "iptables", "nftables", "cisco")

TOP_KEYS = frozenset(
    {
        "base_network",
        "growth_factor",
        "allocation_strategy",
        "gateway_position",
        "groups",
        "max_prefix",
        "pools",
        "existing",
    }
)
GROUP_KEYS = frozenset({"name", "hosts", "vlan_id", "access", "priority", "overhead", "network", "site"})

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
    """Eine Gruppe (Definition "Gruppe, Konfiguration" der Arbeit).

    Optionale Erweiterungen (Abschnitt Ausblick):
    ``overhead`` ersetzt den berechneten Overhead o_i (Satz "Robustheit gegenüber
    Mindestgrößen"), ``network`` legt einen festen Block fest (Bestandsplanung) und
    ``site`` ordnet die Gruppe einem Standort zu (zweistufige Planung).
    """

    name: str
    hosts: int
    vlan_id: Optional[int] = None
    access: Tuple[str, ...] = ()
    priority: int = 0
    overhead: Optional[int] = None
    network: Optional[IPNetwork] = None
    site: Optional[str] = None
    # Einschränkung auf Protokolle und Ports je Zugriffsziel (Kapitel "Protokolle und Ports"):
    # nur Ziele mit Einschränkung stehen hier; jedes andere Ziel in ``access`` gilt für alle Dienste.
    services: Tuple[Tuple[str, "ServiceSet"], ...] = ()


@dataclass(frozen=True)
class PlanConfig:
    base_network: IPNetwork
    groups: Tuple[Group, ...]
    growth_factor: float = 1.25
    allocation_strategy: str = "vlsm"
    gateway_position: str = "first"
    max_prefix: Optional[int] = None  # längste erlaubte Präfixlänge = Mindestblockgröße
    pools: Tuple[IPNetwork, ...] = ()  # weitere Basisnetze neben base_network
    existing: Tuple[IPNetwork, ...] = ()  # bereits vergebene Netze (Bestand)
    warnings: Tuple[str, ...] = ()  # Hinweise aus der Bereinigung von ``access``


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
    site: Optional[str] = None
    services: Tuple[Tuple[str, "ServiceSet"], ...] = ()  # Einschränkungen je Ziel (siehe Group)

    @property
    def netmask(self) -> str:
        return str(self.network.netmask)

    def as_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
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
        if self.site is not None:
            data["site"] = self.site
        if self.services:
            data["services"] = {target: list(sigma.specs()) for target, sigma in self.services}
        return data


@dataclass(frozen=True)
class Plan:
    base_network: IPNetwork
    subnets: Tuple[Subnet, ...]
    free_ranges: Tuple[IPNetwork, ...]
    pools: Tuple[IPNetwork, ...] = ()  # zusätzliche Pools (Bestandsplanung)
    reserved: Tuple[IPNetwork, ...] = ()  # bereits vergebene Netze, nicht Teil des Plans
    site_blocks: Tuple[Tuple[str, IPNetwork], ...] = ()  # Standortblöcke (Hierarchie)

    @property
    def all_pools(self) -> Tuple[IPNetwork, ...]:
        return (self.base_network,) + self.pools

    @property
    def total_addresses(self) -> int:
        return sum(p.num_addresses for p in self.all_pools)

    @property
    def allocated_addresses(self) -> int:
        """Belegte Adressen; bei hierarchischer Planung zählen die Standortblöcke."""
        if self.site_blocks:
            return sum(net.num_addresses for _, net in self.site_blocks)
        return sum(s.network.num_addresses for s in self.subnets)

    @property
    def reserved_addresses(self) -> int:
        return sum(n.num_addresses for n in self.reserved)

    @property
    def free_addresses(self) -> int:
        return self.total_addresses - self.allocated_addresses - self.reserved_addresses

    @property
    def utilization(self) -> float:
        """Belegung des Basisnetzes in Prozent."""
        return 100.0 * self.allocated_addresses / self.total_addresses
