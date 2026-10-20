"""Protokolle und Ports (Kapitel "Erweiterung um Protokolle und Ports").

Der Portraum ist der Adressraum der Breite w = 16; Blöcke, Ausrichtung und Laminarität gelten
unverändert. Das Modul setzt die Aussagen des Kapitels um:

  * Satz "Normalform"          -> ``normalize``, ``from_ports``, ``MAX_INTERVALS``
  * Lemma/Satz "Zerlegung"     -> ``interval_blocks`` (höchstens 30 Portblöcke, scharf)
  * Satz "Lücken"              -> ``gaps``
  * Korollar "Vollständigkeit" -> ``is_complete``
  * Korollar "Überlappung"     -> ``overlapping``
  * Satz "Verschmelzen"        -> ``normalize``
  * Satz "Teilmengenprüfung"   -> ``is_subset``
  * Definition "Dienstraum" und "Dienstfreigabe" -> ``ServiceSet`` mit ``parse_services``

Das Modul hängt nur von ``PlanError`` ab; es kennt weder Pläne noch Firewall-Syntax.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Any, FrozenSet, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from .models import PlanError

PORT_BITS = 16
PORT_MIN = 0
PORT_MAX = (1 << PORT_BITS) - 1  # 65535
PORT_COUNT = 1 << PORT_BITS  # |P| = 65536

#: Satz "Zerlegung eines Intervalls": 2w - 2 mit w = 16 (scharf, Beispiel [1, 65534]).
MAX_BLOCKS_PER_INTERVAL = 2 * PORT_BITS - 2
#: Satz "Normalform": höchstens 2^15 Läufe (die geraden Ports erreichen die Schranke).
MAX_INTERVALS = 1 << (PORT_BITS - 1)

PORT_PROTOCOLS = ("tcp", "udp")  # Menge Pi der Protokolle mit Ports
OTHER_PROTOCOLS = ("icmp", "icmpv6")  # Menge Omega der portlosen Protokolle
FAMILY_PROTOCOL = {4: "icmp", 6: "icmpv6"}  # welches portlose Protokoll zu welcher IP-Version passt

Interval = Tuple[int, int]
Service = Tuple[str, Optional[int]]  # ("tcp", 443) oder ("icmp", None)


# --------------------------------------------------------------------------- Intervalle
def check_interval(low: Any, high: Any) -> Interval:
    """Prüft 0 <= low <= high <= 65535 (ganze Zahlen) und gibt das Intervall zurück."""
    for value in (low, high):
        if isinstance(value, bool) or not isinstance(value, int):
            raise PlanError(f"Port-Intervall ({low!r}, {high!r}): ganze Zahlen erwartet")
        if not PORT_MIN <= value <= PORT_MAX:
            raise PlanError(f"Port {value} außerhalb des Portraums {PORT_MIN}..{PORT_MAX}")
    if low > high:
        raise PlanError(f"Port-Intervall {low}-{high}: der Anfang liegt hinter dem Ende")
    return (low, high)


def normalize(intervals: Iterable[Interval]) -> Tuple[Interval, ...]:
    """Normalisierte Intervallliste der Vereinigung (Sätze "Normalform" und "Verschmelzen").

    Sortiert nach dem Anfang und beginnt ein neues Ausgabeintervall genau dann, wenn
    ``l_{k+1} >= R_k + 2`` gilt; benachbarte und überlappende Intervalle werden verschmolzen.
    Die Darstellung ist eindeutig: es ist die Liste der Läufe der Menge.
    """
    out: List[Interval] = []
    for low, high in sorted(check_interval(*iv) for iv in intervals):
        if out and low <= out[-1][1] + 1:
            if high > out[-1][1]:
                out[-1] = (out[-1][0], high)
        else:
            out.append((low, high))
    return tuple(out)


def from_ports(ports: Iterable[int]) -> Tuple[Interval, ...]:
    """Normalform einer Menge einzelner Ports (Liste ihrer Läufe)."""
    return normalize((q, q) for q in ports)


def ports_of(intervals: Iterable[Interval]) -> FrozenSet[int]:
    """Alle Ports der Vereinigung (für Tests und Vergleiche; bis zu 65536 Elemente)."""
    result = set()
    for low, high in intervals:
        check_interval(low, high)
        result.update(range(low, high + 1))
    return frozenset(result)


def size(intervals: Iterable[Interval]) -> int:
    """Anzahl der Ports in der Vereinigung."""
    return sum(high - low + 1 for low, high in normalize(intervals))


def contains(normalized: Sequence[Interval], port: int) -> bool:
    """Ob ``port`` in einer *normalisierten* Liste liegt (Binärsuche, O(log m))."""
    if isinstance(port, bool) or not isinstance(port, int) or not PORT_MIN <= port <= PORT_MAX:
        raise PlanError(f"Ungültiger Port {port!r} (erlaubt: {PORT_MIN}..{PORT_MAX})")
    index = bisect.bisect_right(normalized, port, key=lambda iv: iv[0]) - 1
    return index >= 0 and port <= normalized[index][1]


def union(a: Iterable[Interval], b: Iterable[Interval]) -> Tuple[Interval, ...]:
    return normalize([*a, *b])


def gaps(intervals: Iterable[Interval]) -> Tuple[Interval, ...]:
    """Nicht abgedeckte Ports einer beliebigen Liste (Satz "Lücken").

    Mit ``R_0 = -1`` und ``R_k = max(r_1..r_k)`` ist der Zwischenraum
    ``G_k = [R_k + 1, l_{k+1} - 1]``; die nichtleeren ``G_k`` bilden eine normalisierte Liste.
    """
    result: List[Interval] = []
    reach = -1
    for low, high in sorted(check_interval(*iv) for iv in intervals):
        if low > reach + 1:
            result.append((reach + 1, low - 1))
        reach = max(reach, high)
    if reach < PORT_MAX:
        result.append((reach + 1, PORT_MAX))
    return tuple(result)


def is_complete(intervals: Iterable[Interval]) -> bool:
    """Ob die Vereinigung der Liste der ganze Portraum ist (Korollar "Vollständigkeit").

    Die leere Liste ist nie vollständig (ihr Zwischenraum ``G_0`` ist der ganze Portraum).
    """
    return not gaps(intervals)


def overlapping(intervals: Iterable[Interval]) -> Tuple[Tuple[Interval, Interval], ...]:
    """Überlappende Intervallpaare (Korollar "Überlappung").

    Die sortierte Liste ist genau dann überlappungsfrei, wenn ``l_{k+1} > r_k`` für alle k gilt.
    Gemeldet wird je überlappendem Intervall ein Paar (früheres, späteres), wobei das frühere
    das Intervall mit dem bisher größten Ende ist. Eine leere Rückgabe bedeutet: disjunkt.
    """
    pairs: List[Tuple[Interval, Interval]] = []
    reaching: Optional[Interval] = None
    for iv in sorted(check_interval(*iv) for iv in intervals):
        if reaching is not None and iv[0] <= reaching[1]:
            pairs.append((reaching, iv))
        if reaching is None or iv[1] > reaching[1]:
            reaching = iv
    return tuple(pairs)


def is_subset(a: Iterable[Interval], b: Iterable[Interval]) -> bool:
    """Ob die Vereinigung von ``a`` in der von ``b`` liegt (Satz "Teilmengenprüfung").

    Beide Listen werden normalisiert; dann liegt jedes Intervall von ``a`` in genau einem
    Intervall von ``b`` genau dann, wenn die Mengen enthalten sind. Zwei Zeiger: O(a + b).
    """
    left, right = normalize(a), normalize(b)
    j = 0
    for low, high in left:
        while j < len(right) and right[j][1] < low:
            j += 1  # solche Intervalle enthalten keinen späteren Anfang
        if j == len(right) or not (right[j][0] <= low and high <= right[j][1]):
            return False
    return True


# --------------------------------------------------------------------------- Portblöcke
class PortBlock(NamedTuple):
    """Ausgerichteter Portblock ``N(start, prefix)`` mit 2^(16 - prefix) Ports."""

    start: int
    prefix: int

    @property
    def size(self) -> int:
        return 1 << (PORT_BITS - self.prefix)

    @property
    def last(self) -> int:
        return self.start + self.size - 1

    @property
    def mask(self) -> int:
        """Wert-Maske-Schreibweise: ``port & mask == start``."""
        return PORT_MAX & ~(self.size - 1)


def interval_blocks(low: int, high: int) -> Tuple[PortBlock, ...]:
    """Minimale Zerlegung von ``[low, high]`` in ausgerichtete Portblöcke.

    Nach Satz "Zerlegung eines Intervalls" sind es höchstens 30 Blöcke, und ``[1, 65534]``
    braucht genau 30. Gierig vom Anfang aus: jeweils der größte ausgerichtete Block, der noch
    in das Restintervall passt. Das entspricht ``ipaddress.summarize_address_range``.
    """
    check_interval(low, high)
    blocks: List[PortBlock] = []
    cur = low
    while cur <= high:
        exponent = PORT_BITS if cur == 0 else (cur & -cur).bit_length() - 1
        while cur + (1 << exponent) - 1 > high:
            exponent -= 1
        blocks.append(PortBlock(cur, PORT_BITS - exponent))
        cur += 1 << exponent
    return tuple(blocks)


def list_blocks(intervals: Iterable[Interval]) -> Tuple[PortBlock, ...]:
    """Portblöcke aller Intervalle der Normalform (höchstens 30 je Intervall)."""
    return tuple(block for low, high in normalize(intervals) for block in interval_blocks(low, high))


# --------------------------------------------------------------------------- Dienste
@dataclass(frozen=True)
class ServiceSet:
    """Dienstmenge ``Sigma`` im Dienstraum ``D = (Pi x P) ∪ Omega`` (Definition "Dienstraum").

    ``ports`` hält je Protokoll mit Ports (tcp, udp) die normalisierte Liste der Zielports;
    ``others`` die portlosen Protokolle (icmp, icmpv6). Die Darstellung ist kanonisch (sortiert,
    verschmolzen, ohne leere Protokolle), also sind gleiche Mengen auch gleiche Objekte.
    """

    ports: Tuple[Tuple[str, Tuple[Interval, ...]], ...] = ()
    others: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        merged: dict = {}
        for proto, intervals in self.ports:
            if proto not in PORT_PROTOCOLS:
                raise PlanError(f"Unbekanntes Protokoll mit Ports {proto!r}, erlaubt: {list(PORT_PROTOCOLS)}")
            merged.setdefault(proto, []).extend(intervals)
        canonical = tuple((p, normalize(v)) for p, v in sorted(merged.items()) if v)
        unknown = sorted(set(self.others) - set(OTHER_PROTOCOLS))
        if unknown:
            raise PlanError(f"Unbekanntes Protokoll {unknown}, erlaubt: {list(OTHER_PROTOCOLS)}")
        object.__setattr__(self, "ports", canonical)
        object.__setattr__(self, "others", frozenset(self.others))

    # -- Konstruktion
    @classmethod
    def everything(cls) -> "ServiceSet":
        """Alle Dienste (``sigma = D``): das bisherige Verhalten ohne Einschränkung."""
        full = ((PORT_MIN, PORT_MAX),)
        return cls(tuple((p, full) for p in PORT_PROTOCOLS), frozenset(OTHER_PROTOCOLS))

    @classmethod
    def from_specs(cls, specs: Iterable[Any]) -> "ServiceSet":
        return parse_services(list(specs))[0]

    # -- Abfragen
    def intervals(self, proto: str) -> Tuple[Interval, ...]:
        return dict(self.ports).get(proto, ())

    @property
    def is_empty(self) -> bool:
        return not self.ports and not self.others

    def covers_all(self, version: int) -> bool:
        """Ob die Menge für die IP-Version so viel erlaubt wie ``D`` (keine Einschränkung)."""
        full = ((PORT_MIN, PORT_MAX),)
        return (
            all(self.intervals(p) == full for p in PORT_PROTOCOLS)
            and FAMILY_PROTOCOL[version] in self.others
        )

    def contains(self, proto: str, port: Optional[int] = None) -> bool:
        """Ob der Dienst ``(proto, port)`` beziehungsweise das portlose ``proto`` enthalten ist."""
        if proto in PORT_PROTOCOLS:
            if port is None:
                raise PlanError(f"Für {proto} wird ein Port benötigt")
            return contains(self.intervals(proto), port)
        if proto in OTHER_PROTOCOLS:
            return proto in self.others
        raise PlanError(f"Unbekanntes Protokoll {proto!r}")

    def union(self, other: "ServiceSet") -> "ServiceSet":
        return ServiceSet(self.ports + other.ports, self.others | other.others)

    def issubset(self, other: "ServiceSet") -> bool:
        """``self ⊆ other`` (Satz "Teilmengenprüfung" je Protokoll, dazu die Mengen in Omega)."""
        return self.others <= other.others and all(
            is_subset(ivs, other.intervals(p)) for p, ivs in self.ports
        )

    def validate_version(self, version: int, where: str = "") -> None:
        """``icmp`` gibt es nur bei IPv4, ``icmpv6`` nur bei IPv6."""
        wrong = [p for p in OTHER_PROTOCOLS if p in self.others and p != FAMILY_PROTOCOL[version]]
        if wrong:
            prefix = f"{where}: " if where else ""
            raise PlanError(f"{prefix}Protokoll {wrong[0]} passt nicht zu einem IPv{version}-Basisnetz")

    # -- Darstellung
    def specs(self) -> Tuple[str, ...]:
        """Kanonische Schreibweise: ``tcp/22``, ``tcp/8000-8099``, ``udp``, ``icmp``."""
        out: List[str] = []
        for proto, ivs in self.ports:
            for low, high in ivs:
                if (low, high) == (PORT_MIN, PORT_MAX):
                    out.append(proto)
                elif low == high:
                    out.append(f"{proto}/{low}")
                else:
                    out.append(f"{proto}/{low}-{high}")
        out.extend(sorted(self.others))
        return tuple(out)

    def __str__(self) -> str:
        return ",".join(self.specs())


_SPEC_PORTS_RE = re.compile(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?")


def _format_interval(proto: str, low: int, high: int) -> str:
    if (low, high) == (PORT_MIN, PORT_MAX):
        return proto
    return f"{proto}/{low}" if low == high else f"{proto}/{low}-{high}"


def parse_service_entry(spec: Any) -> Tuple[str, Optional[Interval]]:
    """Liest einen Dienst wie ``tcp/22``, ``udp/5000-5010``, ``tcp`` (alle Ports) oder ``icmp``.

    Rückgabe: (Protokoll, Intervall); für portlose Protokolle ist das Intervall ``None``.
    Der reservierte Port 0 ist nur über die Kurzform ``tcp``/``udp`` (alle Ports) enthalten
    und wird in einer ausdrücklichen Angabe abgelehnt (Bemerkung "Port 0").
    """
    if not isinstance(spec, str):
        raise PlanError(f"Dienst {spec!r}: Text wie 'tcp/443' erwartet (das Protokoll fehlt bei einer Zahl)")
    text = spec.strip().lower()
    proto, slash, rest = text.partition("/")
    proto = proto.strip()
    if proto in OTHER_PROTOCOLS:
        if slash:
            raise PlanError(f"Dienst {spec!r}: {proto} hat keine Ports")
        return proto, None
    if proto not in PORT_PROTOCOLS:
        allowed = list(PORT_PROTOCOLS + OTHER_PROTOCOLS)
        raise PlanError(f"Dienst {spec!r}: unbekanntes Protokoll {proto!r}, erlaubt: {allowed}")
    if not slash:
        return proto, (PORT_MIN, PORT_MAX)
    match = _SPEC_PORTS_RE.fullmatch(rest.strip())
    if match is None:
        raise PlanError(f"Dienst {spec!r}: Ports als 'tcp/22' oder 'tcp/8000-8099' angeben")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) is not None else low
    if low == 0:
        raise PlanError(f"Dienst {spec!r}: Port 0 ist reserviert (alle Ports: einfach '{proto}')")
    return proto, check_interval(low, high)


def parse_services(specs: Sequence[Any], where: str = "") -> Tuple[ServiceSet, Tuple[str, ...]]:
    """Liest eine Liste von Diensten; Rückgabe: Dienstmenge und Warnungen zu Überlappungen.

    Überlappende oder doppelte Angaben ändern die Menge nicht (Satz "Default-Deny-Korrektheit
    mit Diensten"), zeigen aber eine redundante Freigabe an (Korollar "Überlappung").
    """
    if isinstance(specs, str) or not isinstance(specs, (list, tuple)):
        raise PlanError("Dienste müssen als Liste angegeben werden, z. B. [tcp/22, tcp/443]")
    if not specs:
        raise PlanError("Die Dienstliste darf nicht leer sein (sonst würde nichts freigegeben)")
    raw: dict = {}
    others: set = set()
    warnings: List[str] = []
    prefix = f"{where}: " if where else ""
    for spec in specs:
        proto, interval = parse_service_entry(spec)
        if interval is None:
            if proto in others:
                warnings.append(f"{prefix}{proto} steht mehrfach in der Dienstliste")
            others.add(proto)
        else:
            raw.setdefault(proto, []).append(interval)
    for proto, intervals in raw.items():
        for first, second in overlapping(intervals):
            warnings.append(
                f"{prefix}{_format_interval(proto, *first)} und {_format_interval(proto, *second)} überlappen"
            )
    result = ServiceSet(tuple((p, tuple(v)) for p, v in raw.items()), frozenset(others))
    return result, tuple(warnings)


def parse_service(spec: Any) -> Service:
    """Ein konkreter Zieldienst eines Pakets: ``"tcp/443"``, ``("udp", 53)`` oder ``"icmp"``.

    Anders als in Freigaben sind hier einzelne Ports einschließlich 0 erlaubt (ein Paket kann
    jeden Zielport tragen). Rückgabe: (Protokoll, Port oder None).
    """
    if isinstance(spec, tuple):
        if len(spec) != 2:
            raise PlanError(f"Dienst {spec!r}: (Protokoll, Port) erwartet")
        proto, port = spec
        proto = str(proto).strip().lower()
    elif isinstance(spec, str):
        proto, _, rest = spec.strip().lower().partition("/")
        port = rest.strip() if rest else None
    else:
        raise PlanError(f"Dienst {spec!r}: Text wie 'tcp/443' oder Tupel erwartet")
    if proto in OTHER_PROTOCOLS:
        if port not in (None, ""):
            raise PlanError(f"Dienst {spec!r}: {proto} hat keine Ports")
        return proto, None
    if proto not in PORT_PROTOCOLS:
        raise PlanError(f"Dienst {spec!r}: unbekanntes Protokoll {proto!r}")
    try:
        number = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise PlanError(f"Dienst {spec!r}: für {proto} wird ein Port benötigt") from exc
    check_interval(number, number)
    return proto, number
