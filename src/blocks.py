"""Blockalgebra: freie Bereiche, Packbarkeit und konstruktive Zuteilung.

Umgesetzt werden die Aussagen der Arbeit zu
  * Satz "Freie Bereiche" (maximale freie Blöcke, minimale CIDR-Zerlegung),
  * Satz "Packbarkeit" (Bedingung (*)) und Satz "Planung mit Bestand und mehreren Pools",
  * Korollar "Verlustfreie Erweiterbarkeit" (``can_extend``),
  * dem konstruktiven Beweis von Satz "Packbarkeit" (``pack``).

Alle Blöcke einer Betrachtung müssen derselben IP-Version angehören.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Sequence, Tuple

from .models import IPNetwork, PlanError


def _same_version(nets: Sequence[IPNetwork]) -> None:
    if len({n.version for n in nets}) > 1:
        raise PlanError("IPv4- und IPv6-Netze lassen sich nicht in einem Plan mischen")


def free_ranges_in_pool(pool: IPNetwork, occupied: Sequence[IPNetwork]) -> Tuple[IPNetwork, ...]:
    """Minimale CIDR-Zerlegung aller Lücken des Pools (maximale freie Blöcke).

    ``occupied`` müssen im Pool liegen und paarweise disjunkt sein; Lücken vor, zwischen
    und hinter den belegten Netzen werden berücksichtigt.
    """
    addr = type(pool.network_address)
    pos = int(pool.network_address)
    end = int(pool.broadcast_address)
    free: List[IPNetwork] = []
    for net in sorted(occupied, key=lambda n: int(n.network_address)):
        start = int(net.network_address)
        if start > pos:
            free.extend(ipaddress.summarize_address_range(addr(pos), addr(start - 1)))
        pos = int(net.broadcast_address) + 1
    if pos <= end:
        free.extend(ipaddress.summarize_address_range(addr(pos), addr(end)))
    return tuple(free)


def check_occupied(pools: Sequence[IPNetwork], occupied: Sequence[IPNetwork]) -> Dict[IPNetwork, List[IPNetwork]]:
    """Ordnet belegte Netze ihrem Pool zu und prüft Disjunktheit und Enthaltensein."""
    _same_version(list(pools) + list(occupied))
    for i, a in enumerate(pools):
        for b in pools[i + 1 :]:
            if a.overlaps(b):
                raise PlanError(f"Die Pools {a} und {b} überschneiden sich")
    per_pool: Dict[IPNetwork, List[IPNetwork]] = {p: [] for p in pools}
    for net in occupied:
        owner = next((p for p in pools if net.subnet_of(p)), None)  # type: ignore[arg-type]
        if owner is None:
            raise PlanError(f"Das Netz {net} liegt in keinem Pool")
        per_pool[owner].append(net)
    items = sorted(occupied, key=lambda n: (int(n.network_address), n.prefixlen))
    for a, b in zip(items, items[1:]):
        if a.overlaps(b):
            raise PlanError(f"Die belegten Netze {a} und {b} überschneiden sich")
    return per_pool


def maximal_free_blocks(pools: Sequence[IPNetwork], occupied: Sequence[IPNetwork] = ()) -> Tuple[IPNetwork, ...]:
    """Die Menge M aus Satz "Planung mit Bestand und mehreren Pools"."""
    per_pool = check_occupied(pools, occupied)
    blocks: List[IPNetwork] = []
    for pool in sorted(pools, key=lambda p: int(p.network_address)):
        blocks.extend(free_ranges_in_pool(pool, per_pool[pool]))
    return tuple(blocks)


def packable(free_blocks: Sequence[IPNetwork], sizes: Sequence[int]) -> bool:
    """Bedingung (*) aus Satz "Packbarkeit".

    ``sizes`` sind Blockgrößen (Zweierpotenzen). Für jedes j muss die Summe der Aufträge
    mit Größe >= 2^j höchstens die Summe der freien Blöcke mit Größe >= 2^j sein.
    """
    for s in sizes:
        if s < 1 or s & (s - 1):
            raise PlanError(f"Blockgröße {s} ist keine Zweierpotenz")
    top = max([s.bit_length() - 1 for s in sizes] + [b.num_addresses.bit_length() - 1 for b in free_blocks] + [0])
    for j in range(top + 1):
        need = sum(s for s in sizes if s >= 1 << j)
        have = sum(b.num_addresses for b in free_blocks if b.num_addresses >= 1 << j)
        if need > have:
            return False
    return True


def pack(free_blocks: Sequence[IPNetwork], items: Sequence[Tuple[str, int]]) -> Dict[str, IPNetwork]:
    """Konstruktives Verfahren aus dem Beweis von Satz "Packbarkeit".

    ``items`` sind (Schlüssel, Blockgröße) in der gewünschten Reihenfolge; die Aufträge
    werden stabil nach absteigender Größe verarbeitet und lückenlos ab dem Füllstand in den
    freien Block mit der kleinsten ausreichenden Restkapazität gelegt (bei Gleichstand der
    mit der kleineren Adresse). Ist ``packable`` erfüllt, gelingt das immer.
    """
    sizes = [size for _, size in items]
    if not packable(free_blocks, sizes):
        raise PlanError("Platzmangel: die Gruppen passen nicht in die freien Bereiche")
    blocks = sorted(free_blocks, key=lambda b: int(b.network_address))
    fill = [0] * len(blocks)
    result: Dict[str, IPNetwork] = {}
    for key, size in sorted(items, key=lambda item: -item[1]):
        candidates = [
            (blocks[i].num_addresses - fill[i], int(blocks[i].network_address), i)
            for i in range(len(blocks))
            if blocks[i].num_addresses - fill[i] >= size
        ]
        if not candidates:  # pragma: no cover - durch packable() ausgeschlossen
            raise PlanError("Platzmangel: die Gruppen passen nicht in die freien Bereiche")
        _, _, idx = min(candidates)
        start = int(blocks[idx].network_address) + fill[idx]
        fill[idx] += size
        prefix = blocks[idx].max_prefixlen - (size.bit_length() - 1)
        result[key] = type(blocks[idx])((start, prefix))
    return result


def can_extend(free_blocks: Sequence[IPNetwork], new_sizes: Sequence[int]) -> bool:
    """Korollar "Verlustfreie Erweiterbarkeit".

    Bei freien Bereichen aus einem Plan (maximale Blöcke) ist die Erweiterung genau dann
    möglich, wenn die Summe der neuen Blockgrößen höchstens F beträgt; ``packable`` prüft
    die allgemeine Bedingung (*) und stimmt für solche Bereiche damit überein.
    """
    return packable(free_blocks, new_sizes)


def block_size_for(total: int) -> int:
    """Kleinste Zweierpotenz >= total (Satz "Minimalität des Blocks")."""
    if total < 1:
        raise PlanError(f"Bedarf {total} muss mindestens 1 sein")
    return 1 << (total - 1).bit_length()


def parent_block(net: IPNetwork) -> Optional[IPNetwork]:
    """Elternblock (doppelte Größe) oder None bei Präfixlänge 0."""
    if net.prefixlen == 0:
        return None
    return net.supernet(prefixlen_diff=1)
