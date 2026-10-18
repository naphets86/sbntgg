"""Ausgabeformate des Plans: Tabelle, CSV, JSON."""
from __future__ import annotations

import csv
import io
import json
from typing import List, Sequence

from .models import CSV_FIELDS, FORMATS, Plan, PlanError


def _percent(plan: Plan) -> float:
    return round(plan.utilization, 2)


def render_json(plan: Plan) -> str:
    payload = {
        "base_network": str(plan.base_network),
        "total_addresses": plan.total_addresses,
        "allocated_addresses": plan.allocated_addresses,
        "free_addresses": plan.free_addresses,
        "utilization_percent": _percent(plan),
        "free_ranges": [str(n) for n in plan.free_ranges],
        "subnets": [s.as_dict() for s in plan.subnets],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_csv(plan: Plan) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for subnet in plan.subnets:
        row = subnet.as_dict()
        row["access"] = ";".join(row["access"])
        writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
    return buffer.getvalue().rstrip("\n")


def render_table(plan: Plan) -> str:
    headers = [
        "Gruppe", "VLAN", "Netz/CIDR", "Subnetzmaske", "Gateway",
        "Host-Range", "Broadcast", "Nutzbar", "Bedarf",
    ]
    rows = [
        [
            s.group,
            str(s.vlan_id),
            str(s.network),
            s.netmask,
            "-" if s.gateway is None else str(s.gateway),
            f"{s.first_host} - {s.last_host}",
            "-" if s.broadcast is None else str(s.broadcast),
            str(s.usable_hosts),
            str(s.requested_hosts),
        ]
        for s in plan.subnets
    ]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    out: List[str] = [line(headers), line(["-" * w for w in widths]), *(line(r) for r in rows)]
    free = ", ".join(str(n) for n in plan.free_ranges) or "-"
    out += [
        "",
        f"Basisnetz: {plan.base_network} ({plan.total_addresses} Adressen)",
        f"Belegt: {plan.allocated_addresses} ({_percent(plan)} %), frei: {plan.free_addresses}",
        f"Freie Bereiche: {free}",
    ]
    return "\n".join(out)


def render(plan: Plan, fmt: str) -> str:
    renderers = {"table": render_table, "csv": render_csv, "json": render_json}
    if fmt not in renderers:
        raise PlanError(f"Unbekanntes Format {fmt!r}, erlaubt: {list(FORMATS)}")
    return renderers[fmt](plan)
