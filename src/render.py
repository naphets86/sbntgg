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
    if plan.pools:
        payload["pools"] = [str(n) for n in plan.pools]
    if plan.reserved:
        payload["reserved"] = [str(n) for n in plan.reserved]
    if plan.site_blocks:
        payload["site_blocks"] = {site: str(net) for site, net in plan.site_blocks}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_csv(plan: Plan) -> str:
    buffer = io.StringIO()
    fields = CSV_FIELDS + (("site",) if any(s.site is not None for s in plan.subnets) else ())
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
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
    if any(s.site is not None for s in plan.subnets):
        headers.append("Standort")
        for row, s in zip(rows, plan.subnets):
            row.append(s.site or "-")
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    out: List[str] = [line(headers), line(["-" * w for w in widths]), *(line(r) for r in rows)]
    free = ", ".join(str(n) for n in plan.free_ranges) or "-"
    pools = ", ".join(str(n) for n in plan.all_pools)
    out += [
        "",
        f"Basisnetz: {pools} ({plan.total_addresses} Adressen)"
        if plan.pools
        else f"Basisnetz: {plan.base_network} ({plan.total_addresses} Adressen)",
        f"Belegt: {plan.allocated_addresses} ({_percent(plan)} %), frei: {plan.free_addresses}",
        f"Freie Bereiche: {free}",
    ]
    if plan.site_blocks:
        out.append("Standortblöcke: " + ", ".join(f"{site} {net}" for site, net in plan.site_blocks))
    return "\n".join(out)


def render(plan: Plan, fmt: str) -> str:
    renderers = {"table": render_table, "csv": render_csv, "json": render_json}
    if fmt not in renderers:
        raise PlanError(f"Unbekanntes Format {fmt!r}, erlaubt: {list(FORMATS)}")
    return renderers[fmt](plan)
