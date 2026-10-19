"""Gemeinsame Hilfen für die neuen Tests."""
from typing import Any, Dict, List, Optional

from src.config import build_config
from src.planner import plan_subnets


def groups(*specs) -> List[Dict[str, Any]]:
    return [dict(name=n, hosts=h, **kw) for n, h, kw in specs]


def make(base="10.0.0.0/24", glist=None, **top):
    raw = {"base_network": base, "groups": glist or [{"name": "A", "hosts": 50}, {"name": "B", "hosts": 10, "access": ["A"]}]}
    raw.update(top)
    cfg = build_config(raw)
    return cfg, plan_subnets(cfg)
