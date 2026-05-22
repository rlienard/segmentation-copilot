"""Build TrustSec contracts from classified flows and render the matrix."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .aggregator import AggregatedFlow
from .sgt import SGTDictionary


PERMIT_CATEGORIES = {"business_relevant", "default"}
DENY_CATEGORIES = {"business_irrelevant", "harmful"}


def _action_for(category: str) -> str:
    if category in PERMIT_CATEGORIES:
        return "permit"
    if category in DENY_CATEGORIES:
        return "deny"
    return "permit"


def _contract_name(src_name: str, dst_name: str) -> str:
    return f"{src_name}_to_{dst_name}"


def build_contracts(
    classified: list[tuple[AggregatedFlow, str, str]],
    sgt_dict: SGTDictionary,
) -> list[dict]:
    """Group classified flows into one contract per (src_sgt, dst_sgt) pair.

    Each contract owns a list of ACEs (protocol, src_port, dst_port, action). Duplicate
    ACEs (same proto/ports/action) are collapsed; conflicts (same proto/ports with both
    permit and deny) resolve to deny (least-privilege).
    """
    by_pair: dict[tuple[int, int], dict] = {}

    for flow, category, _ in classified:
        pair = (flow.key.sgt, flow.key.dgt)
        src_name = sgt_dict.get_or_default(flow.key.sgt)
        dst_name = sgt_dict.get_or_default(flow.key.dgt)
        contract = by_pair.setdefault(
            pair,
            {
                "src_sgt": flow.key.sgt,
                "dst_sgt": flow.key.dgt,
                "src_sgt_name": src_name,
                "dst_sgt_name": dst_name,
                "name": _contract_name(src_name, dst_name),
                "aces": {},
            },
        )
        ace_key = (flow.key.protocol, flow.key.src_port, flow.key.dst_port)
        action = _action_for(category)
        existing = contract["aces"].get(ace_key)
        if existing and existing["action"] != action:
            # Conflict — least-privilege wins.
            action = "deny"
        contract["aces"][ace_key] = {
            "protocol": flow.key.protocol,
            "src_port": flow.key.src_port,
            "dst_port": flow.key.dst_port,
            "action": action,
            "source_category": category,
        }

    contracts: list[dict] = []
    for contract in by_pair.values():
        contract["aces"] = sorted(
            contract["aces"].values(),
            # deny first (more specific / safer to apply first), then by protocol/port
            key=lambda a: (0 if a["action"] == "deny" else 1, a["protocol"], a["dst_port"]),
        )
        contracts.append(contract)

    contracts.sort(key=lambda c: (c["src_sgt"], c["dst_sgt"]))
    return contracts


def render_markdown(contracts: list[dict]) -> str:
    header = (
        "| Source SGT | Destination SGT | Contract Name | Protocol | Source Port | Destination Port | Action |\n"
        "|------------|-----------------|---------------|----------|-------------|------------------|--------|"
    )
    rows: list[str] = [header]
    for c in contracts:
        for ace in c["aces"]:
            rows.append(
                f"| {c['src_sgt_name']} | {c['dst_sgt_name']} | {c['name']} | "
                f"{ace['protocol']} | {ace['src_port']} | {ace['dst_port']} | {ace['action']} |"
            )
    rows.append("")
    rows.append("> **Default matrix rule:** `deny-ip` — any (Source SGT, Destination SGT) "
                "pair not listed above is denied.")
    return "\n".join(rows)
