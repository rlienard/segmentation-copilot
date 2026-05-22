"""Pure-Python tool implementations that the Claude agent invokes.

These are deliberately framework-agnostic so they can be wrapped either by the
`claude-agent-sdk` tool registry or called directly from the Streamlit app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anthropic import Anthropic
from dateutil import parser as date_parser

from . import aggregator, classify, contracts, db, parser, sgt
from .sources import LocalFileSource, LogSourceConfig, SSHSource


@dataclass
class AgentState:
    """Mutable scratchpad shared across tool calls within one run."""

    db_path: str
    api_key: str | None = None
    run_id: int | None = None
    source_config: LogSourceConfig | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    sgt_dict: sgt.SGTDictionary | None = None
    raw_lines: list[str] = field(default_factory=list)
    events: list[parser.FlowEvent] = field(default_factory=list)
    aggregated: list[aggregator.AggregatedFlow] = field(default_factory=list)
    classified: list[tuple[aggregator.AggregatedFlow, str, str]] = field(default_factory=list)
    contracts: list[dict] = field(default_factory=list)
    matrix_markdown: str | None = None


def configure_source(state: AgentState, kind: str, options: dict[str, Any]) -> str:
    if kind not in {"local", "ssh"}:
        raise ValueError(f"Unsupported log source kind: {kind}")
    state.source_config = LogSourceConfig(kind=kind, options=options)
    return f"Configured {kind} log source."


def set_window(state: AgentState, start: str, end: str) -> str:
    state.window_start = date_parser.parse(start)
    state.window_end = date_parser.parse(end)
    return f"Analysis window: {state.window_start.isoformat()} → {state.window_end.isoformat()}."


def set_sgt_dictionary(state: AgentState, mapping: dict[str, str] | None = None,
                      file_path: str | None = None) -> str:
    if file_path:
        state.sgt_dict = sgt.load_from_file(file_path)
    elif mapping:
        state.sgt_dict = sgt.SGTDictionary(names={int(k): v for k, v in mapping.items()})
    else:
        raise ValueError("Provide either `mapping` or `file_path`.")
    return f"SGT dictionary loaded with {len(state.sgt_dict.names)} entries."


def register_sgt_name(state: AgentState, sgt_id: int, name: str) -> str:
    if state.sgt_dict is None:
        state.sgt_dict = sgt.SGTDictionary(names={})
    state.sgt_dict.register(int(sgt_id), name)
    return f"Registered SGT {sgt_id} → {name}."


def fetch_and_parse_logs(state: AgentState) -> dict[str, Any]:
    if state.source_config is None or state.window_start is None or state.window_end is None:
        raise RuntimeError("Source and time window must be configured first.")

    source = _build_source(state.source_config)
    state.raw_lines = list(source.fetch(state.window_start, state.window_end))
    state.events = list(parser.parse_lines(state.raw_lines))
    state.aggregated = aggregator.aggregate(state.events)

    if state.run_id is None:
        state.run_id = db.create_run(
            state.db_path, state.source_config.kind, state.window_start, state.window_end
        )
    db.insert_flow_events(state.db_path, state.run_id, state.events)

    return {
        "raw_lines": len(state.raw_lines),
        "parsed_events": len(state.events),
        "unique_flows": len(state.aggregated),
        "unique_sgts": sorted({e.sgt for e in state.events} | {e.dgt for e in state.events}),
    }


def list_missing_sgt_names(state: AgentState) -> list[int]:
    if state.sgt_dict is None:
        return sorted({e.sgt for e in state.events} | {e.dgt for e in state.events})
    ids = {e.sgt for e in state.events} | {e.dgt for e in state.events}
    return state.sgt_dict.missing_ids(sorted(ids))


def classify_flows(state: AgentState, model: str = "claude-opus-4-7") -> dict[str, int]:
    if not state.aggregated:
        raise RuntimeError("No aggregated flows. Run fetch_and_parse_logs first.")
    if state.sgt_dict is None:
        raise RuntimeError("SGT dictionary not configured.")

    client = Anthropic(api_key=state.api_key) if state.api_key else Anthropic()
    state.classified = classify.classify_batch(
        state.aggregated, state.sgt_dict, client=client, model=model
    )
    db.insert_classifications(state.db_path, state.run_id, state.classified)

    counts: dict[str, int] = {}
    for _, category, _ in state.classified:
        counts[category] = counts.get(category, 0) + 1
    return counts


def build_matrix(state: AgentState) -> str:
    if not state.classified:
        raise RuntimeError("Classify flows before building the matrix.")
    state.contracts = contracts.build_contracts(state.classified, state.sgt_dict)
    db.insert_contracts(state.db_path, state.run_id, state.contracts)
    state.matrix_markdown = contracts.render_markdown(state.contracts)
    db.set_run_status(state.db_path, state.run_id, "complete")
    return state.matrix_markdown


def _build_source(cfg: LogSourceConfig):
    if cfg.kind == "local":
        return LocalFileSource.from_config(cfg)
    if cfg.kind == "ssh":
        return SSHSource.from_config(cfg)
    raise ValueError(f"Unknown source kind: {cfg.kind}")
