"""Claude Agent SDK wiring for the Security Analyst agent.

Defines the system prompt (persona + workflow + log schema + output format) and
registers the tool functions in `tools.py` so the model can drive the analysis
autonomously when interaction is required.

The Streamlit app can either:
  * call the tools directly in a deterministic pipeline (preferred for the
    happy path), or
  * spawn the agent loop here for free-form Q&A and edge cases.
"""

from __future__ import annotations

from typing import Any

from . import tools

SYSTEM_PROMPT = """\
You are a **Security Analyst** in charge of defining the TrustSec contracts between
endpoints connected to a large Cisco SD-Access network. The customer's management
wants to switch the TrustSec matrix default rule to `deny-ip` as part of their
Zero-Trust programme. Your job is to propose the explicit `permit` (and selective
`deny`) contracts that must exist for legitimate traffic to keep flowing.

## Workflow

1. Ask the user **which syslog server** the SG-ACL hits are being exported to
   (host, credentials/key, log file path), or accept a local file path.
2. Ask the user **for which period** to analyse (start and end timestamps).
3. Ask the user **for the SGT/DGT dictionary** (file path with id→name, or paste
   the mapping inline). If, during analysis, you encounter SGT/DGT IDs not in the
   dictionary, ask the user inline for those specific names.
4. Fetch and parse the logs.
5. Classify each unique flow tuple into exactly one of:
   - **business_relevant**: legitimate production protocols.
   - **default**: not unambiguously business, but plausibly legitimate for the SGT pair.
   - **business_irrelevant**: explicitly non-production (peer-to-peer, mining, etc.).
   - **harmful**: known-malicious (Talos-flagged, scan/sniff patterns, exfil).
6. Group classified flows into one **contract** per (Source SGT, Destination SGT) pair.
   Each contract contains one or more **ACEs** (protocol / src port / dst port → action).
   Action is `permit` for business_relevant + default, `deny` for the rest.
   The matrix-wide default rule remains `deny-ip` — do not emit explicit rows for it.
7. Produce the final markdown table for the manager to review.

## Log entry schema (`%RBM-6-SGACLHIT`)

`ingress_interface` (network device ingress)
`sgacl_name` (filtering ACL)
`action` (observed permit/deny on the device)
`protocol` (udp/tcp/icmp/...)
`src-vrf`, `src-ip`, `src-port`
`dest-vrf`, `dest-ip`, `dest-port`
`sgt` (sender Scalable Group Tag)
`dgt` (receiver Scalable Group Tag)
`logging_interval_hits` (packets observed in the 5-minute interval)

## Required output

A single markdown table with columns:

`Source SGT | Destination SGT | Contract Name | Protocol | Source Port | Destination Port | Action`

Followed by a one-line footer reminding the reviewer that the matrix default is `deny-ip`.

Be precise. Prefer asking a clarifying question over guessing. When you make a
classification judgement, briefly state the reasoning in chat (the per-flow
rationale will also be stored in SQLite).
"""


def build_tool_definitions(state: tools.AgentState) -> list[dict[str, Any]]:
    """Return Anthropic-style tool definitions bound to a state object.

    The Claude Agent SDK consumes a similar shape; alternatively these can be
    passed directly to `anthropic.messages.create(tools=...)`.
    """
    return [
        {
            "name": "configure_source",
            "description": "Configure the syslog source (local files or SSH to a collector).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["local", "ssh"]},
                    "options": {"type": "object"},
                },
                "required": ["kind", "options"],
            },
        },
        {
            "name": "set_window",
            "description": "Set the analysis time window. Pass ISO-8601 timestamps.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                },
                "required": ["start", "end"],
            },
        },
        {
            "name": "set_sgt_dictionary",
            "description": "Load the SGT/DGT id→name dictionary from a file path or inline mapping.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "mapping": {
                        "type": "object",
                        "description": "Inline mapping: {\"100\": \"Employees\", ...}",
                    },
                },
            },
        },
        {
            "name": "register_sgt_name",
            "description": "Register a single SGT id→name (used when a new id is encountered).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sgt_id": {"type": "integer"},
                    "name": {"type": "string"},
                },
                "required": ["sgt_id", "name"],
            },
        },
        {
            "name": "fetch_and_parse_logs",
            "description": "Fetch logs from the configured source, parse SGACLHIT entries, "
                          "and aggregate unique flow tuples. Requires source + window first.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "list_missing_sgt_names",
            "description": "Return the list of SGT/DGT IDs present in logs but missing from the dictionary.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "classify_flows",
            "description": "Classify aggregated flows into the four TrustSec categories. "
                          "Requires the dictionary to be loaded.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "build_matrix",
            "description": "Build contracts from classified flows and return the markdown matrix.",
            "input_schema": {"type": "object", "properties": {}},
        },
    ]


def dispatch(state: tools.AgentState, name: str, arguments: dict[str, Any]) -> Any:
    """Dispatch a tool call by name. Used by both the SDK and the Streamlit pipeline."""
    handler = {
        "configure_source": lambda: tools.configure_source(state, **arguments),
        "set_window": lambda: tools.set_window(state, **arguments),
        "set_sgt_dictionary": lambda: tools.set_sgt_dictionary(state, **arguments),
        "register_sgt_name": lambda: tools.register_sgt_name(state, **arguments),
        "fetch_and_parse_logs": lambda: tools.fetch_and_parse_logs(state),
        "list_missing_sgt_names": lambda: tools.list_missing_sgt_names(state),
        "classify_flows": lambda: tools.classify_flows(state),
        "build_matrix": lambda: tools.build_matrix(state),
    }.get(name)
    if handler is None:
        raise ValueError(f"Unknown tool: {name}")
    return handler()
