"""Parser for Cisco SG-ACL hit syslog entries (%RBM-6-SGACLHIT)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

from dateutil import parser as date_parser


@dataclass(frozen=True)
class FlowEvent:
    ts: datetime | None
    ingress_interface: str
    sgacl_name: str
    observed_action: str
    protocol: str
    src_vrf: str
    src_ip: str
    src_port: str
    dst_vrf: str
    dst_ip: str
    dst_port: str
    sgt: int
    dgt: int
    hits: int
    raw: str


_FIELD_RE = re.compile(r"(\w[\w-]*)='([^']*)'")
_SGACLHIT_RE = re.compile(r"%RBM-\d+-SGACLHIT:")
_TS_RE = re.compile(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def _parse_ts(line: str) -> datetime | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        return date_parser.parse(m.group(1), fuzzy=True)
    except (ValueError, OverflowError):
        return None


def _to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_line(line: str) -> FlowEvent | None:
    """Parse a single syslog line. Returns None if the line is not an SGACLHIT."""
    if not _SGACLHIT_RE.search(line):
        return None

    fields = dict(_FIELD_RE.findall(line))
    if not fields:
        return None

    required = {"sgt", "dgt", "protocol"}
    if not required.issubset(fields):
        return None

    return FlowEvent(
        ts=_parse_ts(line),
        ingress_interface=fields.get("ingress_interface", ""),
        sgacl_name=fields.get("sgacl_name", ""),
        observed_action=fields.get("action", ""),
        protocol=fields.get("protocol", "").lower(),
        src_vrf=fields.get("src-vrf", ""),
        src_ip=fields.get("src-ip", ""),
        src_port=fields.get("src-port", "0"),
        dst_vrf=fields.get("dest-vrf", ""),
        dst_ip=fields.get("dest-ip", ""),
        dst_port=fields.get("dest-port", "0"),
        sgt=_to_int(fields.get("sgt", "0")),
        dgt=_to_int(fields.get("dgt", "0")),
        hits=_to_int(fields.get("logging_interval_hits", "1"), default=1),
        raw=line.rstrip(),
    )


def parse_lines(lines: Iterable[str]) -> Iterator[FlowEvent]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event
