"""Aggregate FlowEvents into unique flow tuples for classification."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .parser import FlowEvent

EPHEMERAL_PORT_THRESHOLD = 1024
ANY_PORT = "any"


def bucket_port(port: str, role: str) -> str:
    """Collapse ephemeral source ports to 'any'; keep well-known/registered ports literal.

    role: 'src' or 'dst'. Destination ports are kept as-is because they identify the
    service; source ports above 1024 are typically ephemeral and noisy.
    """
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return ANY_PORT

    if port_int == 0:
        return ANY_PORT
    if role == "src" and port_int >= EPHEMERAL_PORT_THRESHOLD:
        return ANY_PORT
    return str(port_int)


@dataclass
class FlowKey:
    sgt: int
    dgt: int
    protocol: str
    src_port: str
    dst_port: str

    def as_tuple(self) -> tuple[int, int, str, str, str]:
        return (self.sgt, self.dgt, self.protocol, self.src_port, self.dst_port)


@dataclass
class AggregatedFlow:
    key: FlowKey
    total_hits: int = 0
    event_count: int = 0
    sample_src_ips: set[str] = field(default_factory=set)
    sample_dst_ips: set[str] = field(default_factory=set)
    observed_actions: set[str] = field(default_factory=set)


def aggregate(events: Iterable[FlowEvent], sample_ip_limit: int = 5) -> list[AggregatedFlow]:
    buckets: dict[tuple, AggregatedFlow] = {}

    for event in events:
        key = FlowKey(
            sgt=event.sgt,
            dgt=event.dgt,
            protocol=event.protocol,
            src_port=bucket_port(event.src_port, "src"),
            dst_port=bucket_port(event.dst_port, "dst"),
        )
        agg = buckets.get(key.as_tuple())
        if agg is None:
            agg = AggregatedFlow(key=key)
            buckets[key.as_tuple()] = agg

        agg.total_hits += event.hits
        agg.event_count += 1
        if len(agg.sample_src_ips) < sample_ip_limit and event.src_ip:
            agg.sample_src_ips.add(event.src_ip)
        if len(agg.sample_dst_ips) < sample_ip_limit and event.dst_ip:
            agg.sample_dst_ips.add(event.dst_ip)
        if event.observed_action:
            agg.observed_actions.add(event.observed_action)

    return sorted(buckets.values(), key=lambda f: f.total_hits, reverse=True)
