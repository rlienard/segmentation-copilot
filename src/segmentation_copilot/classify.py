"""LLM-driven classification of aggregated flows into TrustSec categories."""

from __future__ import annotations

import json
from dataclasses import dataclass

from anthropic import Anthropic

from .aggregator import AggregatedFlow
from .sgt import SGTDictionary

CATEGORIES = ("business_relevant", "default", "business_irrelevant", "harmful")


CLASSIFY_SYSTEM_PROMPT = """You are a Cisco TrustSec Security Analyst.

Given a batch of network flows observed between Scalable Group Tags (SGTs), classify
each flow into exactly one of these categories:

- business_relevant: Legitimate production protocols (HTTP/HTTPS to known services,
  DNS, AD/Kerberos/LDAP, SMB to file servers, RDP/SSH for admin VLANs, etc.).
- default: Plausibly legitimate for production endpoints but not unambiguously a
  business protocol (e.g., ICMP, NTP, generic high-port TCP between trusted SGTs).
- business_irrelevant: Explicitly not production (peer-to-peer, BitTorrent, crypto
  mining stratum protocols, public game servers, etc.).
- harmful: Known-malicious traffic patterns (Talos-flagged C2 ports, broad
  scan/sniff patterns, exfiltration over unusual ports, EternalBlue/SMB exploit
  ports targeting endpoints that should not expose SMB).

Use the source and destination SGT names to inform context (e.g., traffic from
"Guests" to "Internal_Servers" is more suspicious than between two "Server" SGTs).

Return STRICT JSON, no prose, matching this schema:
{
  "classifications": [
    {"index": 0, "category": "business_relevant", "rationale": "TCP/443 to web servers"},
    ...
  ]
}
"""


@dataclass
class FlowSummary:
    index: int
    src_sgt_name: str
    dst_sgt_name: str
    protocol: str
    src_port: str
    dst_port: str
    total_hits: int
    sample_dst_ips: list[str]


def summarise_flows(flows: list[AggregatedFlow], sgt_dict: SGTDictionary) -> list[FlowSummary]:
    return [
        FlowSummary(
            index=i,
            src_sgt_name=sgt_dict.get_or_default(f.key.sgt),
            dst_sgt_name=sgt_dict.get_or_default(f.key.dgt),
            protocol=f.key.protocol,
            src_port=f.key.src_port,
            dst_port=f.key.dst_port,
            total_hits=f.total_hits,
            sample_dst_ips=sorted(f.sample_dst_ips)[:3],
        )
        for i, f in enumerate(flows)
    ]


def classify_batch(
    flows: list[AggregatedFlow],
    sgt_dict: SGTDictionary,
    client: Anthropic | None = None,
    model: str = "claude-opus-4-7",
) -> list[tuple[AggregatedFlow, str, str]]:
    """Classify all flows in a single Claude call.

    Returns a list of (flow, category, rationale) tuples in the same order as `flows`.
    """
    if not flows:
        return []

    client = client or Anthropic()
    summaries = summarise_flows(flows, sgt_dict)
    user_payload = json.dumps(
        {
            "flows": [
                {
                    "index": s.index,
                    "src_sgt": s.src_sgt_name,
                    "dst_sgt": s.dst_sgt_name,
                    "protocol": s.protocol,
                    "src_port": s.src_port,
                    "dst_port": s.dst_port,
                    "total_hits": s.total_hits,
                    "sample_dst_ips": s.sample_dst_ips,
                }
                for s in summaries
            ]
        }
    )

    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=CLASSIFY_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_payload}],
    )
    text = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Classifier returned non-JSON: {text[:200]}") from exc

    by_index = {item["index"]: item for item in decoded["classifications"]}
    result: list[tuple[AggregatedFlow, str, str]] = []
    for i, flow in enumerate(flows):
        item = by_index.get(i)
        if item is None or item.get("category") not in CATEGORIES:
            result.append((flow, "default", "no classification returned; defaulted"))
            continue
        result.append((flow, item["category"], item.get("rationale", "")))
    return result
