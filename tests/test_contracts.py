from segmentation_copilot.aggregator import AggregatedFlow, FlowKey
from segmentation_copilot.contracts import build_contracts, render_markdown
from segmentation_copilot.sgt import SGTDictionary


def _flow(sgt: int, dgt: int, protocol: str, dst_port: str, hits: int = 10) -> AggregatedFlow:
    return AggregatedFlow(
        key=FlowKey(sgt=sgt, dgt=dgt, protocol=protocol, src_port="any", dst_port=dst_port),
        total_hits=hits,
        event_count=1,
    )


def _dict() -> SGTDictionary:
    return SGTDictionary(names={100: "Employees", 200: "Web_Servers", 300: "Guests",
                                400: "DNS_Resolvers", 999: "Internet"})


def test_build_contracts_groups_by_sgt_pair():
    classified = [
        (_flow(100, 200, "tcp", "443"), "business_relevant", "https"),
        (_flow(100, 200, "tcp", "80"), "business_relevant", "http"),
        (_flow(100, 400, "udp", "53"), "business_relevant", "dns"),
        (_flow(300, 999, "tcp", "6881"), "business_irrelevant", "bittorrent"),
    ]
    contracts = build_contracts(classified, _dict())

    pairs = {(c["src_sgt_name"], c["dst_sgt_name"]) for c in contracts}
    assert pairs == {
        ("Employees", "Web_Servers"),
        ("Employees", "DNS_Resolvers"),
        ("Guests", "Internet"),
    }
    emp_to_web = next(c for c in contracts if c["dst_sgt_name"] == "Web_Servers")
    assert {a["dst_port"] for a in emp_to_web["aces"]} == {"443", "80"}
    assert all(a["action"] == "permit" for a in emp_to_web["aces"])

    guests = next(c for c in contracts if c["src_sgt_name"] == "Guests")
    assert guests["aces"][0]["action"] == "deny"


def test_conflicting_actions_resolve_to_deny():
    classified = [
        (_flow(100, 200, "tcp", "8080"), "business_relevant", "internal app"),
        (_flow(100, 200, "tcp", "8080"), "harmful", "Talos hit on this port"),
    ]
    contracts = build_contracts(classified, _dict())
    ace = contracts[0]["aces"][0]
    assert ace["action"] == "deny"


def test_render_markdown_shapes():
    classified = [(_flow(100, 200, "tcp", "443"), "business_relevant", "https")]
    md = render_markdown(build_contracts(classified, _dict()))
    assert "| Source SGT | Destination SGT |" in md
    assert "| Employees | Web_Servers | Employees_to_Web_Servers | tcp | any | 443 | permit |" in md
    assert "deny-ip" in md
