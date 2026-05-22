from pathlib import Path

from segmentation_copilot.aggregator import aggregate, bucket_port
from segmentation_copilot.parser import parse_lines


def test_bucket_port_collapses_ephemeral_src():
    assert bucket_port("52341", "src") == "any"
    assert bucket_port("443", "src") == "443"
    assert bucket_port("443", "dst") == "443"
    assert bucket_port("0", "dst") == "any"
    assert bucket_port("not-a-port", "src") == "any"


def test_aggregate_groups_and_sums_hits():
    fixture = Path(__file__).parent / "fixtures" / "sample.log"
    events = list(parse_lines(fixture.read_text().splitlines()))
    flows = aggregate(events)

    # All ephemeral src ports collapse to 'any', so flows are grouped by
    # (sgt, dgt, protocol, src=any, dst=443/80/53/6881/4444/0)
    keys = {f.key.as_tuple() for f in flows}
    assert (100, 200, "tcp", "any", "443") in keys
    assert (100, 200, "tcp", "any", "80") in keys
    assert (100, 400, "udp", "any", "53") in keys
    assert (300, 999, "tcp", "any", "6881") in keys

    # Total hits for HTTPS flow == 248 (only one event).
    https = next(f for f in flows if f.key.dst_port == "443")
    assert https.total_hits == 248
    # DNS to resolvers had 1200 hits in one event.
    dns = next(f for f in flows if f.key.dst_port == "53")
    assert dns.total_hits == 1200


def test_aggregate_sorts_by_hits_descending():
    fixture = Path(__file__).parent / "fixtures" / "sample.log"
    events = list(parse_lines(fixture.read_text().splitlines()))
    flows = aggregate(events)
    hits = [f.total_hits for f in flows]
    assert hits == sorted(hits, reverse=True)
