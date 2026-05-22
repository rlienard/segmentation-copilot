from pathlib import Path

from segmentation_copilot.parser import parse_line, parse_lines


EXAMPLE = (
    "Jun 18 10:17:22.205: %RBM-6-SGACLHIT: ingress_interface='GigabitEthernet1/0/1' "
    "sgacl_name='testv4' action='Permit' protocol='udp' src-vrf='default' "
    "src-ip='25.1.1.1' src-port='96' dest-vrf='default' dest-ip='25.1.1.2' "
    "dest-port='0' sgt='100' dgt='200' logging_interval_hits='12'"
)


def test_parse_line_extracts_all_fields():
    event = parse_line(EXAMPLE)
    assert event is not None
    assert event.ingress_interface == "GigabitEthernet1/0/1"
    assert event.sgacl_name == "testv4"
    assert event.observed_action == "Permit"
    assert event.protocol == "udp"
    assert event.src_vrf == "default"
    assert event.src_ip == "25.1.1.1"
    assert event.src_port == "96"
    assert event.dst_vrf == "default"
    assert event.dst_ip == "25.1.1.2"
    assert event.dst_port == "0"
    assert event.sgt == 100
    assert event.dgt == 200
    assert event.hits == 12
    assert event.ts is not None


def test_parse_line_skips_non_sgaclhit():
    assert parse_line("Jun 18 10:21:00: %SYS-5-CONFIG_I: some other message") is None
    assert parse_line("") is None
    assert parse_line("random text") is None


def test_parse_line_handles_missing_optional_fields():
    minimal = (
        "Jun 18 10:00:00: %RBM-6-SGACLHIT: protocol='tcp' sgt='10' dgt='20' "
        "logging_interval_hits='1'"
    )
    event = parse_line(minimal)
    assert event is not None
    assert event.sgt == 10
    assert event.dgt == 20
    assert event.ingress_interface == ""


def test_parse_lines_from_fixture():
    fixture = Path(__file__).parent / "fixtures" / "sample.log"
    events = list(parse_lines(fixture.read_text().splitlines()))
    # 6 SGACLHIT lines in the fixture, plus one non-SGACLHIT to ignore.
    assert len(events) == 6
    assert {e.sgt for e in events} == {100, 300}
    assert {e.dgt for e in events} == {200, 400, 999}
