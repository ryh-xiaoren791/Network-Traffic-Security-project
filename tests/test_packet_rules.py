from src.core.filtering.packet_rules import match_packet_rule, match_packet_term, parse_packet_rule_term


SAMPLE_ROW = {
    "id": 7,
    "src_ip": "10.0.0.8",
    "dst_ip": "8.8.8.8",
    "src_port": 51515,
    "dst_port": 53,
    "proto": "UDP",
    "length": 128,
    "process_name": "powershell.exe",
    "source": "offline",
    "risk_level": "high",
    "ts_epoch": 12.5,
}


def test_parse_packet_rule_term_parses_compare_expression() -> None:
    assert parse_packet_rule_term("dst_port >= 53") == ("dst_port", ">=", "53")


def test_match_packet_term_supports_contains_alias() -> None:
    assert match_packet_term(SAMPLE_ROW, "process contains powershell")
    assert match_packet_term(SAMPLE_ROW, "ip.addr contains 8.8.8.8")


def test_match_packet_rule_supports_and_or_and_negation() -> None:
    expr = "proto==udp && dst_port==53 && !process contains chrome"
    assert match_packet_rule(SAMPLE_ROW, expr)
    assert match_packet_rule(SAMPLE_ROW, "risk==high || proto==tcp")
    assert not match_packet_rule(SAMPLE_ROW, "src_port < 100 && proto==tcp")
