#!/usr/bin/env pytest
"""
tests/test_parse_logs.py — Validate parse_syslog against RFC5424 lines.
"""

import pytest
from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

# Load sample lines
with open("data/sample_syslog.log", "r") as f:
    SAMPLE_LINES = [line.strip() for line in f if line.strip()]

def test_parse_basic_record():
    record = parse_syslog(SAMPLE_LINES[0])
    assert record["pri"] == "13"
    assert record["version"] == "1"
    assert record["timestamp"] == "2025-05-15T14:31:02Z"
    assert record["host"] == "host1"
    assert record["appname"] == "cron"
    assert record["procid"] == "1002"
    assert record["msgid"] == "ID48"
    assert record["structured_data"] == "-"
    assert record["message"].startswith("(root) CMD")

def test_parse_with_structured_data():
    record = parse_syslog(SAMPLE_LINES[1])
    assert record["pri"] == "34"
    assert record["structured_data"].startswith("[exampleSDID@32473")
    assert "eventSource" in record["structured_data"]
    assert "User login succeeded" in record["message"]

@pytest.mark.parametrize("line", [
    "",                               # empty
    "Not a syslog line",              # totally wrong
    "<13>2 badtimestamp host app 1 1 - msg",  # wrong version/timestamp
])
def test_malformed_lines_raise(line):
    with pytest.raises(UnsupportedFormat):
        parse_syslog(line)

def test_all_sample_lines_parse():
    # Ensure every sample line parses without error
    for line in SAMPLE_LINES:
        parse_syslog(line)  # should not raise

