#!/usr/bin/env pytest
"""
tests/test_parse_logs.py — Validate parse_syslog against RFC5424 lines.
"""

import pytest
from pathlib import Path
from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat


def test_valid_syslog_line():
    log = "<34>1 2025-05-15T14:31:02Z host1 sshd 1001 ID123 - Accepted password for user from 192.168.1.1"
    result = parse_syslog(log)
    assert result["host"] == "host1"
    assert result["appname"] == "sshd"
    assert result["message"].startswith("Accepted password")


def test_empty_line_raises():
    with pytest.raises(UnsupportedFormat):
        parse_syslog("")


def test_totally_invalid_line_raises():
    with pytest.raises(UnsupportedFormat):
        parse_syslog("<<< totally invalid >>>")

# Load sample lines from data directory
project_root = Path(__file__).parent.parent
possible_paths = [
    project_root / "blue_team_ai" / "data" / "sample_syslog.log",
    project_root / "data" / "sample_syslog.log",
]
for path in possible_paths:
    if path.is_file():
        sample_file = path
        break
else:
    pytest.exit("sample_syslog.log not found in expected data directories")

with open(sample_file, "r") as f:
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
    assert record["appname"] == "sshd"
    assert record["structured_data"].startswith("[exampleSDID@32473")
    assert "eventSource" in record["structured_data"]
    assert "User login succeeded" in record["message"]


def test_parse_nginx_basic():
    record = parse_syslog(SAMPLE_LINES[2])
    assert record["pri"] == "11"
    assert record["appname"] == "nginx"
    assert record["message"].startswith("GET /index.html 200")


def test_parse_postgres_with_sd():
    record = parse_syslog(SAMPLE_LINES[3])
    assert record["pri"] == "22"
    assert record["appname"] == "postgres"
    assert record["structured_data"].startswith("[meta")
    assert record["message"] == "Connection established"


def test_parse_scheduled_task():
    record = parse_syslog(SAMPLE_LINES[4])
    assert record["appname"] == "app"
    assert record["message"].startswith("Starting scheduled task")


def test_parse_cleanup_process():
    record = parse_syslog(SAMPLE_LINES[5])
    assert record["appname"] == "daemon"
    assert "Completed cleanup process" in record["message"]


def test_parse_accepted_password_multiple():
    record = parse_syslog(SAMPLE_LINES[6])
    assert record["appname"] == "sshd"
    assert "Accepted password for user from" in record["message"]


def test_parse_combined_log_format():
    record = parse_syslog(SAMPLE_LINES[7])
    assert record["appname"] == "nginx"
    assert "192.168.1.2" in record["message"]
    assert "GET /index.html HTTP/1.1" in record["message"]

@pytest.mark.parametrize("line", [
    "",
    "Not a syslog line",
    "<13>2 badtimestamp host app 1 1 - msg",
])
def test_malformed_lines_raise(line):
    with pytest.raises(UnsupportedFormat):
        parse_syslog(line)


def test_all_sample_lines_parse():
    for line in SAMPLE_LINES:
        parse_syslog(line)  # should not raise
