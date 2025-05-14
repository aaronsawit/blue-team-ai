# tests/test_parse_logs.py
import pytest

from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

def test_parse_syslog_valid():
    """
    Given a minimal valid syslog entry, parse_syslog should return a dict.
    """
    log_str = "<34>1 2025-05-15T02:00:00Z host app - - - test message"
    result = parse_syslog(log_str)
    assert isinstance(result, dict)


def test_parse_syslog_invalid():
    """
    Given a non-syslog string, parse_syslog should raise UnsupportedFormat.
    """
    log_str = "garbage"
    with pytest.raises(UnsupportedFormat):
        parse_syslog(log_str)
