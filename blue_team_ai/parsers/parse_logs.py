#!/usr/bin/env python3
"""
parse_logs.py — Parse RFC5424-style syslog lines into a dict or raise UnsupportedFormat.
"""

import re
import argparse
import json
import sys

from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

# Regex for minimal RFC5424 format:
#   <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
SYSLOG_REGEX = re.compile(
    r'^<(?P<pri>\d+)>'              # Priority
    r'(?P<version>\d+) '            # Version
    r'(?P<timestamp>\S+) '          # Timestamp
    r'(?P<host>\S+) '               # Hostname
    r'(?P<appname>\S+) '            # Application name
    r'(?P<procid>\S+) '             # Process ID
    r'(?P<msgid>\S+) '              # Message ID
    r'(?P<structured_data>(?:-|\[.*?\])) '  # Structured data (or '-')
    r'(?P<message>.*)$'              # Message text
)

def parse_syslog(log_str):
    """
    Parse a single syslog entry into a dict.

    Args:
        log_str (str): A single line of syslog.

    Returns:
        dict: Keys: pri, version, timestamp, host, appname, procid, msgid, structured_data, message

    Raises:
        UnsupportedFormat: If the line doesn't match RFC5424 format.
    """
    line = log_str.strip()
    match = SYSLOG_REGEX.match(line)
    if not match:
        raise UnsupportedFormat(f"Line does not match syslog RFC5424 format: {line!r}")
    return match.groupdict()


def main():
    parser = argparse.ArgumentParser(
        description="Parse syslog file (RFC5424) and output JSON dict per entry"
    )
    parser.add_argument("file", help="Path to syslog file")
    args = parser.parse_args()

    try:
        with open(args.file, "r") as f:
            for raw_line in f:
                try:
                    parsed = parse_syslog(raw_line)
                    print(json.dumps(parsed))
                except UnsupportedFormat as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found - {args.file}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
