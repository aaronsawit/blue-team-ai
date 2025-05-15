#!/usr/bin/env python3
"""
parse_logs.py — Parse RFC5424-style syslog lines into a dict or raise UnsupportedFormat.

Usage:
    parse_logs.py --file INPUT_FILE [--output OUTPUT_FILE] [--ignore-errors]

Examples:
    # Exit on first malformed line (default behavior)
    ./parse_logs.py --file /var/log/syslog

    # Skip malformed lines, printing only valid JSON
    ./parse_logs.py -f /var/log/syslog -o parsed.jsonl --ignore-errors
"""

import re
import argparse
import json
import sys

from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

# Regex for minimal RFC5424 format:
SYSLOG_REGEX = re.compile(
    r'^<(?P<pri>\d+)>'                   # Priority
    r'(?P<version>\d+)\s+'               # Version
    r'(?P<timestamp>\S+)\s+'             # Timestamp
    r'(?P<host>\S+)\s+'                  # Hostname
    r'(?P<appname>\S+)\s+'               # Application name
    r'(?P<procid>\S+)\s+'                # Process ID
    r'(?P<msgid>\S+)\s+'                 # Message ID
    r'(?P<structured_data>(?:-|\[.*?\]))\s+'  # Structured data (or '-')
    r'(?P<message>.*)$'                  # Message text
)

#!/usr/bin/env python3
"""
parse_logs.py — Parse RFC5424-style syslog lines into a dict or raise UnsupportedFormat.
"""

import re
import datetime

from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

# Regex for minimal RFC5424 format:
#   <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
SYSLOG_REGEX = re.compile(
    r'^<(?P<pri>\d+)>'                          # Priority
    r'(?P<version>\d+) '                        # Version
    r'(?P<timestamp>\S+) '                      # Timestamp
    r'(?P<host>\S+) '                           # Hostname
    r'(?P<appname>\S+) '                        # Application name
    r'(?P<procid>\S+) '                         # Process ID
    r'(?P<msgid>\S+) '                          # Message ID
    r'(?P<structured_data>(?:-|\[.*?\])) '       # Structured data (or '-')
    r'(?P<message>.*)$'                         # Message text
)

def parse_syslog(log_str: str) -> dict:
    """
    Parse a single syslog line in RFC5424 format into its components.
    Raises UnsupportedFormat if the line is not valid.
    """
    m = SYSLOG_REGEX.match(log_str)
    if not m:
        raise UnsupportedFormat(f"Line does not match syslog RFC5424 format: '{log_str}'")

    record = m.groupdict()

    # Only version "1" is supported per RFC5424
    if record["version"] != "1":
        raise UnsupportedFormat(f"Unsupported syslog version: '{record['version']}'")

    # Validate timestamp is ISO-8601 (e.g. 2025-05-15T14:31:02Z)
    ts = record["timestamp"]
    try:
        # Replace Z with +00:00 for Python parsing
        datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        raise UnsupportedFormat(f"Invalid timestamp: '{ts}'")

    return record


def main():
    parser = argparse.ArgumentParser(
        description="Parse syslog file (RFC5424) and output JSON dict per entry"
    )
    parser.add_argument(
        "-f", "--file",
        dest="file",
        required=True,
        help="Path to syslog file"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Path to output file; defaults to stdout"
    )
    parser.add_argument(
        "-i", "--ignore-errors",
        action="store_true",
        help="Skip malformed lines instead of exiting on first error"
    )
    args = parser.parse_args()

    # Open output handle
    if args.output:
        try:
            out_fh = open(args.output, "w")
        except IOError as e:
            print(f"Error: cannot open output file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        out_fh = sys.stdout

    try:
        with open(args.file, "r") as infile:
            for raw_line in infile:
                try:
                    parsed = parse_syslog(raw_line)
                    out_fh.write(json.dumps(parsed) + "\n")
                except UnsupportedFormat as e:
                    if args.ignore_errors:
                        print(f"Warning: {e}", file=sys.stderr)
                        continue
                    else:
                        print(f"Error: {e}", file=sys.stderr)
                        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: file not found - {args.file}", file=sys.stderr)
        sys.exit(1)
    finally:
        if args.output:
            out_fh.close()

if __name__ == "__main__":
    main()
