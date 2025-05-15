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
    r'^<(?P<pri>\d+)>'              
    r'(?P<version>\d+) '
    r'(?P<timestamp>\S+) '
    r'(?P<host>\S+) '
    r'(?P<appname>\S+) '
    r'(?P<procid>\S+) '
    r'(?P<msgid>\S+) '
    r'(?P<structured_data>(?:-|\[.*?\])) '
    r'(?P<message>.*)$'
)

def parse_syslog(log_str):
    """
    Parse a single syslog entry into a dict.
    Raises UnsupportedFormat if it does not match RFC5424.
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
