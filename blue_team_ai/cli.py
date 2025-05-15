#!/usr/bin/env python3
"""
blue_team_ai/cli.py — Blue Team AI CLI - Syslog Parser.

Usage:
    cli.py --file INPUT_FILE [--output OUTPUT_FILE] [--ignore-errors]

Examples:
    # Exit on first malformed line (default):
    python3 cli.py --file Windows_2k.log --output results.json

    # Skip malformed lines, logging warnings:
    python3 cli.py -f Windows_2k.log -o results.json -i
"""

import argparse
import json
import sys
from pathlib import Path

from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

def cli():
    parser = argparse.ArgumentParser(description="Blue Team AI CLI - Syslog Parser")
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="Path to syslog file",
        required=True
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Optional output JSON file"
    )
    parser.add_argument(
        "--ignore-errors", "-i",
        action="store_true",
        help="Skip malformed lines instead of exiting on first error"
    )
    args = parser.parse_args()

    input_path = Path(args.file)
    if not input_path.exists():
        print(f"Error: File not found - {args.file}", file=sys.stderr)
        sys.exit(1)

    results = []
    with open(input_path, "r") as f:
        for line in f:
            try:
                parsed = parse_syslog(line)
                results.append(parsed)
            except UnsupportedFormat as e:
                if args.ignore_errors:
                    print(f"Warning: Skipped malformed line -> {e}", file=sys.stderr)
                    continue
                else:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)

    # Write output
    if args.output:
        try:
            with open(args.output, "w") as out:
                json.dump(results, out, indent=2)
        except IOError as e:
            print(f"Error: cannot write to {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    cli()
