# blue_team_ai/cli.py

import argparse
import json
import sys
from pathlib import Path

from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.exceptions.unsupported_format import UnsupportedFormat

def cli():
    parser = argparse.ArgumentParser(description="Blue Team AI CLI - Syslog Parser")
    parser.add_argument("--file", "-f", type=str, help="Path to syslog file", required=True)
    parser.add_argument("--output", "-o", type=str, help="Optional output JSON file")
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
                print(f"Warning: Skipped malformed line -> {e}", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as out:
            json.dump(results, out, indent=2)
    else:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    cli()
