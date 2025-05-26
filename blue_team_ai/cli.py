#!/usr/bin/env python3
"""
blue_team_ai/cli.py — Production CLI for syslog parsing, enrichment, and rule evaluation
"""
import argparse
import json
import sys
import logging
from pathlib import Path

from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.enrichment import load_ioc_list, enrich_all
from blue_team_ai.rules import apply_rules


def setup_logging(verbose: bool):
    """
    Configure root logger. DEBUG level if verbose, else INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s", level=level
    )


def load_file(file_path: Path):
    """
    Read non-empty lines from the syslog file. Exit on errors.
    """
    if not file_path.exists():
        logging.error("Input file does not exist: %s", file_path)
        sys.exit(1)
    try:
        with file_path.open() as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except Exception as e:
        logging.error("Failed reading file %s: %s", file_path, e)
        sys.exit(1)


def process_records(lines, do_enrich: bool, ioc_file: Path, do_rules: bool):
    """
    Parse, optionally enrich, and optionally apply rules to a list of log lines.
    """
    # Parse
    parsed = []
    for line in lines:
        try:
            rec = parse_syslog(line)
            if rec:
                parsed.append(rec)
        except Exception as e:
            logging.warning("Parse error on line '%s': %s", line[:50], e)

    # Enrich with IOCs
    if do_enrich:
        iocs = load_ioc_list(str(ioc_file))
        parsed = enrich_all(parsed, iocs, None)

    # Apply rules
    if do_rules:
        return apply_rules(parsed)

    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="Convert RFC5424 syslog to JSON with optional IOC enrichment and rule alerts"
    )
    parser.add_argument(
        "--file", "-f", required=True, type=Path,
        help="Path to the syslog file"
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        help="Output JSON file (defaults to stdout)"
    )
    parser.add_argument(
        "--enrich", action="store_true",
        help="Enable IOC enrichment"
    )
    parser.add_argument(
        "--ioc-file", type=Path, default=Path(__file__).parent / "data" / "iocs.csv",
        help="CSV file of IOCs for enrichment"
    )
    parser.add_argument(
        "--rules", action="store_true",
        help="Enable alert rule evaluation"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose (DEBUG) logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Load and process
    lines = load_file(args.file)
    output_records = process_records(
        lines, args.enrich, args.ioc_file, args.rules
    )

    # Build output summary
    summary = {
        "total_lines": len(lines),
        "parsed_records": None if args.rules else len(output_records),
        "output_records": len(output_records),
        "records": output_records
    }

    # Serialize
    try:
        out_json = json.dumps(summary, default=str, indent=2)
    except Exception as e:
        logging.error("Failed to serialize output JSON: %s", e)
        sys.exit(1)

    # Write or print
    if args.output:
        try:
            # Ensure parent directory exists
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w") as f:
                f.write(out_json)
            logging.info("Output written to %s", args.output)
        except Exception as e:
            logging.error("Failed writing output file: %s", e)
            sys.exit(1)
    else:
        print(out_json)


if __name__ == "__main__":
    main()
