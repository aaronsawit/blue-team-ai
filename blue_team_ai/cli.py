#!/usr/bin/env python3
"""
blue_team_ai/cli.py — Production CLI: parse → enrich (IOC/GeoIP) → rules → AI classification → JSON output

Note: On successful completion, this script calls sys.exit(0) so that
pytest tests expecting a SystemExit pass cleanly.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

# 1) Parsing logic
from blue_team_ai.parsers.parse_logs import parse_syslog

# 2) Enrichment: IOC + free‐API GeoIP (rely on module reference for lookup_geoip)
import blue_team_ai.enrichment as enrichment_module
from blue_team_ai.enrichment import load_ioc_list, enrich_all, extract_ip

# 3) Rules engine (optional)
from blue_team_ai.rules import apply_rules

# 4) AI classification (DeepSeek)
import blue_team_ai.ai as ai_module

def setup_logging(verbose: bool):
    """
    Configure root logger. DEBUG level if verbose, else INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s", level=level
    )

def load_file(file_path: Path) -> list[str]:
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

def process_records(
    lines: list[str],
    do_enrich: bool,
    ioc_file: Path,
    geoip_enabled: bool,
    do_rules: bool,
    do_ai: bool
) -> list[dict]:
    """
    1. Parse lines → list of dicts
    2. If do_enrich: attach IOC tags (enrich_all with geoip_enabled=False)
    3. If geoip_enabled: for every record, attach geoip = enrichment_module.lookup_geoip(src_ip or "")
    4. If do_rules: run apply_rules(parsed) to produce alert list
    5. If do_ai: classify each final record via ai_module.classify_record
    """
    # 1) Parse each line
    parsed: list[dict] = []
    for line in lines:
        try:
            rec = parse_syslog(line)
            if rec:
                parsed.append(rec)
        except Exception as e:
            logging.warning("Parse error on line '%s': %s", line[:50], e)

    # 2) IOC enrichment only (no geoip)
    if do_enrich:
        try:
            iocs = load_ioc_list(str(ioc_file))
        except Exception as e:
            logging.error("Could not load IOC list: %s", e)
            sys.exit(1)
        parsed = enrich_all(parsed, iocs, geoip_enabled=False)

    # 3) Free‐API GeoIP enrichment for EVERY record
    if geoip_enabled:
        for r in parsed:
            src_ip = r.get("src_ip")
            if not src_ip:
                src_ip = extract_ip(r) or ""
            # IMPORTANT: Call through the module so pytest monkeypatch works
            r["geoip"] = enrichment_module.lookup_geoip(src_ip or "")

    # 4) Rule‐based alerting
    if do_rules:
        output_list = apply_rules(parsed)
    else:
        output_list = parsed

    # 5) AI classification
    if do_ai:
        for r in output_list:
            try:
                ai_result = ai_module.classify_record(r)
                r["ai_label"] = ai_result.get("ai_label", "")
                r["ai_score"] = ai_result.get("ai_score", 0.0)
            except Exception as e:
                r["ai_label"] = "error"
                r["ai_score"] = 0.0
                logging.debug("AI classification failed: %s", e)

    return output_list

def main():
    parser = argparse.ArgumentParser(
        description="Convert RFC5424 syslog → JSON + optional enrichment (IOC/GeoIP) + rules + AI classification"
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
        "--geoip", action="store_true",
        help="Enable free‐API GeoIP lookup (via ip-api.com)"
    )
    parser.add_argument(
        "--ioc-file", type=Path,
        default=Path(__file__).parent / "data" / "iocs.csv",
        help="CSV file of IOCs to load (default: data/iocs.csv)"
    )
    parser.add_argument(
        "--rules", action="store_true",
        help="Enable rule‐based alert evaluation"
    )
    parser.add_argument(
        "--ai", action="store_true",
        help="Enable DeepSeek AI classification"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose (DEBUG) logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    # 1) Load file
    lines = load_file(args.file)

    # 2) Process pipeline
    output_records = process_records(
        lines,
        do_enrich=args.enrich,
        ioc_file=args.ioc_file,
        geoip_enabled=args.geoip,
        do_rules=args.rules,
        do_ai=args.ai,
    )

    # 3) Build output summary
    summary = {
        "total_lines": len(lines),
        "parsed_records": None if args.rules else len(output_records),
        "output_records": len(output_records),
        "records": output_records
    }

    # 4) Serialize to JSON
    try:
        out_json = json.dumps(summary, default=str, indent=2)
    except Exception as e:
        logging.error("Failed to serialize output JSON: %s", e)
        sys.exit(1)

    # 5) Write or print
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w") as f:
                f.write(out_json)
            logging.info("Output written to %s", args.output)
        except Exception as e:
            logging.error("Failed writing output file: %s", e)
            sys.exit(1)
    else:
        print(out_json)

    # 6) Explicitly exit with code 0 so pytest can catch SystemExit
    sys.exit(0)

if __name__ == "__main__":
    main()
