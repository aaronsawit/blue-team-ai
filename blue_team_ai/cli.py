#!/usr/bin/env python3
"""
blue_team_ai/cli.py — Command-line interface for parsing, enriching, and alerting on syslog data.
"""
import argparse
import json
from blue_team_ai.parsers.parse_logs import parse_syslog
from blue_team_ai.enrichment import load_ioc_list, enrich_all
from blue_team_ai.rules import apply_rules

try:
    from geoip2.database import Reader as GeoIP2Reader
except ImportError:
    GeoIP2Reader = None


def main():
    parser = argparse.ArgumentParser(
        description="Parse syslog, enrich records, and apply alert rules."
    )
    # Input file (raw syslog)
    parser.add_argument(
        "--file", required=True,
        help="Path to raw syslog input file"
    )
    # Enrichment options
    parser.add_argument(
        "--enrich", action="store_true",
        help="Enable IOC and GeoIP enrichment"
    )
    parser.add_argument(
        "--ioc-file", default="blue_team_ai/data/iocs.csv",
        help="Path to IOC CSV feed"
    )
    parser.add_argument(
        "--geoip-db", default=None,
        help="Path to GeoIP2 City database (mmdb)"
    )
    # Rule engine
    parser.add_argument(
        "--rules", action="store_true",
        help="Enable alert rule evaluation"
    )
    # Output
    parser.add_argument(
        "--output", default=None,
        help="Path to write output JSON (parses, enriched, or alerts)"
    )
    args = parser.parse_args()

    # Read and parse syslog lines
    with open(args.file, "r") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    parsed_records = [parse_syslog(ln) for ln in lines]

    # Enrichment
    if args.enrich:
        # Load IOCs
        ioc_list = load_ioc_list(args.ioc_file)
        # Initialize GeoIP reader if requested and available
        geo_reader = None
        if args.geoip_db:
            if not GeoIP2Reader:
                raise RuntimeError("geoip2 library is required for GeoIP enrichment")
            geo_reader = GeoIP2Reader(args.geoip_db)
        parsed_records = enrich_all(parsed_records, ioc_list, geo_reader)

    # Rule evaluation
    output_data = parsed_records
    if args.rules:
        alerts = apply_rules(parsed_records)
        output_data = alerts

    # Write or print output
    if args.output:
        with open(args.output, "w") as outfh:
            json.dump(output_data, outfh, indent=2)
    else:
        print(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()
