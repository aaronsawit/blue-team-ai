#!/usr/bin/env python3
"""
blue_team_ai/enrichment.py — Enrichment functions for parsed syslog records.
"""
import csv
import re
from typing import List, Dict, Optional

# Regular expression to extract IPv4 addresses
IP_REGEX = re.compile(r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)')


def load_ioc_list(ioc_path: str) -> List[Dict[str, str]]:
    """
    Load IOC list from a CSV file. CSV must have columns: ioc,type,description
    Returns a list of dicts, each with keys 'ioc', 'type', and 'description'.
    """
    ioc_list: List[Dict[str, str]] = []
    with open(ioc_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Ensure expected keys exist
            if 'ioc' in row and 'type' in row and 'description' in row:
                ioc_list.append(row)
    return ioc_list


def extract_ip(record: Dict[str, str]) -> Optional[str]:
    """
    Extract the first IPv4 address found in record['message'], if any.
    """
    message = record.get('message', '')
    match = IP_REGEX.search(message)
    return match.group('ip') if match else None


def enrich_record(
    record: Dict[str, any],
    ioc_list: List[Dict[str, str]],
    geo_reader=None
) -> Dict[str, any]:
    """
    Enrich a single parsed syslog record with IOC tags and optional GeoIP data.

    Parameters:
    - record: dict from parse_syslog
    - ioc_list: list from load_ioc_list
    - geo_reader: optional geoip2.database.Reader instance

    Returns a new dict with added keys 'ioc_hits' and optionally 'geoip'.
    """
    # Work on a copy to avoid mutating original
    enriched = record.copy()

    # 1) IOC tagging
    hits: List[Dict[str, str]] = []
    msg_text = enriched.get('message', '')
    host = enriched.get('host', '')
    for ioc in ioc_list:
        if ioc['ioc'] in msg_text or ioc['ioc'] == host:
            hits.append(ioc)
    enriched['ioc_hits'] = hits

    # 2) GeoIP enrichment (if a reader is provided)
    if geo_reader:
        ip = extract_ip(enriched)
        if ip:
            try:
                geo = geo_reader.city(ip)
                enriched['geoip'] = {
                    'ip': ip,
                    'country': geo.country.name,
                    'city': geo.city.name,
                    'asn': geo.traits.autonomous_system_number,
                }
            except Exception:
                # On lookup failure, attach empty geoip
                enriched['geoip'] = {}

    return enriched


def enrich_all(
    records: List[Dict[str, any]],
    ioc_list: List[Dict[str, str]],
    geo_reader=None
) -> List[Dict[str, any]]:
    """
    Enrich a list of parsed records with IOC and optional GeoIP data.
    """
    return [enrich_record(r, ioc_list, geo_reader) for r in records]
