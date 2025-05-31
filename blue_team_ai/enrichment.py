#!/usr/bin/env python3
"""
blue_team_ai/enrichment.py — IOC enrichment + Free‐API GeoIP lookup for syslog records.
"""
import csv
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

# Regular expression to extract IPv4 addresses
IP_REGEX = re.compile(r"(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)")

# Default path for IOCs CSV (relative to this file)
IOC_CSV_DEFAULT = Path(__file__).parent / "data" / "iocs.csv"

def load_ioc_list(ioc_path: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Load IOC list from a CSV file. CSV should have at least the columns:
      "ioc", "type", "description"
    Returns a list of dicts, each with keys 'ioc', 'type', and 'description'.
    """
    csv_path = Path(ioc_path) if ioc_path else IOC_CSV_DEFAULT
    ioc_list: List[Dict[str, str]] = []
    try:
        with csv_path.open(newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Only add rows that have the required columns
                if "ioc" in row and "type" in row and "description" in row:
                    ioc = row["ioc"].strip()
                    itype = row["type"].strip()
                    desc = row["description"].strip()
                    if ioc:
                        ioc_list.append({"ioc": ioc, "type": itype, "description": desc})
    except FileNotFoundError:
        raise RuntimeError(f"IOC CSV file not found: {csv_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to load IOC file {csv_path}: {e}")
    return ioc_list

def extract_ip(record: Dict[str, Any]) -> Optional[str]:
    """
    Extract the first IPv4 address found in record['message'], if any.
    Returns None if no IPv4 is found.
    """
    message = record.get("message", "")
    match = IP_REGEX.search(message)
    return match.group("ip") if match else None

def lookup_geoip(ip: str) -> Dict[str, str]:
    """
    Use the free ip-api.com service to return geo info for `ip`.
    Returns: {"country": "US", "city": "San Francisco"} or {} on failure.
    Rate‐limit is approximately 45 requests/minute.
    """
    if not ip:
        return {}
    try:
        # Query ip-api.com with a short timeout
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("countryCode", ""),
                "city": data.get("city", "")
            }
    except Exception:
        # On any failure (timeout, network error, etc.), return empty dict
        pass
    return {}

def enrich_record(
    record: Dict[str, Any],
    ioc_list: List[Dict[str, str]],
    geoip_enabled: bool = False
) -> Dict[str, Any]:
    """
    Enrich a single parsed syslog record with IOC tags and optional GeoIP data.
    - record: dict output from parse_syslog()
    - ioc_list: list of IOC dicts from load_ioc_list()
    - geoip_enabled: if True, perform a free API lookup for each record's IP

    Returns a shallow copy of `record` with added keys:
      - 'ioc_hits': List[Dict[str, str]]  (each dict contains 'ioc','type','description')
      - If geoip_enabled=True and an IP is found, 'geoip': { 'country', 'city' }
    """
    enriched = record.copy()

    # 1) Extract or confirm src_ip
    src_ip = enriched.get("src_ip")
    if not src_ip:
        ip_found = extract_ip(enriched)
        if ip_found:
            enriched["src_ip"] = ip_found
            src_ip = ip_found

    # 2) IOC tagging
    hits: List[Dict[str, str]] = []
    msg_text = enriched.get("message", "")
    host_val = enriched.get("host", "")
    for ioc in ioc_list:
        ioc_value = ioc["ioc"]
        if (ioc_value and ((ioc_value in msg_text) or (ioc_value == host_val) or (ioc_value == src_ip))):
            hits.append(ioc)
    enriched["ioc_hits"] = hits

    # 3) GeoIP enrichment (if enabled)
    if geoip_enabled and src_ip:
        geo_data = lookup_geoip(src_ip)
        enriched["geoip"] = geo_data if geo_data else {}

    return enriched

def enrich_all(
    records: List[Dict[str, Any]],
    ioc_list: List[Dict[str, str]],
    geoip_enabled: bool = False
) -> List[Dict[str, Any]]:
    """
    Enrich a list of parsed syslog records with IOC tags (always) and
    GeoIP data (if geoip_enabled=True).

    - records: list of dicts from parse_syslog()
    - ioc_list: list from load_ioc_list()
    - geoip_enabled: whether to call lookup_geoip() per record

    Returns a new list of enriched dicts.
    """
    enriched_records: List[Dict[str, Any]] = []
    for rec in records:
        try:
            enriched = enrich_record(rec, ioc_list, geoip_enabled)
            enriched_records.append(enriched)
        except Exception:
            # If enrichment fails for one record, attach minimal fields
            fallback = rec.copy()
            fallback["ioc_hits"] = []
            if geoip_enabled:
                fallback["geoip"] = {}
            enriched_records.append(fallback)
    return enriched_records
