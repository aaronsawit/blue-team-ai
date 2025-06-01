#!/usr/bin/env python3
"""
blue_team_ai/enrichment.py — IOC enrichment + Free‐API GeoIP lookup for syslog records.

Now, if geoip_enabled=True, every record receives a 'geoip' key:
- If an IP is found, 'geoip' = lookup_geoip(ip)
- If no IP is found, 'geoip' = {}
"""
import csv
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

# Regular expression to extract IPv4 addresses
IP_REGEX = re.compile(r"(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)")

# Regular expressions for different IOC types
DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

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

def extract_domains(text: str) -> List[str]:
    """
    Extract all domain names from the given text.
    """
    return [match.group(0) for match in DOMAIN_REGEX.finditer(text)]

def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from the given text.
    """
    return URL_REGEX.findall(text)

def extract_hashes(text: str) -> List[str]:
    """
    Extract all hash values (MD5, SHA1, SHA256) from the given text.
    """
    hashes = []
    hashes.extend(MD5_REGEX.findall(text))
    hashes.extend(SHA1_REGEX.findall(text))
    hashes.extend(SHA256_REGEX.findall(text))
    return hashes

def lookup_geoip(ip: str) -> Dict[str, str]:
    """
    Use the free ip-api.com service to return geo info for `ip`.
    Returns: {"country": "US", "city": "San Francisco"} or {} on failure.
    """
    if not ip:
        return {}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        if data.get("status") == "success":
            return {
                "country": data.get("countryCode", ""),
                "city": data.get("city", "")
            }
    except Exception:
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
    - geoip_enabled: if True, every record gets a 'geoip' key:
        * If an IP is found, lookup_geoip(ip)
        * If no IP, {}
    Returns a shallow copy of `record` with added keys:
      - 'ioc_hits': List[Dict[str, str]]  (each dict contains 'ioc','type','description')
      - If geoip_enabled=True, always attach 'geoip': { 'country', 'city' } (or empty)
    """
    enriched = record.copy()
    message = enriched.get("message", "")

    # 1) Extract or confirm src_ip
    src_ip = enriched.get("src_ip")
    if not src_ip:
        ip_found = extract_ip(enriched)
        if ip_found:
            enriched["src_ip"] = ip_found
            src_ip = ip_found

    # 2) IOC tagging - Initialize empty list
    enriched["ioc_hits"] = []

    # Create sets of IOCs by type for efficient lookup
    malicious_ips = set()
    malicious_domains = set()
    malicious_urls = set()
    malicious_hashes = set()
    
    for ioc_entry in ioc_list:
        ioc_value = ioc_entry["ioc"].lower()
        ioc_type = ioc_entry["type"].lower()
        
        if ioc_type == "ip":
            malicious_ips.add(ioc_value)
        elif ioc_type == "domain":
            malicious_domains.add(ioc_value)
        elif ioc_type == "url":
            malicious_urls.add(ioc_value)
        elif ioc_type == "hash":
            malicious_hashes.add(ioc_value)

    # Check for IP IOCs
    if src_ip and src_ip.lower() in malicious_ips:
        # Find the matching IOC entry for full details
        for ioc_entry in ioc_list:
            if ioc_entry["ioc"].lower() == src_ip.lower() and ioc_entry["type"].lower() == "ip":
                enriched["ioc_hits"].append({
                    "ioc": ioc_entry["ioc"],
                    "type": ioc_entry["type"],
                    "description": ioc_entry["description"]
                })
                break

    # Check for domain IOCs
    found_domains = extract_domains(message.lower())
    for domain in found_domains:
        if domain in malicious_domains:
            # Find the matching IOC entry for full details
            for ioc_entry in ioc_list:
                if ioc_entry["ioc"].lower() == domain and ioc_entry["type"].lower() == "domain":
                    enriched["ioc_hits"].append({
                        "ioc": ioc_entry["ioc"],
                        "type": ioc_entry["type"],
                        "description": ioc_entry["description"]
                    })
                    break

    # Check for URL IOCs
    found_urls = extract_urls(message.lower())
    for url in found_urls:
        if url in malicious_urls:
            # Find the matching IOC entry for full details
            for ioc_entry in ioc_list:
                if ioc_entry["ioc"].lower() == url and ioc_entry["type"].lower() == "url":
                    enriched["ioc_hits"].append({
                        "ioc": ioc_entry["ioc"],
                        "type": ioc_entry["type"],
                        "description": ioc_entry["description"]
                    })
                    break

    # Check for hash IOCs
    found_hashes = extract_hashes(message.lower())
    for hash_val in found_hashes:
        if hash_val in malicious_hashes:
            # Find the matching IOC entry for full details
            for ioc_entry in ioc_list:
                if ioc_entry["ioc"].lower() == hash_val and ioc_entry["type"].lower() == "hash":
                    enriched["ioc_hits"].append({
                        "ioc": ioc_entry["ioc"],
                        "type": ioc_entry["type"],
                        "description": ioc_entry["description"]
                    })
                    break

    # 3) GeoIP enrichment (always attach 'geoip' if requested)
    if geoip_enabled:
        if src_ip:
            enriched["geoip"] = lookup_geoip(src_ip)
        else:
            enriched["geoip"] = {}

    return enriched

def enrich_all(
    records: List[Dict[str, Any]],
    ioc_list: List[Dict[str, str]],
    geoip_enabled: bool = False
) -> List[Dict[str, Any]]:
    """
    Enrich a list of parsed syslog records with IOC tags and optional GeoIP.
    - records: list of dicts from parse_syslog()
    - ioc_list: list from load_ioc_list()
    - geoip_enabled: if True, every record gets a 'geoip' key
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