# tests/test_enrichment.py

import os
import tempfile
import csv
import pytest

from blue_team_ai.enrichment import (
    load_ioc_list,
    extract_ip,
    lookup_geoip,
    enrich_record,
    enrich_all,
)

# 1. Test extract_ip (regex-based)
def test_extract_ip_found():
    record = {"message": "Failed login from 192.168.0.42 for user root"}
    assert extract_ip(record) == "192.168.0.42"

def test_extract_ip_not_found():
    record = {"message": "No IP here, just plain text"}
    assert extract_ip(record) is None

# 2. Test load_ioc_list using a temporary CSV
def test_load_ioc_list(tmp_path):
    # Create a temporary CSV with header and two IOCs
    csv_file = tmp_path / "iocs.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        # Must have columns: ioc,type,description
        writer.writerow(["ioc", "type", "description"])
        writer.writerow(["1.2.3.4", "ip", "Test IOC A"])
        writer.writerow(["bad.domain.com", "domain", "Test IOC B"])

    iocs = load_ioc_list(str(csv_file))
    # Should be a list of two dicts
    assert isinstance(iocs, list) and len(iocs) == 2
    assert iocs[0]["ioc"] == "1.2.3.4"
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["description"] == "Test IOC A"
    assert iocs[1]["ioc"] == "bad.domain.com"

# 3. Test lookup_geoip (monkeypatch HTTP call to ip-api.com)
def test_lookup_geoip_success(monkeypatch):
    # Monkeypatch requests.get inside lookup_geoip to return a dummy success JSON
    class DummyResp:
        def json(self):
            return {"status": "success", "countryCode": "ZZ", "city": "Testville"}

    def dummy_get(url, timeout):
        return DummyResp()

    monkeypatch.setenv("NO_INTERNET", "1")  # Just to signify we’re stubbing
    import requests
    monkeypatch.setattr(requests, "get", dummy_get)

    geo = lookup_geoip("8.8.8.8")
    assert geo == {"country": "ZZ", "city": "Testville"}

def test_lookup_geoip_failure(monkeypatch):
    # If the HTTP call returns a non-success status, or raises, we get {}
    class DummyResp:
        def json(self):
            return {"status": "fail"}

    def dummy_get(url, timeout):
        return DummyResp()

    import requests
    monkeypatch.setattr(requests, "get", dummy_get)

    geo = lookup_geoip("8.8.8.8")
    assert geo == {}

# 4. Test enrich_record and enrich_all
def test_enrich_record_and_enrich_all(monkeypatch, tmp_path):
    # 4.1. Prepare a dummy IOC list
    ioc_list = [
        {"ioc": "1.2.3.4", "type": "ip", "description": "Test IP IOC"},
        {"ioc": "evil.com", "type": "domain", "description": "Bad Domain IOC"}
    ]

    # 4.2. Prepare a single record with a message containing both an IP and a domain
    record = {
        "host": "myhost",
        "message": "User connected from 1.2.3.4 and also tried evil.com",
    }

    # Monkeypatch lookup_geoip to return a known dict
    monkeypatch.setattr("blue_team_ai.enrichment.lookup_geoip", lambda ip: {"country": "ZZ", "city": "Nowhere"})

    # Enrich only IOC (geoip_enabled=False)
    enriched = enrich_record(record, ioc_list, geoip_enabled=False)
    assert "src_ip" in enriched and enriched["src_ip"] == "1.2.3.4"
    assert isinstance(enriched["ioc_hits"], list)
    # Should contain exactly two IOCs (ip and domain)
    assert any(hit["ioc"] == "1.2.3.4" for hit in enriched["ioc_hits"])
    assert any(hit["ioc"] == "evil.com" for hit in enriched["ioc_hits"])
    # Should not have "geoip" key
    assert "geoip" not in enriched

    # Enrich with GeoIP enabled
    enriched2 = enrich_record(record, ioc_list, geoip_enabled=True)
    assert "geoip" in enriched2
    assert enriched2["geoip"] == {"country": "ZZ", "city": "Nowhere"}

    # 4.3. Test enrich_all on a list of records
    rec_list = [record.copy(), {"message": "No IOC here", "host": "other"}]
    enriched_list = enrich_all(rec_list, ioc_list, geoip_enabled=True)
    assert isinstance(enriched_list, list)
    assert len(enriched_list) == 2
    # First record should have two hits + geoip
    assert len(enriched_list[0]["ioc_hits"]) == 2
    assert "geoip" in enriched_list[0]
    # Second record: no matches means empty ioc_hits, but still geoip (if an IP found); since no IP, geoip is {}
    assert enriched_list[1]["ioc_hits"] == []
    assert "geoip" in enriched_list[1]
    assert enriched_list[1]["geoip"] == {}
