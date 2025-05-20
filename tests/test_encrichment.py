#!/usr/bin/env pytest
"""
tests/test_enrichment.py — Unit tests for enrichment module.
"""
import pytest
from pathlib import Path
from blue_team_ai.enrichment import (
    load_ioc_list,
    extract_ip,
    enrich_record,
    enrich_all
)


def test_load_ioc_list(tmp_path):
    # Create a temporary IOC CSV file
    content = (
        "ioc,type,description\n"
        "1.2.3.4,malicious_ip,Test IP IOC\n"
        "bad.example.com,malicious_domain,Test domain IOC\n"
    )
    csv_file = tmp_path / "iocs.csv"
    csv_file.write_text(content)

    iocs = load_ioc_list(str(csv_file))
    assert isinstance(iocs, list)
    assert len(iocs) == 2
    assert iocs[0]["ioc"] == "1.2.3.4"
    assert iocs[0]["type"] == "malicious_ip"
    assert iocs[1]["description"] == "Test domain IOC"


def test_extract_ip():
    record_with_ip = {"message": "Failed login from 5.6.7.8 port 22"}
    assert extract_ip(record_with_ip) == "5.6.7.8"

    record_without_ip = {"message": "No IP address here"}
    assert extract_ip(record_without_ip) is None


def test_enrich_record_without_geo():
    record = {"message": "Connection from 9.9.9.9", "host": "server1"}
    ioc_list = [{"ioc": "9.9.9.9", "type": "malicious_ip", "description": "Test IOC"}]
    enriched = enrich_record(record, ioc_list, geo_reader=None)

    # IOC hits should be tagged
    assert "ioc_hits" in enriched
    assert len(enriched["ioc_hits"]) == 1
    assert enriched["ioc_hits"][0]["ioc"] == "9.9.9.9"

    # No geoip field when geo_reader is None
    assert "geoip" not in enriched


class FakeGeoReader:
    class Country:
        name = "TestCountry"
    class City:
        name = "TestCity"
    class Traits:
        autonomous_system_number = 54321

    def city(self, ip):
        # Return an object with country, city, and traits attributes
        class GeoInfo:
            country = FakeGeoReader.Country
            city = FakeGeoReader.City
            traits = FakeGeoReader.Traits
        return GeoInfo()


def test_enrich_record_with_geo():
    record = {"message": "Ping from 1.1.1.1", "host": "server2"}
    ioc_list = []
    fake_geo = FakeGeoReader()
    enriched = enrich_record(record, ioc_list, geo_reader=fake_geo)

    # GeoIP enrichment should attach geoip dict
    assert "geoip" in enriched
    geo = enriched["geoip"]
    assert geo["country"] == "TestCountry"
    assert geo["city"] == "TestCity"
    assert geo["asn"] == 54321


def test_enrich_all():
    records = [
        {"message": "x 2.2.2.2 y", "host": "h1"},
        {"message": "z", "host": "h2"}
    ]
    ioc_list = []
    enriched_list = enrich_all(records, ioc_list, geo_reader=None)

    assert isinstance(enriched_list, list)
    assert len(enriched_list) == 2
    # Each record should have an ioc_hits key
    for rec in enriched_list:
        assert "ioc_hits" in rec
