#!/usr/bin/env pytest
"""
tests/test_rules.py — Unit tests for the rule engine.
"""
import pytest
from datetime import datetime, timedelta
from blue_team_ai.rules import (
    detect_ssh_bruteforce,
    detect_suspicious_cron,
    detect_ioc_hits,
    apply_rules
)


def iso(ts):
    """Helper to get ISO timestamp without timezone Z suffix."""
    return ts.isoformat()


def test_detect_ssh_bruteforce_triggers():
    # Create 6 failure records within 60s for host 'h1'
    base = datetime(2025, 5, 20, 12, 0, 0)
    records = []
    for i in range(6):
        ts = base + timedelta(seconds=i * 5)
        records.append({
            "appname": "sshd",
            "host": "h1",
            "message": "Failed password for user",
            "timestamp": iso(ts)
        })
    alerts = detect_ssh_bruteforce(records)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "ssh_bruteforce"
    assert alert["host"] == "h1"
    assert alert["count"] == 6


def test_detect_ssh_bruteforce_no_trigger():
    # Exactly 5 failures (threshold), should not trigger
    base = datetime(2025, 5, 20, 12, 0, 0)
    records = []
    for i in range(5):
        ts = base + timedelta(seconds=i * 10)
        records.append({
            "appname": "sshd",
            "host": "h1",
            "message": "Failed password",
            "timestamp": iso(ts)
        })
    alerts = detect_ssh_bruteforce(records)
    assert alerts == []


def test_detect_suspicious_cron():
    # Cron run by non-root user
    rec1 = {"appname": "cron", "host": "srv", "message": "(admin) run job", "timestamp": "2025-05-20T12:00:00"}
    rec2 = {"appname": "cron", "host": "srv", "message": "(root) run job", "timestamp": "2025-05-20T12:01:00"}
    alerts = detect_suspicious_cron([rec1, rec2])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "cron_non_root"
    assert alert["host"] == "srv"


def test_detect_ioc_hits():
    # Record with IOC hits
    rec = {"host": "h2", "timestamp": "2025-05-20T12:00:00", "ioc_hits": [{"ioc": "1.2.3.4"}]}
    alerts = detect_ioc_hits([rec])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "ioc_hit"
    assert alert["ioc_details"] == rec["ioc_hits"]


def test_apply_rules_combines_all():
    # Combine records for all detectors
    base = datetime(2025, 5, 20, 12, 0, 0)
    # SSH failures
    ssh_recs = [
        {"appname": "sshd", "host": "h1", "message": "Failed password", "timestamp": iso(base + timedelta(seconds=i))}
        for i in range(6)
    ]
    # Suspicious cron
    cron_rec = {"appname": "cron", "host": "c1", "message": "(user) cron task", "timestamp": iso(base)}
    # IOC hit
    ioc_rec = {"host": "h2", "timestamp": iso(base), "ioc_hits": [{"ioc": "x"}]}

    all_recs = ssh_recs + [cron_rec] + [ioc_rec]
    alerts = apply_rules(all_recs)
    # We expect one ssh_bruteforce, one cron_non_root, one ioc_hit
    rules = {a["rule"] for a in alerts}
    assert rules == {"ssh_bruteforce", "cron_non_root", "ioc_hit"}
    assert len(alerts) == 3
