#!/usr/bin/env python3
"""
blue_team_ai/rules.py — Rule engine for detecting suspicious patterns in enriched syslog records.
"""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any


def detect_ssh_bruteforce(
    records: List[Dict[str, Any]],
    window_sec: int = 60,
    threshold: int = 5
) -> List[Dict[str, Any]]:
    """
    Detect SSH brute-force: more than `threshold` failed auths within `window_sec`.
    """
    failures: Dict[str, List[datetime]] = defaultdict(list)
    for r in records:
        if r.get("appname") == "sshd":
            msg = r.get("message", "")
            # Look for common failure patterns
            if "Failed password" in msg or "authentication failure" in msg:
                ts = r.get("timestamp")
                try:
                    failures[r.get("host")].append(datetime.fromisoformat(ts))
                except Exception:
                    continue
    alerts: List[Dict[str, Any]] = []
    for host, times in failures.items():
        times.sort()
        for i, start in enumerate(times):
            end_time = start + timedelta(seconds=window_sec)
            count = sum(1 for t in times if start <= t < end_time)
            if count > threshold:
                alerts.append({
                    "rule": "ssh_bruteforce",
                    "host": host,
                    "first_seen": start.isoformat(),
                    "count": count,
                    "description": f"{count} SSH failures in {window_sec}s"
                })
                break
    return alerts


def detect_suspicious_cron(
    records: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Detect cron jobs executed by non-root users.
    """
    alerts: List[Dict[str, Any]] = []
    for r in records:
        if r.get("appname") == "cron":
            msg = r.get("message", "")
            # Skip root jobs (message starts with '(root)')
            if msg.startswith("(root)"):
                continue
            alerts.append({
                "rule": "cron_non_root",
                "host": r.get("host"),
                "timestamp": r.get("timestamp"),
                "description": "Cron job run by non-root user"
            })
    return alerts


def detect_ioc_hits(
    records: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Detect any record with IOC hits.
    """
    alerts: List[Dict[str, Any]] = []
    for r in records:
        hits = r.get("ioc_hits", [])
        if hits:
            alerts.append({
                "rule": "ioc_hit",
                "host": r.get("host"),
                "timestamp": r.get("timestamp"),
                "ioc_details": hits
            })
    return alerts


def apply_rules(
    records: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Apply all detection rules to the list of records.
    """
    alerts: List[Dict[str, Any]] = []
    alerts.extend(detect_ssh_bruteforce(records))
    alerts.extend(detect_suspicious_cron(records))
    alerts.extend(detect_ioc_hits(records))
    return alerts
