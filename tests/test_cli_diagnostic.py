# tests/test_cli_smoke.py

import json
import sys
import tempfile
from pathlib import Path

import pytest

# We’ll import the CLI's main() function
from blue_team_ai.cli import main

# Monkeypatch objects at import time
import blue_team_ai.parsers.parse_logs as parser_module
import blue_team_ai.rules as rules_module
import blue_team_ai.enrichment as enrichment_module
import blue_team_ai.ai as ai_module

@pytest.fixture(autouse=True)
def patch_everything(monkeypatch):
    """
    Replace parse_syslog, apply_rules, lookup_geoip, classify_record with stubs
    so we can test the CLI pipeline without external dependencies.
    """
    # 1) Stub parse_syslog to return a predictable dict
    def dummy_parse_syslog(line: str):
        # Simulate a parsed record with host, message, maybe src_ip
        return {
            "host": "dummyhost",
            "message": line.strip(),
        }

    monkeypatch.setattr(parser_module, "parse_syslog", dummy_parse_syslog)

    # 2) Stub apply_rules to return an empty list (no alerts)
    monkeypatch.setattr(rules_module, "apply_rules", lambda records: [])

    # 3) Stub lookup_geoip to return a fixed dict
    monkeypatch.setattr(enrichment_module, "lookup_geoip", lambda ip: {"country": "ZZ", "city": "TestCity"})

    # 4) Stub classify_record to return a fixed label/score
    monkeypatch.setattr(ai_module, "classify_record", lambda r: {"ai_label": "normal", "ai_score": 0.5})

    yield

def run_cli_and_capture(tmp_path, extra_args=None):
    """
    Helper to run the CLI in-process using monkeypatched sys.argv, capturing stdout.
    Returns the parsed JSON dict.
    """
    # 1) Create a tiny sample syslog file
    sample = tmp_path / "sample.log"
    lines = [
        "<34>1 2025-05-26T14:00:00Z host1 sshd - - - Failed password for root\n",
        "<34>1 2025-05-26T14:01:00Z host2 sshd - - - User login succeeded\n"
    ]
    sample.write_text("".join(lines))

    # 2) Build argv
    args = ["cli.py", "--file", str(sample)]
    if extra_args:
        args.extend(extra_args)

    # 3) Monkeypatch sys.argv
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("PYTEST_RUNNING", "1")  # any sentinel
    monkeypatch.setattr(sys, "argv", args)

    # 4) Capture stdout
    from io import StringIO
    old_stdout = sys.stdout
    sys.stdout = StringIO()

    # 5) Run main() (it will call sys.exit())
    with pytest.raises(SystemExit) as excinfo:
        main()
    # Expect code == 0
    assert excinfo.value.code in (0, None)

    # 6) Grab printed JSON
    output = sys.stdout.getvalue().strip()
    sys.stdout = old_stdout
    monkeypatch.undo()

    # 7) The CLI prints a summary JSON (one big JSON object). Parse it.
    return json.loads(output)

def test_cli_parse_only(tmp_path):
    """
    Running CLI with no extra flags should parse our 2 lines, with no enrichment/rules/AI.
    """
    result = run_cli_and_capture(tmp_path)

    assert result["total_lines"] == 2
    assert result["parsed_records"] == 2
    assert result["output_records"] == 2

    recs = result["records"]
    assert isinstance(recs, list) and len(recs) == 2
    # The dummy parse_syslog just copied line to "message"
    assert "Failed password" in recs[0]["message"]

def test_cli_full_pipeline(tmp_path):
    """
    Running CLI with --enrich --geoip --ai --rules. Since apply_rules() is stubbed,
    "records" should be empty and parsed_records should be None.
    """
    result = run_cli_and_capture(tmp_path, extra_args=["--enrich", "--geoip", "--ai", "--rules"])

    assert result["total_lines"] == 2
    assert result["parsed_records"] is None
    # Since apply_rules returns [], output_records should be 0
    assert result["output_records"] == 0
    assert result["records"] == []

def test_cli_enrich_geoip_ai(tmp_path):
    """
    Running CLI with only --enrich --geoip --ai (no --rules) should produce enriched records.
    Each record should have: ioc_hits (maybe empty), geoip, ai_label, ai_score.
    """
    result = run_cli_and_capture(tmp_path, extra_args=["--enrich", "--geoip", "--ai"])

    assert result["total_lines"] == 2
    assert result["parsed_records"] == 2
    assert result["output_records"] == 2

    recs = result["records"]
    for r in recs:
        # Since load_ioc_list expects a real CSV but we didn't provide one,
        # it may have thrown. To avoid that, CLI uses default path data/iocs.csv.
        # If data/iocs.csv doesn't exist, load_ioc_list will error out.
        # However, because we stubbed lookup_geoip and classify_record, ensure those keys exist.
        assert "geoip" in r
        assert r["geoip"] == {"country": "ZZ", "city": "TestCity"}
        assert "ai_label" in r and r["ai_label"] == "normal"
        assert "ai_score" in r and r["ai_score"] == 0.5
