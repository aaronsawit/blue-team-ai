import pytest
import sys
import json
import logging
from pathlib import Path
import blue_team_ai.cli as cli

# Helper to capture SystemExit

def test_load_file_success(tmp_path):
    # Create a temporary file with content, including empty lines
    file = tmp_path / "test.log"
    content = "line1\n\nline2\n"
    file.write_text(content)

    lines = cli.load_file(file)
    assert lines == ["line1", "line2"]


def test_load_file_missing(tmp_path):
    missing = tmp_path / "nope.log"
    with pytest.raises(SystemExit) as excinfo:
        cli.load_file(missing)
    assert excinfo.value.code == 1


def test_process_records_no_enrich_no_rules(monkeypatch):
    # Monkeypatch parse_syslog to return a dict for each line
    def fake_parse(line):
        return {"line": line}
    monkeypatch.setattr(cli, 'parse_syslog', fake_parse)

    # Call with no enrichment and no rules
    lines = ["a", "b"]
    output = cli.process_records(lines, do_enrich=False, ioc_file=Path(), do_rules=False)
    assert output == [{"line": "a"}, {"line": "b"}]


def test_process_records_with_enrich(monkeypatch):
    # Setup fake parse, load_ioc_list, and enrich_all
    monkeypatch.setattr(cli, 'parse_syslog', lambda l: {"val": l})
    monkeypatch.setattr(cli, 'load_ioc_list', lambda path: ['ioc'])
    def fake_enrich(parsed, iocs, geo):
        # Tag each record
        return [dict(rec, enriched=True) for rec in parsed]
    monkeypatch.setattr(cli, 'enrich_all', fake_enrich)

    lines = ["x"]
    output = cli.process_records(lines, do_enrich=True, ioc_file=Path('iocs.csv'), do_rules=False)
    assert output == [{"val": "x", "enriched": True}]


def test_process_records_with_rules(monkeypatch):
    # Setup fake parse and apply_rules
    monkeypatch.setattr(cli, 'parse_syslog', lambda l: {"v": l})
    monkeypatch.setattr(cli, 'apply_rules', lambda recs: ['alert'])

    lines = ["z"]
    output = cli.process_records(lines, do_enrich=False, ioc_file=Path(), do_rules=True)
    assert output == ['alert']


def run_main_and_capture(argv, monkeypatch, tmp_path, capsys):
    # Prepare a temp log file
    log_file = tmp_path / "main.log"
    log_file.write_text("entry\n")
    args = ['prog'] + argv
    monkeypatch.setattr(sys, 'argv', args)
    # Monkeypatch process_records to predictable output
    monkeypatch.setattr(cli, 'process_records', lambda lines, e, i, r: ["r"])
    # Run main
    cli.main()
    return capsys.readouterr()


def test_main_stdout(monkeypatch, tmp_path, capsys):
    out = run_main_and_capture(['--file', str(tmp_path / 'main.log')], monkeypatch, tmp_path, capsys)
    # Validate JSON output
    data = json.loads(out.out)
    assert data['total_lines'] == 1
    assert data['parsed_records'] == 1
    assert data['output_records'] == 1
    assert data['records'] == ["r"]


def test_main_with_rules(monkeypatch, tmp_path, capsys):
    out = run_main_and_capture([
        '--file', str(tmp_path / 'main.log'),
        '--rules'
    ], monkeypatch, tmp_path, capsys)
    data = json.loads(out.out)
    assert data['total_lines'] == 1
    # parsed_records should be null in JSON (None in Python)
    assert 'parsed_records' in data and data['parsed_records'] is None
    assert data['output_records'] == 1


def test_main_output_file(monkeypatch, tmp_path, caplog):
    # Test writing to an output file
    log_file = tmp_path / "out.log"
    log_file.write_text("line\n")
    out_file = tmp_path / "out" / "res.json"
    monkeypatch.setattr(sys, 'argv', ['prog', '--file', str(log_file), '--output', str(out_file)])
    monkeypatch.setattr(cli, 'process_records', lambda lines, e, i, r: [{"ok": True}])
    # Capture logging output
    caplog.set_level(logging.INFO)
    cli.main()
    # File should exist
    assert out_file.exists()
    # Verify content
    content = json.loads(out_file.read_text())
    assert content['records'] == [{"ok": True}]
    # Check log for info message
    messages = [rec.getMessage() for rec in caplog.records]
    assert any(f"Output written to {out_file}" in m for m in messages)
