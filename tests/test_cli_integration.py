#!/usr/bin/env pytest
"""
tests/test_cli_minimal.py — Minimal CLI test to debug issues
"""
import os
import json
import subprocess
import sys
from pathlib import Path

def test_cli_basic():
    """Just a basic test to see if the CLI works at all."""
    # Get paths
    project_root = Path(__file__).parent.parent
    cli_path = project_root / "blue_team_ai" / "cli.py"
    
    # Create a test log file
    test_log = project_root / "test_log.txt"
    test_log.write_text("<34>1 2025-05-15T14:31:02Z host1 sshd 1001 ID123 - Test message\n")
    
    # Try running the CLI (no JSON parsing)
    result = subprocess.run(
        [sys.executable, str(cli_path), "--file", str(test_log), "--help"],
        cwd=str(project_root),
        env={"PYTHONPATH": str(project_root)},
        capture_output=True,
        text=True,
    )
    
    # Just check return code
    assert result.returncode == 0, f"CLI failed: {result.stderr}\nCommand was: {sys.executable} {cli_path} --file {test_log} --help"
    
    # Print output for debugging
    print(f"CLI stdout: {result.stdout}")
    print(f"CLI stderr: {result.stderr}")