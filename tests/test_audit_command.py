"""
Tests for the audit command.
"""

import pytest
from pathlib import Path
import json
from io import StringIO
from unittest.mock import patch
from vault.cli.audit import read_audit_log, format_csv, format_json, audit, format_table

@pytest.fixture
def valid_log_path(tmp_path):
    """Create a valid audit log file."""
    log_path = tmp_path / "audit_log.jsonl"
    entries = [
        {
            "timestamp": "2024-03-03T10:00:00Z",
            "action": "redact",
            "role": "admin",
            "input": "123-45-6789",
            "output": "[REDACTED]"
        },
        {
            "timestamp": "2024-03-03T10:01:00Z",
            "action": "redact",
            "role": "vendor",
            "input": "john@example.com",
            "output": "[REDACTED]"
        }
    ]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return log_path

@pytest.fixture
def malformed_log_path(tmp_path):
    """Create an audit log file with malformed entries."""
    log_path = tmp_path / "malformed_log.jsonl"
    entries = [
        json.dumps({
            "timestamp": "2024-03-03T10:00:00Z",
            "action": "redact",
            "role": "admin",
            "input": "123-45-6789",
            "output": "[REDACTED]"
        }),
        "invalid json",
        json.dumps({
            "timestamp": "2024-03-03T10:01:00Z",
            "action": "redact",
            "role": "vendor",
            "input": "john@example.com",
            "output": "[REDACTED]"
        }),
        "{\"missing\": \"fields\"}"
    ]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(entry + "\n")
    return log_path

@pytest.fixture
def empty_log_path(tmp_path):
    """Create an empty audit log file."""
    log_path = tmp_path / "empty_log.jsonl"
    log_path.touch()
    return log_path

def test_audit_valid_logfile(valid_log_path):
    """Test reading a valid audit log file."""
    entries = read_audit_log(valid_log_path)
    assert len(entries) == 2
    assert all(field in entries[0] for field in ["timestamp", "action", "role"])
    assert entries[0]["action"] == "redact"
    assert entries[0]["role"] == "admin"

def test_audit_missing_file():
    """Test handling of missing audit log file."""
    with pytest.raises(Exception) as exc_info:
        read_audit_log(Path("nonexistent.jsonl"))
    assert "not found" in str(exc_info.value)

def test_audit_malformed_lines(malformed_log_path):
    """Test handling of malformed audit log entries."""
    entries = read_audit_log(malformed_log_path)
    assert len(entries) == 2  # Should skip invalid entries
    assert all(field in entries[0] for field in ["timestamp", "action", "role"])

def test_audit_empty_file(empty_log_path):
    """Test handling of empty audit log file."""
    entries = read_audit_log(empty_log_path)
    assert len(entries) == 0

def test_format_table(valid_log_path):
    """Test table formatting of audit log entries."""
    entries = read_audit_log(valid_log_path)
    table = format_table(entries)
    assert table.row_count == 2
    
    # Test role filtering
    filtered_table = format_table(entries, role="admin")
    assert filtered_table.row_count == 1
    assert filtered_table.columns[2]._cells[0] == "admin"

def test_format_csv(valid_log_path):
    """Test formatting audit log entries as CSV."""
    entries = read_audit_log(valid_log_path)
    csv_output = format_csv(entries)
    assert "timestamp,action,field,result" in csv_output
    assert "2024-03-03T10:00:00Z,redact,ssn,success" in csv_output
    assert "2024-03-03T10:01:00Z,redact,email,success" in csv_output

def test_format_json(valid_log_path):
    """Test formatting audit log entries as JSON."""
    entries = read_audit_log(valid_log_path)
    json_output = format_json(entries)
    parsed = json.loads(json_output)
    assert len(parsed) == 2
    assert parsed[0]["action"] == "redact"
    assert parsed[1]["action"] == "redact"

def test_audit_command_valid(valid_log_path, capsys):
    """Test the audit command with valid log."""
    with patch("sys.argv", ["audit", "--log", str(valid_log_path)]):
        audit()
    captured = capsys.readouterr()
    assert "Audit Log" in captured.out
    assert "Timestamp" in captured.out
    assert "Action" in captured.out
    assert "Role" in captured.out

def test_audit_command_missing_log(capsys):
    """Test the audit command with missing log file."""
    with patch("sys.argv", ["audit", "--log", "nonexistent.jsonl"]):
        with pytest.raises(SystemExit):
            audit()
    captured = capsys.readouterr()
    assert "not found" in captured.err

def test_audit_command_role_filter(valid_log_path, capsys):
    """Test the audit command with role filtering."""
    with patch("sys.argv", ["audit", "--log", str(valid_log_path), "--role", "vendor"]):
        audit()
    captured = capsys.readouterr()
    assert "vendor" in captured.out
    assert "admin" not in captured.out

def test_audit_command_valid_csv(valid_log_path, capsys):
    """Test the audit command with valid log and CSV format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log_path), "--format", "csv"]):
        audit()
    captured = capsys.readouterr()
    assert "timestamp,action,field,result" in captured.out
    assert "2024-03-03T10:00:00Z,redact,ssn,success" in captured.out
    assert "2024-03-03T10:01:00Z,redact,email,success" in captured.out

def test_audit_command_valid_json(valid_log_path, capsys):
    """Test the audit command with valid log and JSON format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log_path), "--format", "json"]):
        audit()
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) == 2
    assert output[0]["action"] == "redact"
    assert output[1]["action"] == "redact"

def test_audit_command_unsupported_format(valid_log_path, capsys):
    """Test the audit command with unsupported format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log_path), "--format", "xml"]):
        with pytest.raises(SystemExit):
            audit()
    captured = capsys.readouterr()
    assert "Unsupported format" in captured.err

def test_audit_command_default_log(tmp_path, capsys):
    """Test the audit command with default log file."""
    # Create default vault.log
    log_path = tmp_path / "vault.log"
    entries = [{
        "timestamp": "2024-01-01T00:00:00Z",
        "action": "read",
        "field": "trust_score",
        "result": "allowed"
    }]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    
    with patch("sys.argv", ["audit"]):
        audit()
    captured = capsys.readouterr()
    assert "timestamp,action,field,result" in captured.out 