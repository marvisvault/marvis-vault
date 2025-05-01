import pytest
from pathlib import Path
import json
from io import StringIO
from unittest.mock import patch
from vault.cli.audit import read_audit_log, format_csv, format_json, audit

@pytest.fixture
def valid_log(tmp_path):
    """Create a valid audit log file."""
    log_path = tmp_path / "vault.log"
    entries = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "action": "read",
            "field": "trust_score",
            "result": "allowed"
        },
        {
            "timestamp": "2024-01-01T00:01:00Z",
            "action": "write",
            "field": "role",
            "result": "denied"
        }
    ]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return log_path

@pytest.fixture
def malformed_log(tmp_path):
    """Create an audit log file with malformed entries."""
    log_path = tmp_path / "malformed.log"
    entries = [
        '{"timestamp": "2024-01-01T00:00:00Z", "action": "read", "field": "trust_score", "result": "allowed"}',
        '{"invalid": "json"',
        '{"timestamp": "2024-01-01T00:01:00Z", "action": "write", "field": "role", "result": "denied"}'
    ]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(entry + "\n")
    return log_path

@pytest.fixture
def incomplete_log(tmp_path):
    """Create an audit log file with incomplete entries."""
    log_path = tmp_path / "incomplete.log"
    entries = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "action": "read",
            "field": "trust_score"
            # Missing "result" field
        },
        {
            "timestamp": "2024-01-01T00:01:00Z",
            "action": "write",
            "field": "role",
            "result": "denied"
        }
    ]
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return log_path

def test_read_audit_log_valid(valid_log):
    """Test reading a valid audit log file."""
    entries = read_audit_log(valid_log)
    assert len(entries) == 2
    assert entries[0]["action"] == "read"
    assert entries[1]["action"] == "write"

def test_read_audit_log_malformed(malformed_log):
    """Test reading a malformed audit log file."""
    entries = read_audit_log(malformed_log)
    assert len(entries) == 2  # Should skip the malformed entry
    assert entries[0]["action"] == "read"
    assert entries[1]["action"] == "write"

def test_read_audit_log_incomplete(incomplete_log):
    """Test reading an audit log file with incomplete entries."""
    entries = read_audit_log(incomplete_log)
    assert len(entries) == 1  # Should skip the incomplete entry
    assert entries[0]["action"] == "write"

def test_read_audit_log_missing():
    """Test reading a missing audit log file."""
    with pytest.raises(Exception):
        read_audit_log(Path("nonexistent.log"))

def test_format_csv(valid_log):
    """Test formatting audit log entries as CSV."""
    entries = read_audit_log(valid_log)
    csv_output = format_csv(entries)
    assert "timestamp,action,field,result" in csv_output
    assert "2024-01-01T00:00:00Z,read,trust_score,allowed" in csv_output
    assert "2024-01-01T00:01:00Z,write,role,denied" in csv_output

def test_format_json(valid_log):
    """Test formatting audit log entries as JSON."""
    entries = read_audit_log(valid_log)
    json_output = format_json(entries)
    parsed = json.loads(json_output)
    assert len(parsed) == 2
    assert parsed[0]["action"] == "read"
    assert parsed[1]["action"] == "write"

def test_audit_command_valid_csv(valid_log, capsys):
    """Test the audit command with valid log and CSV format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log), "--format", "csv"]):
        audit()
    captured = capsys.readouterr()
    assert "timestamp,action,field,result" in captured.out
    assert "2024-01-01T00:00:00Z,read,trust_score,allowed" in captured.out

def test_audit_command_valid_json(valid_log, capsys):
    """Test the audit command with valid log and JSON format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log), "--format", "json"]):
        audit()
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert len(output) == 2
    assert output[0]["action"] == "read"
    assert output[1]["action"] == "write"

def test_audit_command_missing_log(capsys):
    """Test the audit command with missing log file."""
    with patch("sys.argv", ["audit", "--log", "nonexistent.log"]):
        with pytest.raises(SystemExit):
            audit()
    captured = capsys.readouterr()
    assert "Audit log file not found" in captured.err

def test_audit_command_unsupported_format(valid_log, capsys):
    """Test the audit command with unsupported format."""
    with patch("sys.argv", ["audit", "--log", str(valid_log), "--format", "xml"]):
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