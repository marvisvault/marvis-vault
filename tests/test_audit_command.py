"""
Tests for the audit command.
"""

import pytest
from pathlib import Path
import json
from io import StringIO
from unittest.mock import patch, MagicMock
from vault.cli.audit import read_audit_log, audit, format_table
import typer

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
    filtered_table = format_table(entries, role_filter="admin")
    assert filtered_table.row_count == 1
    assert filtered_table.columns[2]._cells[0] == "admin"

def test_audit_command_valid(valid_log_path, capsys):
    """Test the audit command with valid log."""
    mock_log = MagicMock(spec=typer.models.OptionInfo)
    mock_log.value = valid_log_path
    mock_role = MagicMock(spec=typer.models.OptionInfo)
    mock_role.value = None
    
    with patch("vault.cli.audit.read_audit_log") as mock_read:
        mock_read.return_value = [
            {
                "timestamp": "2024-03-03T10:00:00Z",
                "action": "redact",
                "role": "admin",
                "input": "123-45-6789",
                "output": "[REDACTED]"
            }
        ]
        audit(log=mock_log, role=mock_role)
    
    captured = capsys.readouterr()
    assert "Audit Log" in captured.out
    assert "Timestamp" in captured.out
    assert "Action" in captured.out
    assert "Role" in captured.out

def test_audit_command_missing_log(capsys):
    """Test the audit command with missing log file."""
    mock_log = MagicMock(spec=typer.models.OptionInfo)
    mock_log.value = Path("nonexistent.jsonl")
    mock_role = MagicMock(spec=typer.models.OptionInfo)
    mock_role.value = None
    
    with patch("vault.cli.audit.read_audit_log") as mock_read:
        mock_read.side_effect = typer.BadParameter("File not found")
        with pytest.raises(typer.Exit) as exc_info:
            audit(log=mock_log, role=mock_role)
        assert exc_info.value.exit_code == 1
    
    captured = capsys.readouterr()
    assert "Error" in captured.out
    assert "File not found" in captured.out

def test_audit_command_role_filter(valid_log_path, capsys):
    """Test the audit command with role filtering."""
    mock_log = MagicMock(spec=typer.models.OptionInfo)
    mock_log.value = valid_log_path
    mock_role = MagicMock(spec=typer.models.OptionInfo)
    mock_role.value = "vendor"
    
    with patch("vault.cli.audit.read_audit_log") as mock_read:
        mock_read.return_value = [
            {
                "timestamp": "2024-03-03T10:01:00Z",
                "action": "redact",
                "role": "vendor",
                "input": "john@example.com",
                "output": "[REDACTED]"
            }
        ]
        audit(log=mock_log, role=mock_role)
    
    captured = capsys.readouterr()
    assert "vendor" in captured.out
    assert "admin" not in captured.out 