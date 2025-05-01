import pytest
import json
from pathlib import Path
from vault.audit.export_log import (
    export_log,
    validate_log_entry,
    format_csv,
    format_json
)

@pytest.fixture
def valid_log_entry():
    """Create a valid log entry."""
    return {
        "timestamp": "2024-04-30T12:34:56Z",
        "action": "redact",
        "field": "email",
        "agent": {
            "role": "admin",
            "trustScore": 90
        },
        "result": "masked"
    }

@pytest.fixture
def invalid_log_entry():
    """Create an invalid log entry (missing required fields)."""
    return {
        "timestamp": "2024-04-30T12:34:56Z",
        "field": "email",
        "result": "masked"
    }

@pytest.fixture
def log_file(tmp_path, valid_log_entry):
    """Create a log file with valid and invalid entries."""
    path = tmp_path / "vault.log"
    
    # Write valid entry
    with path.open("w") as f:
        f.write(json.dumps(valid_log_entry) + "\n")
        # Write malformed JSON
        f.write("{invalid json}\n")
        # Write entry missing required fields
        f.write(json.dumps({"timestamp": "2024-04-30T12:34:56Z"}) + "\n")
        # Write another valid entry
        f.write(json.dumps(valid_log_entry) + "\n")
    
    return path

def test_validate_log_entry_valid(valid_log_entry):
    """Test validation of a valid log entry."""
    assert validate_log_entry(valid_log_entry)

def test_validate_log_entry_invalid(invalid_log_entry):
    """Test validation of an invalid log entry."""
    assert not validate_log_entry(invalid_log_entry)

def test_format_csv(valid_log_entry):
    """Test CSV formatting of log entries."""
    entries = [valid_log_entry]
    csv_output = format_csv(entries)
    
    # Check header
    assert "timestamp,field,role,result" in csv_output
    
    # Check entry
    assert valid_log_entry["timestamp"] in csv_output
    assert valid_log_entry["field"] in csv_output
    assert valid_log_entry["agent"]["role"] in csv_output
    assert valid_log_entry["result"] in csv_output

def test_format_json(valid_log_entry):
    """Test JSON formatting of log entries."""
    entries = [valid_log_entry]
    json_output = format_json(entries)
    
    # Parse output to verify it's valid JSON
    parsed = json.loads(json_output)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0] == valid_log_entry

def test_export_log_csv(log_file):
    """Test exporting log to CSV format."""
    output = export_log(str(log_file), "csv")
    
    # Check header
    assert "timestamp,field,role,result" in output
    
    # Check entries (should only include valid ones)
    lines = output.strip().split("\n")
    assert len(lines) == 3  # header + 2 valid entries

def test_export_log_json(log_file):
    """Test exporting log to JSON format."""
    output = export_log(str(log_file), "json")
    
    # Parse output to verify it's valid JSON
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert len(parsed) == 2  # 2 valid entries

def test_export_log_missing_file():
    """Test exporting from a missing log file."""
    with pytest.raises(FileNotFoundError):
        export_log("nonexistent.log")

def test_export_log_default_path(tmp_path, valid_log_entry):
    """Test exporting using default log path."""
    # Create vault.log in current directory
    path = tmp_path / "vault.log"
    with path.open("w") as f:
        f.write(json.dumps(valid_log_entry) + "\n")
    
    # Export without specifying path
    output = export_log(output_format="csv")
    assert valid_log_entry["timestamp"] in output

def test_export_log_unsupported_format(log_file):
    """Test exporting with unsupported format."""
    with pytest.raises(ValueError):
        export_log(str(log_file), "xml")

def test_export_log_malformed_lines(log_file, capsys):
    """Test handling of malformed log lines."""
    # Export should succeed but warn about malformed lines
    output = export_log(str(log_file), "csv")
    
    # Check warnings
    captured = capsys.readouterr()
    assert "Skipping malformed JSON line" in captured.out
    assert "Skipping entry missing required fields" in captured.out
    
    # Check output still contains valid entries
    lines = output.strip().split("\n")
    assert len(lines) == 3  # header + 2 valid entries 