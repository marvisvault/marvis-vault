import pytest
import os
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from vault.audit.audit_logger import (
    log_event,
    get_log_path,
    validate_agent,
    format_timestamp
)

@pytest.fixture
def valid_agent():
    """Create a valid agent dictionary."""
    return {
        "role": "admin",
        "trustScore": 90,
        "department": "security"
    }

@pytest.fixture
def invalid_agent():
    """Create an invalid agent dictionary (missing required keys)."""
    return {
        "department": "security"
    }

@pytest.fixture
def log_file(tmp_path):
    """Create a temporary log file."""
    return tmp_path / "vault.log"

def test_validate_agent_valid(valid_agent):
    """Test validation of a valid agent."""
    validate_agent(valid_agent)  # Should not raise

def test_validate_agent_invalid(invalid_agent):
    """Test validation of an invalid agent."""
    with pytest.raises(ValueError) as e:
        validate_agent(invalid_agent)
    assert "missing required keys" in str(e.value)

def test_format_timestamp():
    """Test timestamp formatting."""
    timestamp = format_timestamp()
    # Should be in ISO 8601 format with Z suffix
    assert timestamp.endswith("Z")
    # Should be parseable as datetime
    datetime.fromisoformat(timestamp[:-1])  # Remove Z for parsing

def test_get_log_path_default():
    """Test getting default log path."""
    path = get_log_path()
    assert path == Path("vault.log")

def test_get_log_path_env_var(tmp_path):
    """Test getting log path from environment variable."""
    custom_path = tmp_path / "custom.log"
    with patch.dict(os.environ, {"VAULT_LOG_PATH": str(custom_path)}):
        path = get_log_path()
        assert path == custom_path

def test_log_event_valid(log_file, valid_agent):
    """Test logging a valid event."""
    # Log an event
    log_event("redact", "email", valid_agent, "masked")
    
    # Read the log file
    with log_file.open() as f:
        entry = json.loads(f.readline())
    
    # Check entry contents
    assert "timestamp" in entry
    assert entry["action"] == "redact"
    assert entry["field"] == "email"
    assert entry["agent"] == valid_agent
    assert entry["result"] == "masked"
    
    # Check timestamp format
    datetime.fromisoformat(entry["timestamp"][:-1])  # Remove Z for parsing

def test_log_event_invalid_agent(log_file, invalid_agent):
    """Test logging with invalid agent."""
    with pytest.raises(ValueError):
        log_event("redact", "email", invalid_agent, "masked")
    
    # Log file should be empty
    assert not log_file.exists()

def test_log_event_multiple_entries(log_file, valid_agent):
    """Test logging multiple events."""
    # Log two events
    log_event("redact", "email", valid_agent, "masked")
    log_event("unmask", "ssn", valid_agent, "unmasked")
    
    # Read the log file
    with log_file.open() as f:
        entries = [json.loads(line) for line in f]
    
    # Check number of entries
    assert len(entries) == 2
    
    # Check first entry
    assert entries[0]["action"] == "redact"
    assert entries[0]["field"] == "email"
    assert entries[0]["result"] == "masked"
    
    # Check second entry
    assert entries[1]["action"] == "unmask"
    assert entries[1]["field"] == "ssn"
    assert entries[1]["result"] == "unmasked"

def test_log_event_file_error(log_file, valid_agent):
    """Test logging when file cannot be written."""
    # Make parent directory read-only
    log_file.parent.chmod(0o444)
    
    with pytest.raises(IOError):
        log_event("redact", "email", valid_agent, "masked")

def test_log_event_json_error(log_file, valid_agent):
    """Test logging when JSON serialization fails."""
    # Create an agent with unserializable data
    invalid_agent = valid_agent.copy()
    invalid_agent["invalid"] = lambda x: x  # Functions can't be JSON serialized
    
    with pytest.raises(IOError):
        log_event("redact", "email", invalid_agent, "masked")
    
    # Log file should be empty
    assert not log_file.exists() 