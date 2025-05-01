import pytest
import json
from pathlib import Path
from vault.audit.trust_report import (
    generate_trust_report,
    validate_log_entry,
    count_field_access,
    count_role_frequency,
    count_action_results,
    get_role_field_patterns
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
    
    # Write valid entries with different fields and roles
    with path.open("w") as f:
        # Admin accessing email (masked)
        f.write(json.dumps(valid_log_entry) + "\n")
        
        # Admin accessing phone (unmasked)
        entry = valid_log_entry.copy()
        entry["field"] = "phone"
        entry["result"] = "unmasked"
        f.write(json.dumps(entry) + "\n")
        
        # Auditor accessing email (masked)
        entry = valid_log_entry.copy()
        entry["agent"]["role"] = "auditor"
        f.write(json.dumps(entry) + "\n")
        
        # Write malformed JSON
        f.write("{invalid json}\n")
        
        # Write entry missing required fields
        f.write(json.dumps({"timestamp": "2024-04-30T12:34:56Z"}) + "\n")
    
    return path

def test_validate_log_entry_valid(valid_log_entry):
    """Test validation of a valid log entry."""
    assert validate_log_entry(valid_log_entry)

def test_validate_log_entry_invalid(invalid_log_entry):
    """Test validation of an invalid log entry."""
    assert not validate_log_entry(invalid_log_entry)

def test_count_field_access(valid_log_entry):
    """Test counting field access frequency."""
    entries = [
        valid_log_entry,
        {**valid_log_entry, "field": "phone"},
        {**valid_log_entry, "field": "email"}
    ]
    counts = count_field_access(entries)
    assert counts["email"] == 2
    assert counts["phone"] == 1

def test_count_role_frequency(valid_log_entry):
    """Test counting role frequency."""
    entries = [
        valid_log_entry,
        {**valid_log_entry, "agent": {"role": "auditor"}},
        {**valid_log_entry, "agent": {"role": "admin"}}
    ]
    counts = count_role_frequency(entries)
    assert counts["admin"] == 2
    assert counts["auditor"] == 1

def test_count_action_results(valid_log_entry):
    """Test counting masked and unmasked actions."""
    entries = [
        valid_log_entry,
        {**valid_log_entry, "result": "unmasked"},
        {**valid_log_entry, "result": "masked"}
    ]
    mask_count, unmask_count = count_action_results(entries)
    assert mask_count == 2
    assert unmask_count == 1

def test_get_role_field_patterns(valid_log_entry):
    """Test getting role → field access patterns."""
    entries = [
        valid_log_entry,
        {**valid_log_entry, "field": "phone", "result": "unmasked"},
        {**valid_log_entry, "agent": {"role": "auditor"}}
    ]
    patterns = get_role_field_patterns(entries)
    assert patterns["admin"]["email"] == 1
    assert patterns["admin"]["phone"] == 1
    assert patterns["auditor"]["email"] == 1

def test_generate_trust_report_valid(log_file):
    """Test generating trust report from valid log."""
    report = generate_trust_report(str(log_file))
    
    # Check field access counts
    assert report["most_accessed_fields"]["email"] == 2
    assert report["most_accessed_fields"]["phone"] == 1
    
    # Check role frequency
    assert report["most_frequent_roles"]["admin"] == 2
    assert report["most_frequent_roles"]["auditor"] == 1
    
    # Check action counts
    assert report["mask_count"] == 2
    assert report["unmask_count"] == 1
    
    # Check role → field patterns
    assert report["role_field_patterns"]["admin"]["email"] == 1
    assert report["role_field_patterns"]["admin"]["phone"] == 1
    assert report["role_field_patterns"]["auditor"]["email"] == 1

def test_generate_trust_report_missing_file():
    """Test generating trust report from missing file."""
    with pytest.raises(FileNotFoundError):
        generate_trust_report("nonexistent.log")

def test_generate_trust_report_empty_file(tmp_path):
    """Test generating trust report from empty file."""
    path = tmp_path / "empty.log"
    path.touch()
    
    report = generate_trust_report(str(path))
    assert report["mask_count"] == 0
    assert report["unmask_count"] == 0
    assert not report["most_accessed_fields"]
    assert not report["most_frequent_roles"]
    assert not report["role_field_patterns"]

def test_generate_trust_report_default_path(tmp_path, valid_log_entry):
    """Test generating trust report using default log path."""
    # Create vault.log in current directory
    path = tmp_path / "vault.log"
    with path.open("w") as f:
        f.write(json.dumps(valid_log_entry) + "\n")
    
    # Generate report without specifying path
    report = generate_trust_report()
    assert report["mask_count"] == 1
    assert report["most_accessed_fields"]["email"] == 1
    assert report["most_frequent_roles"]["admin"] == 1 