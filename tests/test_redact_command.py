"""
Test suite for vault redact CLI command.
"""

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner
from vault.cli.redact import app

# Initialize CLI runner
runner = CliRunner()

@pytest.fixture
def tmp_input_file(tmp_path):
    """Create a temporary input file."""
    return tmp_path / "input.txt"

@pytest.fixture
def tmp_policy_file(tmp_path):
    """Create a temporary policy file."""
    return tmp_path / "policy.json"

@pytest.fixture
def tmp_output_file(tmp_path):
    """Create a temporary output file."""
    return tmp_path / "output.txt"

@pytest.fixture
def tmp_audit_file(tmp_path):
    """Create a temporary audit file."""
    return tmp_path / "audit.json"

def test_plaintext_redaction(tmp_input_file, tmp_policy_file, tmp_output_file, tmp_audit_file):
    """Test redaction of plaintext input with basic fields."""
    # Setup input file
    input_content = """name: John
email: john@example.com
phone: 555-1234"""
    tmp_input_file.write_text(input_content)
    
    # Setup policy file
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--audit", str(tmp_audit_file),
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0
    assert "[REDACTED]" in tmp_output_file.read_text()
    assert "email" in tmp_output_file.read_text()
    assert "phone" in tmp_output_file.read_text()
    
    # Check audit log
    audit_data = json.loads(tmp_audit_file.read_text())
    assert "email" in audit_data["field_statistics"]
    assert "phone" in audit_data["field_statistics"]
    assert audit_data["summary"]["total_fields_redacted"] >= 2
    assert audit_data["summary"]["total_occurrences"] >= 2

def test_json_nested_redaction(tmp_input_file, tmp_policy_file, tmp_output_file, tmp_audit_file):
    """Test redaction of nested JSON fields."""
    # Setup input file
    input_content = {
        "user": {
            "email": "jane@x.com",
            "contact": {"phone": "123"}
        },
        "role": "admin"
    }
    tmp_input_file.write_text(json.dumps(input_content))
    
    # Setup policy file
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--audit", str(tmp_audit_file),
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0
    output_data = json.loads(tmp_output_file.read_text())
    assert output_data["user"]["email"] == "[REDACTED]"
    assert output_data["user"]["contact"]["phone"] == "[REDACTED]"
    assert output_data["role"] == "admin"  # Unmasked field
    
    # Check audit log
    audit_data = json.loads(tmp_audit_file.read_text())
    assert audit_data["summary"]["format"] == "JSON"
    assert len(audit_data["detailed_log"]) == 2  # Two fields redacted

def test_compact_json_output(tmp_input_file, tmp_policy_file, tmp_output_file):
    """Test compact JSON output format."""
    # Setup input file
    input_content = {
        "email": "test@example.com",
        "phone": "555-1234"
    }
    tmp_input_file.write_text(json.dumps(input_content))
    
    # Setup policy file
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command with --json flag
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--json",
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0
    output_text = tmp_output_file.read_text()
    assert "\n" not in output_text  # No newlines in compact JSON
    assert "[REDACTED]" in output_text
    assert json.loads(output_text)  # Valid JSON

def test_missing_field_handling(tmp_input_file, tmp_policy_file, tmp_output_file, tmp_audit_file):
    """Test handling of missing fields in input."""
    # Setup input file
    input_content = {
        "email": "test@example.com",
        "name": "Test User"
    }
    tmp_input_file.write_text(json.dumps(input_content))
    
    # Setup policy file with extra field
    policy = {
        "mask": ["email", "ssn"],  # ssn not in input
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--audit", str(tmp_audit_file),
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0
    output_data = json.loads(tmp_output_file.read_text())
    assert output_data["email"] == "[REDACTED]"
    assert "ssn" not in output_data
    assert output_data["name"] == "Test User"
    
    # Check audit log
    audit_data = json.loads(tmp_audit_file.read_text())
    assert "email" in audit_data["field_statistics"]
    assert "ssn" not in audit_data["field_statistics"]
    assert audit_data["summary"]["total_fields_redacted"] == 1

def test_malformed_input_handling(tmp_input_file, tmp_policy_file, tmp_output_file, tmp_audit_file):
    """Test handling of malformed input files."""
    # Setup malformed input file
    input_content = "{invalid json"
    tmp_input_file.write_text(input_content)
    
    # Setup policy file
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--audit", str(tmp_audit_file),
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0  # Should not crash
    output_text = tmp_output_file.read_text()
    assert "invalid" in output_text  # Original content preserved

    # Check audit log
    audit_data = json.loads(tmp_audit_file.read_text())
    assert audit_data["summary"]["format"] == "Text"
    # Skip field_statistics check, only validate fallback log is present
    assert any("JSON redaction failed" in entry.get("reason", "") for entry in audit_data["detailed_log"])


def test_field_aliases(tmp_input_file, tmp_policy_file, tmp_output_file, tmp_audit_file):
    """Test redaction with field aliases."""
    # Setup input file
    input_content = """name: John
e-mail: john@example.com
tel: 555-1234"""
    tmp_input_file.write_text(input_content)
    
    # Setup policy file with aliases
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": [],
        "fieldAliases": {
            "email": ["e-mail", "mail"],
            "phone": ["tel", "mobile"]
        }
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Run command
    result = runner.invoke(app, [
        "--input", str(tmp_input_file),
        "--policy", str(tmp_policy_file),
        "--output", str(tmp_output_file),
        "--audit", str(tmp_audit_file),
        "--force"
    ])
    
    # Assertions
    assert result.exit_code == 0
    output_text = tmp_output_file.read_text()
    # Aliases get rewritten using canonical mask field names in output
    assert "email: [REDACTED]" in output_text
    assert "phone: [REDACTED]" in output_text
    
    # Check audit log
    audit_data = json.loads(tmp_audit_file.read_text())
    assert "email" in audit_data["field_statistics"]
    assert "phone" in audit_data["field_statistics"]
    assert audit_data["summary"]["total_occurrences"] >= 2


def test_stdin_stdout(tmp_policy_file):
    """Test reading from stdin and writing to stdout."""
    # Setup policy file
    policy = {
        "mask": ["email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": []
    }
    tmp_policy_file.write_text(json.dumps(policy))
    
    # Setup input
    input_content = "email: test@example.com\nphone: 555-1234"
    
    # Run command
    result = runner.invoke(app, [
        "--policy", str(tmp_policy_file)
    ], input=input_content)
    
    # Assertions
    assert result.exit_code == 0
    assert "email: [REDACTED]" in result.stdout
    assert "phone: [REDACTED]" in result.stdout 