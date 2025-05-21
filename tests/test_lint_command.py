"""
Tests for the lint command.
"""

import pytest
from typer.testing import CliRunner
from vault.cli.main import app
from pathlib import Path
import json

runner = CliRunner()

@pytest.fixture
def temp_valid_policy_file(tmp_path):
    """Create a temporary policy file with no warnings."""
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": ["trustScore > 85"]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    return policy_file

@pytest.fixture
def temp_policy_with_warnings(tmp_path):
    """Create a temporary policy file with warnings."""
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["*"],  # Overbroad role
        "conditions": [
            "trustScore > 85 && role == 'auditor'",  # Uses AND
            "trustScore > 75 || role == 'hr_admin'"  # Uses OR
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    return policy_file

def test_valid_policy_no_warnings(temp_valid_policy_file):
    """Test lint command with a valid policy that has no warnings."""
    result = runner.invoke(app, ["lint", "-p", str(temp_valid_policy_file)])
    assert result.exit_code == 0
    assert "Policy is valid!" in result.stdout
    assert "Found 0 error(s) and 0 warning(s)" in result.stdout

def test_valid_policy_with_warnings(temp_policy_with_warnings):
    """Test lint command with a valid policy that has warnings."""
    result = runner.invoke(app, ["lint", "-p", str(temp_policy_with_warnings)])
    assert result.exit_code == 0
    assert "Found 0 error(s)" in result.stdout
    assert "warning(s)" in result.stdout
    assert "Warning" in result.stdout

def test_valid_policy_strict_mode(temp_policy_with_warnings):
    """Test lint command with a valid policy that has warnings in strict mode."""
    result = runner.invoke(app, ["lint", "-p", str(temp_policy_with_warnings), "--strict"])
    assert result.exit_code == 1
    assert "Found 0 error(s)" in result.stdout
    assert "warning(s)" in result.stdout
    assert "Warning" in result.stdout

def test_malformed_policy():
    """Test lint command with a malformed policy file."""
    result = runner.invoke(app, ["lint", "-p", "examples/agents/malformed_policy.json"])
    assert result.exit_code == 1
    assert "Error" in result.stdout

def test_nonexistent_policy():
    """Test lint command with a nonexistent policy file."""
    result = runner.invoke(app, ["lint", "-p", "does_not_exist.json"], catch_exceptions=False)
    assert result.exit_code == 2  # Typer returns 2 for parameter validation errors
    assert "Error" in result.stdout 