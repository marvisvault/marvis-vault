"""
Tests for the simulate command.
"""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from vault.cli.main import app

runner = CliRunner()

@pytest.fixture
def temp_agent_file(tmp_path):
    """Create a temporary agent file."""
    agent_data = {
        "role": "admin",
        "trustScore": 90,
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    return agent_file

@pytest.fixture
def temp_policy_file(tmp_path):
    """Create a temporary policy file."""
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 85",
            "role == 'admin'"
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    return policy_file

def test_simulate_valid_policy(temp_agent_file, temp_policy_file):
    """Test simulate command with valid policy and agent."""
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(temp_policy_file)])
    assert result.exit_code == 0
    assert "All conditions passed" in result.stdout

def test_simulate_missing_when_condition(temp_agent_file, tmp_path):
    """Test simulate command with missing when condition."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            None,  # Missing condition
            "role == 'admin'"
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    assert "Skipped invalid condition" in result.stdout
    assert "Condition cannot be empty or None" in result.stdout

def test_simulate_empty_when_condition(temp_agent_file, tmp_path):
    """Test simulate command with empty when condition."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "",  # Empty condition
            "role == 'admin'"
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    assert "Skipped invalid condition" in result.stdout
    assert "Condition cannot be empty or None" in result.stdout

def test_simulate_invalid_syntax(temp_agent_file, tmp_path):
    """Test simulate command with invalid condition syntax."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "== true",  # Missing left operand
            "foo and",  # Incomplete AND
            "!isValid",  # Invalid operator
            "role == 'admin'"  # Valid condition
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    assert "Skipped invalid condition" in result.stdout
    assert "Invalid operator at position 0" in result.stdout
    assert "All conditions passed" in result.stdout  # Valid condition should still pass

def test_simulate_whitespace_condition(temp_agent_file, tmp_path):
    """Test simulate command with whitespace-only condition."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "   ",  # Whitespace only
            "role == 'admin'"
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    assert "Skipped invalid condition" in result.stdout
    assert "Condition cannot be whitespace only" in result.stdout 