"""
Tests for the simulate command.
"""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from vault.cli.main import app
from vault.engine.condition_evaluator import normalize_condition

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

def test_simulate_js_style_conditions(temp_agent_file, tmp_path):
    """Test simulate command with JavaScript-style condition syntax."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 85 && role !== 'auditor'",  # JS AND and !==
            "role === 'admin' || department === 'IT'",  # JS OR and ===
            "!isTest && trustScore > 75",  # JS NOT
            "role == 'admin'"  # Regular condition
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    assert "All conditions passed" in result.stdout

def test_normalize_condition():
    """Test condition normalization function."""
    test_cases = [
        # Basic operators
        ("a && b", "a and b"),
        ("a || b", "a or b"),
        ("!a", "not a"),
        ("a === b", "a == b"),
        ("a !== b", "a != b"),
        
        # Complex expressions
        ("a && b || c", "a and b or c"),
        ("!(a && b)", "not (a and b)"),
        ("a === 'test' && !b", "a == 'test' and not b"),
        
        # String literals should be preserved
        ("role === 'admin && user'", "role == 'admin && user'"),
        ('message === "test || prod"', 'message == "test || prod"'),
        
        # Edge cases
        ("a&&b", "a and b"),
        ("a||b", "a or b"),
        ("a  &&  b", "a  and  b"),
        
        # Multiple operators
        ("a && b && c", "a and b and c"),
        ("a || b || c", "a or b or c"),
        ("a && b || c && d", "a and b or c and d"),
        
        # Parentheses
        ("(a && b) || c", "(a and b) or c"),
        ("!(a || b) && c", "not (a or b) and c"),
        
        # Should not modify
        ("!=", "!="),  # Already a valid operator
        ("==", "=="),  # Already a valid operator
        ("'!important'", "'!important'"),  # Inside string
        ("field_name", "field_name"),  # Regular identifier
    ]
    
    for input_str, expected in test_cases:
        assert normalize_condition(input_str) == expected, \
            f"Failed to normalize '{input_str}', got '{normalize_condition(input_str)}', expected '{expected}'"

def test_normalize_condition_edge_cases():
    """Test condition normalization edge cases."""
    # None/empty cases
    assert normalize_condition(None) is None
    assert normalize_condition("") == ""
    assert normalize_condition("   ") == "   "
    
    # Invalid types
    assert normalize_condition(123) == 123
    assert normalize_condition(True) is True
    
    # String literals with operators
    assert normalize_condition("field == '!== && ||'") == "field == '!== && ||'"
    assert normalize_condition('message === "a && b || c"') == 'message == "a && b || c"'
    
    # Complex nested expressions
    complex_expr = "(role === 'admin' && !test) || (trustScore > 85 && !blocked)"
    expected = "(role == 'admin' and not test) or (trustScore > 85 and not blocked)"
    assert normalize_condition(complex_expr) == expected 

def test_simulate_regression_js_syntax(tmp_path):
    """Regression test for JS-style condition syntax with nested context."""
    # Create agent file
    agent_data = {
        "role": "admin",
        "trustScore": 90,
        "context": {
            "department": "IT"
        }
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy file
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 85 && role !== 'auditor'",
            "role === 'admin'"
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Run simulate command
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file)])
    
    # Verify output
    assert result.exit_code == 0
    assert "All conditions passed" in result.stdout
    assert "No fields would be masked" in result.stdout
    assert "Warnings" not in result.stdout  # No warnings expected

def test_simulate_mixed_condition_failures(temp_agent_file, tmp_path):
    """Test simulate command with mix of valid and invalid conditions."""
    policy_data = {
        "mask": ["ssn"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 85 && role !== 'auditor'",  # Valid, should pass
            "!== invalid syntax",  # Invalid, should be skipped
            "unknown_field > 10",  # Valid syntax but unknown field
            "role === 'admin'"  # Valid, should pass
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(policy_file)])
    
    # Check output formatting
    assert result.exit_code == 0
    assert "⚠ Warnings" in result.stdout
    assert "Skipped invalid condition" in result.stdout
    assert "Invalid operator at position 0" in result.stdout  # For "!== invalid syntax"
    assert "Context key 'unknown_field' not found" in result.stdout
    assert "All conditions passed" in result.stdout  # Valid conditions still pass

def test_simulate_partial_condition_pass(tmp_path):
    """Test that fields are not masked if at least one condition passes."""
    # Create agent with trustScore > 75 but not hr_manager role
    agent_data = {
        "role": "analyst",
        "trustScore": 80,
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy with two conditions - one should pass, one should fail
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 75",  # This should pass
            "role == 'hr_manager'"  # This should fail
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Run simulate command
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file)])
    
    # Check results
    assert result.exit_code == 0
    assert "1 of 2 conditions passed" in result.stdout
    assert "No fields would be masked" in result.stdout
    
    # Run with verbose flag
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-v"])
    assert result.exit_code == 0
    assert "trustScore > 75" in result.stdout
    assert "PASSED" in result.stdout
    assert "role == 'hr_manager'" in result.stdout
    assert "FAILED" in result.stdout

def test_simulate_unmask_role_override(tmp_path):
    """Test that unmask_roles override condition evaluation."""
    # Create agent with admin role but failing conditions
    agent_data = {
        "role": "admin",
        "trustScore": 50,  # Would fail trustScore condition
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy where admin is in unmask_roles
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 75",  # Would fail
            "department == 'HR'"  # Would fail
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Run simulate command
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file)])
    
    # Check that conditions were skipped due to unmask_role
    assert result.exit_code == 0
    assert "Role admin is in unmask_roles" in result.stdout
    assert "No fields would be masked" in result.stdout

def test_simulate_all_conditions_fail(tmp_path):
    """Test that fields are masked only when all conditions fail."""
    # Create agent that fails all conditions
    agent_data = {
        "role": "analyst",
        "trustScore": 50,
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy with multiple failing conditions
    policy_data = {
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 75",  # Will fail
            "role == 'hr_manager'",  # Will fail
            "department == 'HR'"  # Will fail
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Run simulate command
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file)])
    
    # Check that all fields are masked
    assert result.exit_code == 0
    assert "All conditions failed" in result.stdout
    assert "MASKED" in result.stdout
    assert "ssn" in result.stdout
    assert "dob" in result.stdout 