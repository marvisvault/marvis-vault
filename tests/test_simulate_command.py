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
    """Create a temporary agent file with admin role."""
    agent_data = {
        "role": "admin",
        "trustScore": 90,
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    return agent_file

@pytest.fixture
def temp_non_admin_agent_file(tmp_path):
    """Create a temporary agent file with non-admin role."""
    agent_data = {
        "role": "analyst",
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
        "name": "Test Policy",
        "template_id": "test-policy",
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

def parse_cli_output(output: str) -> dict:
    """Parse CLI output into structured format."""
    result = {
        "context_summary": {},
        "masking_analysis": {},
        "conditions": []
    }
    
    # Extract sections based on table titles
    sections = output.split("\n\n")
    current_section = None
    
    for line in output.split("\n"):
        if "Context Summary" in line:
            current_section = "context"
        elif "Masking Analysis" in line:
            current_section = "masking"
        elif "Condition Evaluation" in line:
            current_section = "conditions"
        elif current_section == "context" and "│" in line:
            # Parse context table rows
            parts = line.split("│")
            if len(parts) >= 3:
                key = parts[1].strip()
                value = parts[2].strip()
                if key and value:
                    result["context_summary"][key] = value
        elif current_section == "masking" and "│" in line:
            # Parse masking table rows
            parts = line.split("│")
            if len(parts) >= 4:
                field = parts[1].strip()
                status = parts[2].strip()
                reason = parts[3].strip()
                if field and status:
                    result["masking_analysis"] = {
                        "field": field,
                        "status": status,
                        "reason": reason
                    }
        elif current_section == "conditions" and "│" in line:
            # Parse condition table rows
            parts = line.split("│")
            if len(parts) >= 3:
                condition = parts[1].strip()
                status = parts[2].strip()
                if condition and status and condition != "Condition":
                    result["conditions"].append({
                        "condition": condition,
                        "status": status
                    })
    
    return result

def test_simulate_valid_policy(temp_agent_file, temp_policy_file):
    """Test simulate command with valid policy and admin agent."""
    result = runner.invoke(app, ["simulate", "-a", str(temp_agent_file), "-p", str(temp_policy_file)])
    assert result.exit_code == 0
    
    # Parse CLI output
    output = parse_cli_output(result.stdout)
    
    # Validate context summary
    assert output["context_summary"]["role"] == "admin"
    assert output["context_summary"]["trustScore"] == "90"
    assert output["context_summary"]["department"] == "IT"
    
    # Validate masking analysis - should show role override
    assert output["masking_analysis"]["status"] == "CLEAR"
    assert "Unmasked for role 'admin'" in output["masking_analysis"]["reason"]
    
    # Validate conditions - should be skipped due to role override
    assert len(output["conditions"]) == 1
    assert output["conditions"][0]["status"] == "SKIPPED"

def test_simulate_verbose_output(temp_non_admin_agent_file, temp_policy_file):
    """Test simulate command with verbose flag using non-admin agent."""
    result = runner.invoke(app, ["simulate", "-a", str(temp_non_admin_agent_file), "-p", str(temp_policy_file), "-v"])
    assert result.exit_code == 0
    
    # Validate verbose output includes explanations and fields affected
    assert "trustScore 90 > 85" in result.stdout
    assert "role 'analyst' != 'admin'" in result.stdout
    assert "Fields Affected" in result.stdout
    assert "trustScore" in result.stdout
    assert "role" in result.stdout

def test_simulate_export_format(temp_agent_file, temp_policy_file, tmp_path):
    """Test simulate command with export flag using admin agent."""
    export_path = tmp_path / "test_export.json"
    result = runner.invoke(app, [
        "simulate",
        "-a", str(temp_agent_file),
        "-p", str(temp_policy_file),
        "-e", str(export_path)
    ])
    assert result.exit_code == 0
    
    # Validate export file exists and has correct format
    assert export_path.exists()
    export_data = json.loads(export_path.read_text())
    
    # Validate structure
    assert "context_summary" in export_data
    assert "roles" in export_data
    assert "fields_to_mask" in export_data
    assert "conditions" in export_data
    assert "unmask_role_override" in export_data
    assert "reason" in export_data
    assert "policy_name" in export_data
    assert "template_id" in export_data
    
    # Validate content - should show role override
    assert export_data["context_summary"]["role"] == "admin"
    assert export_data["context_summary"]["trustScore"] == 90
    assert export_data["policy_name"] == "Test Policy"
    assert export_data["template_id"] == "test-policy"
    assert export_data["unmask_role_override"] is True
    assert len(export_data["conditions"]) == 0  # No conditions evaluated
    assert "Unmasked for role 'admin'" in export_data["reason"]

def test_simulate_unmask_role_override(tmp_path):
    """Test simulate with role-based unmask override."""
    # Create agent with admin role
    agent_data = {
        "role": "admin",
        "trustScore": 50  # Would fail conditions
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy with admin in unmask_roles
    policy_data = {
        "name": "Override Test",
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 75"  # Would fail
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Test basic output
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file)])
    assert result.exit_code == 0
    output = parse_cli_output(result.stdout)
    assert "CLEAR" in output["masking_analysis"]["status"]
    assert "Unmasked for role 'admin'" in output["masking_analysis"]["reason"]
    
    # Test export format
    export_path = tmp_path / "override_export.json"
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-e", str(export_path)])
    assert result.exit_code == 0
    
    export_data = json.loads(export_path.read_text())
    assert export_data["unmask_role_override"] is True
    assert len(export_data["conditions"]) == 0  # No conditions evaluated
    assert "Unmasked for role 'admin'" in export_data["reason"]

def test_simulate_mixed_conditions(tmp_path):
    """Test simulate with mix of passing and failing conditions using non-admin agent."""
    # Create agent that will pass some conditions but fail others
    agent_data = {
        "role": "analyst",
        "trustScore": 80,
        "department": "IT"
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    # Create policy with mixed conditions
    policy_data = {
        "name": "Mixed Test",
        "mask": ["ssn", "dob"],
        "unmask_roles": ["admin"],
        "conditions": [
            "trustScore > 75",  # Should pass
            "role == 'hr_manager'",  # Should fail
            "department == 'IT'"  # Should pass
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Test verbose output
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-v"])
    assert result.exit_code == 0
    assert "trustScore 80 > 75" in result.stdout
    assert "role 'analyst'" in result.stdout
    assert "'hr_manager'" in result.stdout
    assert "department 'IT' == 'IT'" in result.stdout
    
    # Test export format
    export_path = tmp_path / "mixed_export.json"
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-e", str(export_path)])
    assert result.exit_code == 0
    
    export_data = json.loads(export_path.read_text())
    assert len(export_data["conditions"]) == 3
    passed = [c for c in export_data["conditions"] if c["result"] == "pass"]
    failed = [c for c in export_data["conditions"] if c["result"] == "fail"]
    assert len(passed) == 2
    assert len(failed) == 1
    assert not export_data["fields_to_mask"]  # No masking since some conditions passed
    assert not export_data["unmask_role_override"]  # Not an admin role

def test_simulate_malformed_conditions(tmp_path):
    """Test simulate with malformed conditions."""
    agent_data = {
        "role": "analyst",
        "trustScore": 80
    }
    agent_file = tmp_path / "agent.json"
    agent_file.write_text(json.dumps(agent_data))
    
    policy_data = {
        "name": "Malformed Test",
        "mask": ["ssn"],
        "unmask_roles": [],
        "conditions": [
            "trustScore >",  # Invalid syntax
            None,  # Missing condition
            "",  # Empty condition
            "role == 'analyst'"  # Valid condition
        ]
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    
    # Test verbose output - should fail with non-zero exit code
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-v"])
    
    assert result.exit_code == 1
    assert "Failed to parse policy: 1 validation error for Policy" in result.stdout
    assert "Input should be a valid string" in result.stdout
    
    # Test export format - should fail with non-zero exit code
    export_path = tmp_path / "malformed_export.json"
    result = runner.invoke(app, ["simulate", "-a", str(agent_file), "-p", str(policy_file), "-e", str(export_path)])
    assert result.exit_code == 1
    assert not export_path.exists()  # Export file should not be created on error

def test_normalize_condition():
    """Test condition normalization function."""
    test_cases = [
        # Basic operators
        ("a && b", "a and b"),
        ("a || b", "a or b"),
        ("!a", "!a"),  # No conversion to "not a"
        ("a === b", "a == b"),
        ("a !== b", "a != b"),
        
        # Complex expressions
        ("a && b || c", "a and b or c"),
        ("!(a && b)", "!(a and b)"),
        ("a === 'test' && !b", "a == 'test' and !b"),
        
        # String literals should be preserved
        ("role === 'admin && user'", "role == 'admin && user'"),
        ('message === "test || prod"', 'message == "test || prod"'),
        
        # Edge cases
        ("a&&b", "a and b"),
        ("a||b", "a or b"),
        ("a  &&  b", "a and b"),
        
        # Multiple operators
        ("a && b && c", "a and b and c"),
        ("a || b || c", "a or b or c"),
        ("a && b || c && d", "a and b or c and d"),
        
        # Parentheses
        ("(a && b) || c", "(a and b) or c"),
        ("!(a || b) && c", "!(a or b) and c"),
        
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
    assert normalize_condition("   ") == ""  # Whitespace normalizes to empty string
    
    # Invalid types
    assert normalize_condition(123) == 123
    assert normalize_condition(True) is True
    
    # String literals with operators
    assert normalize_condition("field == '!== && ||'") == "field == '!== && ||'"
    assert normalize_condition('message === "a && b || c"') == 'message == "a && b || c"'
    
    # Complex nested expressions
    complex_expr = "(role === 'admin' && !test) || (trustScore > 85 && !blocked)"
    expected = "(role == 'admin' and !test) or (trustScore > 85 and !blocked)"
    assert normalize_condition(complex_expr) == expected 