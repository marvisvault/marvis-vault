import pytest
from pathlib import Path
import json
from unittest.mock import patch
from vault.cli.lint import (
    validate_required_fields,
    validate_field_types,
    validate_lists_not_empty,
    check_unreachable_conditions,
    check_overbroad_unmask_roles,
    check_missing_context_fields,
    lint
)

@pytest.fixture
def valid_policy(tmp_path):
    """Create a valid policy file."""
    policy = {
        "mask": "****",
        "unmask_roles": ["admin"],
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 80
            },
            {
                "field": "role",
                "operator": "==",
                "value": "admin"
            }
        ]
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def missing_fields_policy(tmp_path):
    """Create a policy file with missing required fields."""
    policy = {
        "mask": "****"
        # Missing unmask_roles and conditions
    }
    path = tmp_path / "missing_fields.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def invalid_types_policy(tmp_path):
    """Create a policy file with invalid field types."""
    policy = {
        "mask": 123,  # Should be string
        "unmask_roles": "admin",  # Should be list
        "conditions": "invalid"  # Should be list
    }
    path = tmp_path / "invalid_types.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def empty_lists_policy(tmp_path):
    """Create a policy file with empty lists."""
    policy = {
        "mask": "****",
        "unmask_roles": [],
        "conditions": []
    }
    path = tmp_path / "empty_lists.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def unreachable_conditions_policy(tmp_path):
    """Create a policy file with unreachable conditions."""
    policy = {
        "mask": "****",
        "unmask_roles": ["admin"],
        "conditions": [
            {
                "field": "role",
                "operator": "==",
                "value": "admin"
            },
            {
                "field": "role",
                "operator": "==",
                "value": "user"  # Contradicts first condition
            }
        ]
    }
    path = tmp_path / "unreachable.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def overbroad_roles_policy(tmp_path):
    """Create a policy file with overbroad unmask_roles."""
    policy = {
        "mask": "****",
        "unmask_roles": ["*"],  # Overbroad
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 80
            }
        ]
    }
    path = tmp_path / "overbroad.json"
    path.write_text(json.dumps(policy))
    return path

def test_validate_required_fields_valid(valid_policy):
    """Test validation of required fields with valid policy."""
    policy = json.loads(valid_policy.read_text())
    errors = validate_required_fields(policy)
    assert not errors

def test_validate_required_fields_missing(missing_fields_policy):
    """Test validation of required fields with missing fields."""
    policy = json.loads(missing_fields_policy.read_text())
    errors = validate_required_fields(policy)
    assert len(errors) == 1
    assert "Missing required fields" in errors[0]
    assert "unmask_roles" in errors[0]
    assert "conditions" in errors[0]

def test_validate_field_types_valid(valid_policy):
    """Test validation of field types with valid policy."""
    policy = json.loads(valid_policy.read_text())
    errors = validate_field_types(policy)
    assert not errors

def test_validate_field_types_invalid(invalid_types_policy):
    """Test validation of field types with invalid types."""
    policy = json.loads(invalid_types_policy.read_text())
    errors = validate_field_types(policy)
    assert len(errors) == 3
    assert "must be a string" in errors[0]
    assert "must be a list" in errors[1]
    assert "must be a list" in errors[2]

def test_validate_lists_not_empty_valid(valid_policy):
    """Test validation of non-empty lists with valid policy."""
    policy = json.loads(valid_policy.read_text())
    errors = validate_lists_not_empty(policy)
    assert not errors

def test_validate_lists_not_empty_invalid(empty_lists_policy):
    """Test validation of non-empty lists with empty lists."""
    policy = json.loads(empty_lists_policy.read_text())
    errors = validate_lists_not_empty(policy)
    assert len(errors) == 2
    assert "cannot be empty" in errors[0]
    assert "cannot be empty" in errors[1]

def test_check_unreachable_conditions_valid(valid_policy):
    """Test checking for unreachable conditions with valid policy."""
    policy = json.loads(valid_policy.read_text())
    warnings = check_unreachable_conditions(policy)
    assert not warnings

def test_check_unreachable_conditions_invalid(unreachable_conditions_policy):
    """Test checking for unreachable conditions with contradictory conditions."""
    policy = json.loads(unreachable_conditions_policy.read_text())
    warnings = check_unreachable_conditions(policy)
    assert len(warnings) == 1
    assert "are contradictory" in warnings[0]

def test_check_overbroad_unmask_roles_valid(valid_policy):
    """Test checking for overbroad unmask_roles with valid policy."""
    policy = json.loads(valid_policy.read_text())
    warnings = check_overbroad_unmask_roles(policy)
    assert not warnings

def test_check_overbroad_unmask_roles_invalid(overbroad_roles_policy):
    """Test checking for overbroad unmask_roles with wildcard."""
    policy = json.loads(overbroad_roles_policy.read_text())
    warnings = check_overbroad_unmask_roles(policy)
    assert len(warnings) == 1
    assert "overbroad" in warnings[0]

def test_check_missing_context_fields(valid_policy):
    """Test checking for missing context fields."""
    policy = json.loads(valid_policy.read_text())
    warnings = check_missing_context_fields(policy)
    assert len(warnings) == 2
    assert "trust_score" in warnings[0]
    assert "role" in warnings[1]

def test_lint_command_valid(valid_policy, capsys):
    """Test the lint command with a valid policy."""
    with patch("sys.argv", ["lint", "--policy", str(valid_policy)]):
        with pytest.raises(SystemExit) as exc_info:
            lint()
        assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Policy is valid" in captured.out

def test_lint_command_missing_fields(missing_fields_policy, capsys):
    """Test the lint command with missing required fields."""
    with patch("sys.argv", ["lint", "--policy", str(missing_fields_policy)]):
        with pytest.raises(SystemExit) as exc_info:
            lint()
        assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Missing required fields" in captured.out

def test_lint_command_invalid_file(capsys):
    """Test the lint command with a non-existent file."""
    with patch("sys.argv", ["lint", "--policy", "nonexistent.json"]):
        with pytest.raises(SystemExit) as exc_info:
            lint()
        assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_lint_command_invalid_json(tmp_path, capsys):
    """Test the lint command with invalid JSON."""
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{invalid json}")
    
    with patch("sys.argv", ["lint", "--policy", str(invalid_json)]):
        with pytest.raises(SystemExit) as exc_info:
            lint()
        assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.out 