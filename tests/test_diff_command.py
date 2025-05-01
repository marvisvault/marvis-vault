import pytest
from pathlib import Path
import json
from unittest.mock import patch
from vault.cli.diff import (
    load_evaluation_result,
    compare_roles,
    compare_fields,
    compare_conditions,
    diff
)

@pytest.fixture
def before_result(tmp_path):
    """Create a before evaluation result file."""
    result = {
        "roles": ["admin", "user"],
        "fields_to_mask": ["ssn", "email"],
        "conditions": [
            {"field": "trust_score", "result": "pass"},
            {"field": "role", "result": "pass"}
        ]
    }
    path = tmp_path / "before.json"
    path.write_text(json.dumps(result))
    return path

@pytest.fixture
def after_result(tmp_path):
    """Create an after evaluation result file."""
    result = {
        "roles": ["admin", "auditor"],
        "fields_to_mask": ["ssn", "phone"],
        "conditions": [
            {"field": "trust_score", "result": "fail"},
            {"field": "role", "result": "pass"},
            {"field": "department", "result": "pass"}
        ]
    }
    path = tmp_path / "after.json"
    path.write_text(json.dumps(result))
    return path

@pytest.fixture
def empty_result(tmp_path):
    """Create an empty evaluation result file."""
    result = {
        "roles": [],
        "fields_to_mask": [],
        "conditions": []
    }
    path = tmp_path / "empty.json"
    path.write_text(json.dumps(result))
    return path

@pytest.fixture
def invalid_json(tmp_path):
    """Create an invalid JSON file."""
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json}")
    return path

def test_load_evaluation_result_valid(before_result):
    """Test loading a valid evaluation result."""
    result = load_evaluation_result(before_result)
    assert result["roles"] == ["admin", "user"]
    assert result["fields_to_mask"] == ["ssn", "email"]
    assert len(result["conditions"]) == 2

def test_load_evaluation_result_invalid(invalid_json):
    """Test loading an invalid evaluation result."""
    with pytest.raises(Exception):
        load_evaluation_result(invalid_json)

def test_compare_roles(before_result, after_result):
    """Test comparing roles between results."""
    before = load_evaluation_result(before_result)
    after = load_evaluation_result(after_result)
    
    added, removed = compare_roles(before, after)
    assert added == {"auditor"}
    assert removed == {"user"}

def test_compare_fields(before_result, after_result):
    """Test comparing masked fields between results."""
    before = load_evaluation_result(before_result)
    after = load_evaluation_result(after_result)
    
    added, removed = compare_fields(before, after)
    assert added == {"phone"}
    assert removed == {"email"}

def test_compare_conditions(before_result, after_result):
    """Test comparing condition evaluations between results."""
    before = load_evaluation_result(before_result)
    after = load_evaluation_result(after_result)
    
    changes = compare_conditions(before, after)
    assert len(changes) == 2
    assert any(c[0] == "trust_score" and "pass → fail" in c[1] for c in changes)
    assert any(c[0] == "department" and c[1] == "added" for c in changes)

def test_diff_command_role_change(before_result, after_result, capsys):
    """Test the diff command with role changes."""
    with patch("sys.argv", ["diff", "--before", str(before_result), "--after", str(after_result)]):
        diff()
    captured = capsys.readouterr()
    assert "Role Changes" in captured.out
    assert "+ auditor" in captured.out
    assert "- user" in captured.out

def test_diff_command_field_change(before_result, after_result, capsys):
    """Test the diff command with field changes."""
    with patch("sys.argv", ["diff", "--before", str(before_result), "--after", str(after_result)]):
        diff()
    captured = capsys.readouterr()
    assert "Field Changes" in captured.out
    assert "+ phone" in captured.out
    assert "- email" in captured.out

def test_diff_command_condition_change(before_result, after_result, capsys):
    """Test the diff command with condition changes."""
    with patch("sys.argv", ["diff", "--before", str(before_result), "--after", str(after_result)]):
        diff()
    captured = capsys.readouterr()
    assert "Condition Changes" in captured.out
    assert "trust_score" in captured.out
    assert "pass → fail" in captured.out
    assert "department" in captured.out

def test_diff_command_empty_diff(before_result, before_result_copy, capsys):
    """Test the diff command with identical files."""
    with patch("sys.argv", ["diff", "--before", str(before_result), "--after", str(before_result)]):
        diff()
    captured = capsys.readouterr()
    assert "No changes found" in captured.out

def test_diff_command_missing_file(capsys):
    """Test the diff command with missing files."""
    with patch("sys.argv", ["diff", "--before", "nonexistent.json", "--after", "nonexistent.json"]):
        with pytest.raises(SystemExit):
            diff()
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_diff_command_invalid_json(invalid_json, before_result, capsys):
    """Test the diff command with invalid JSON."""
    with patch("sys.argv", ["diff", "--before", str(invalid_json), "--after", str(before_result)]):
        with pytest.raises(SystemExit):
            diff()
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_diff_command_missing_keys(tmp_path, capsys):
    """Test the diff command with missing keys in JSON."""
    # Create a result file missing required keys
    result = {"roles": ["admin"]}  # Missing fields_to_mask and conditions
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps(result))
    
    with patch("sys.argv", ["diff", "--before", str(path), "--after", str(path)]):
        diff()  # Should handle missing keys gracefully
    captured = capsys.readouterr()
    assert "No changes found" in captured.out 