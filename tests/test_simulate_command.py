import pytest
from pathlib import Path
import json
from unittest.mock import patch
from vault.cli.simulate import simulate, load_agent_context, format_masking_explanation
from vault.engine.policy_engine import EvaluationResult

@pytest.fixture
def valid_policy(tmp_path):
    """Create a valid policy file for testing."""
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
def admin_agent(tmp_path):
    """Create an agent context file with admin role."""
    agent = {
        "trust_score": 85,
        "role": "admin",
        "department": "IT"
    }
    path = tmp_path / "admin.json"
    path.write_text(json.dumps(agent))
    return path

@pytest.fixture
def auditor_agent(tmp_path):
    """Create an agent context file with auditor role."""
    agent = {
        "trust_score": 72,
        "role": "auditor",
        "department": "Security"
    }
    path = tmp_path / "auditor.json"
    path.write_text(json.dumps(agent))
    return path

def test_load_agent_context(admin_agent):
    """Test loading agent context from JSON file."""
    context = load_agent_context(admin_agent)
    assert context["trust_score"] == 85
    assert context["role"] == "admin"
    assert context["department"] == "IT"

def test_load_agent_context_invalid_json(tmp_path):
    """Test loading agent context with invalid JSON."""
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{invalid json}")
    
    with pytest.raises(ValueError) as exc_info:
        load_agent_context(invalid_json)
    assert "Invalid JSON" in str(exc_info.value)

def test_format_masking_explanation_no_masking():
    """Test formatting explanation when no fields are masked."""
    result = EvaluationResult(
        status=True,
        reason="All conditions passed",
        fields_to_mask=[],
        policy=None
    )
    explanation = format_masking_explanation(result)
    assert "No fields would be masked" in explanation

def test_format_masking_explanation_with_masking():
    """Test formatting explanation when fields are masked."""
    result = EvaluationResult(
        status=False,
        reason="Condition failed: trust_score >= 80 is False",
        fields_to_mask=["trust_score", "role"],
        policy=None
    )
    explanation = format_masking_explanation(result)
    assert "trust_score" in explanation
    assert "MASKED" in explanation
    assert "trust_score >= 80" in explanation

def test_simulate_admin_agent(admin_agent, valid_policy, capsys):
    """Test simulation with admin agent (should not mask)."""
    with patch("sys.argv", ["simulate", "--agent", str(admin_agent), "--policy", str(valid_policy)]):
        simulate()
    
    captured = capsys.readouterr()
    assert "PASS" in captured.out
    assert "No fields would be masked" in captured.out
    assert "trust_score >= 80" in captured.out
    assert "role == 'admin'" in captured.out

def test_simulate_auditor_agent(auditor_agent, valid_policy, capsys):
    """Test simulation with auditor agent (should mask)."""
    with patch("sys.argv", ["simulate", "--agent", str(auditor_agent), "--policy", str(valid_policy)]):
        simulate()
    
    captured = capsys.readouterr()
    assert "FAIL" in captured.out
    assert "MASKED" in captured.out
    assert "trust_score >= 80" in captured.out
    assert "role == 'admin'" in captured.out

def test_simulate_missing_agent(tmp_path, valid_policy):
    """Test simulation with missing agent file."""
    with patch("sys.argv", ["simulate", "--agent", "nonexistent.json", "--policy", str(valid_policy)]):
        with pytest.raises(SystemExit):
            simulate()

def test_simulate_missing_policy(tmp_path, admin_agent):
    """Test simulation with missing policy file."""
    with patch("sys.argv", ["simulate", "--agent", str(admin_agent), "--policy", "nonexistent.json"]):
        with pytest.raises(SystemExit):
            simulate()

def test_simulate_invalid_agent_json(tmp_path, valid_policy):
    """Test simulation with invalid agent JSON."""
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{invalid json}")
    
    with patch("sys.argv", ["simulate", "--agent", str(invalid_json), "--policy", str(valid_policy)]):
        with pytest.raises(SystemExit):
            simulate()

def test_simulate_partial_masking(tmp_path, valid_policy):
    """Test simulation with partial masking scenario."""
    agent = {
        "trust_score": 85,  # Meets threshold
        "role": "user",     # Doesn't meet role requirement
        "department": "IT"
    }
    agent_path = tmp_path / "partial.json"
    agent_path.write_text(json.dumps(agent))
    
    with patch("sys.argv", ["simulate", "--agent", str(agent_path), "--policy", str(valid_policy)]):
        with patch("sys.stdout") as mock_stdout:
            simulate()
    
    # Verify that only role-related fields are masked
    captured = mock_stdout.getvalue()
    assert "trust_score" not in captured  # Should not be masked
    assert "role" in captured  # Should be masked 