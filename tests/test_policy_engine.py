import pytest
from pathlib import Path
import json
import yaml
from vault.engine.policy_engine import evaluate, EvaluationResult

@pytest.fixture
def valid_policy(tmp_path):
    """Create a valid policy file for testing."""
    policy = {
        "mask": "****",
        "unmask_roles": ["admin", "manager"],
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
def minimal_policy(tmp_path):
    """Create a minimal policy file for testing."""
    policy = {
        "mask": "****",
        "unmask_roles": ["admin"],
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 50
            }
        ]
    }
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(policy))
    return path

def test_evaluate_all_conditions_met(valid_policy):
    """Test evaluation when all conditions are met."""
    context = {
        "trust_score": 85,
        "role": "admin",
        "department": "IT"
    }
    
    result = evaluate(context, valid_policy)
    assert isinstance(result, EvaluationResult)
    assert result.status is True
    assert "All conditions passed" in result.reason
    assert "trust_score >= 80" in result.reason
    assert "role == 'admin'" in result.reason
    assert result.fields_to_mask == []
    assert result.policy is not None

def test_evaluate_some_conditions_failed(valid_policy):
    """Test evaluation when some conditions fail."""
    context = {
        "trust_score": 75,  # Below threshold
        "role": "admin",
        "department": "IT"
    }
    
    result = evaluate(context, valid_policy)
    assert isinstance(result, EvaluationResult)
    assert result.status is False
    assert "Some conditions failed" in result.reason
    assert "trust_score >= 80" in result.reason
    assert "role == 'admin'" in result.reason
    assert set(result.fields_to_mask) == {"trust_score", "role", "department"}
    assert result.policy is not None

def test_evaluate_minimal_policy(minimal_policy):
    """Test evaluation with a minimal policy."""
    context = {
        "trust_score": 60,
        "role": "user"
    }
    
    result = evaluate(context, minimal_policy)
    assert isinstance(result, EvaluationResult)
    assert result.status is True
    assert "All conditions passed" in result.reason
    assert "trust_score >= 50" in result.reason
    assert result.fields_to_mask == []
    assert result.policy is not None

def test_evaluate_missing_context_key(valid_policy):
    """Test evaluation with missing context keys."""
    context = {
        "trust_score": 85
        # Missing 'role' key
    }
    
    result = evaluate(context, valid_policy)
    assert isinstance(result, EvaluationResult)
    assert result.status is False
    assert "Context key 'role' not found" in result.reason
    assert set(result.fields_to_mask) == {"trust_score"}
    assert result.policy is not None

def test_evaluate_invalid_policy(tmp_path):
    """Test evaluation with an invalid policy file."""
    # Create an invalid policy file
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json}")
    
    context = {
        "trust_score": 85,
        "role": "admin"
    }
    
    result = evaluate(context, path)
    assert isinstance(result, EvaluationResult)
    assert result.status is False
    assert "Policy evaluation failed" in result.reason
    assert set(result.fields_to_mask) == {"trust_score", "role"}
    assert result.policy is None

def test_evaluate_nonexistent_policy():
    """Test evaluation with a nonexistent policy file."""
    context = {
        "trust_score": 85,
        "role": "admin"
    }
    
    result = evaluate(context, "nonexistent.json")
    assert isinstance(result, EvaluationResult)
    assert result.status is False
    assert "Policy evaluation failed" in result.reason
    assert set(result.fields_to_mask) == {"trust_score", "role"}
    assert result.policy is None

def test_evaluate_complex_conditions(valid_policy):
    """Test evaluation with complex conditions."""
    context = {
        "trust_score": 90,
        "role": "admin",
        "department": "IT",
        "location": "US",
        "has_access": True
    }
    
    result = evaluate(context, valid_policy)
    assert isinstance(result, EvaluationResult)
    assert result.status is True
    assert "All conditions passed" in result.reason
    assert "trust_score >= 80" in result.reason
    assert "role == 'admin'" in result.reason
    assert result.fields_to_mask == []
    assert result.policy is not None 