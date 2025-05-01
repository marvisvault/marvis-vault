import pytest
from vault.engine.condition_evaluator import evaluate_condition

def test_simple_comparison():
    """Test simple comparison operations."""
    context = {"trustScore": 85, "role": "admin"}
    
    # Greater than
    result, explanation = evaluate_condition("trustScore > 80", context)
    assert result is True
    assert "85 > 80 is True" in explanation
    
    # Less than
    result, explanation = evaluate_condition("trustScore < 90", context)
    assert result is True
    assert "85 < 90 is True" in explanation
    
    # Equals
    result, explanation = evaluate_condition("role == 'admin'", context)
    assert result is True
    assert "admin == admin is True" in explanation
    
    # Not equals
    result, explanation = evaluate_condition("role != 'user'", context)
    assert result is True
    assert "admin != user is True" in explanation

def test_and_chain():
    """Test AND operator chaining."""
    context = {"trustScore": 85, "role": "admin", "department": "IT"}
    
    result, explanation = evaluate_condition(
        "trustScore > 80 && role == 'admin' && department == 'IT'",
        context
    )
    assert result is True
    assert "AND" in explanation
    assert "85 > 80" in explanation
    assert "admin == admin" in explanation
    assert "IT == IT" in explanation

def test_or_chain():
    """Test OR operator chaining."""
    context = {"trustScore": 75, "role": "user", "department": "HR"}
    
    result, explanation = evaluate_condition(
        "trustScore > 80 || role == 'admin' || department == 'HR'",
        context
    )
    assert result is True
    assert "OR" in explanation
    assert "75 > 80" in explanation
    assert "user == admin" in explanation
    assert "HR == HR" in explanation

def test_mixed_and_or():
    """Test mixed AND/OR operations."""
    context = {"trustScore": 85, "role": "user", "department": "IT"}
    
    result, explanation = evaluate_condition(
        "trustScore > 80 && (role == 'admin' || department == 'IT')",
        context
    )
    assert result is True
    assert "AND" in explanation
    assert "OR" in explanation
    assert "85 > 80" in explanation
    assert "user == admin" in explanation
    assert "IT == IT" in explanation

def test_missing_context_key():
    """Test handling of missing context keys."""
    context = {"trustScore": 85}
    
    with pytest.raises(ValueError) as exc_info:
        evaluate_condition("role == 'admin'", context)
    assert "Context key 'role' not found" in str(exc_info.value)

def test_invalid_condition():
    """Test handling of invalid conditions."""
    context = {"trustScore": 85}
    
    with pytest.raises(ValueError) as exc_info:
        evaluate_condition("trustScore >", context)
    assert "Invalid expression structure" in str(exc_info.value)
    
    with pytest.raises(ValueError) as exc_info:
        evaluate_condition("trustScore > 80 &&", context)
    assert "Invalid expression structure" in str(exc_info.value)

def test_empty_condition():
    """Test handling of empty condition."""
    context = {"trustScore": 85}
    
    result, explanation = evaluate_condition("", context)
    assert result is True
    assert "Empty condition" in explanation

def test_complex_nested_conditions():
    """Test complex nested conditions."""
    context = {
        "trustScore": 85,
        "role": "admin",
        "department": "IT",
        "hasAccess": True,
        "location": "US"
    }
    
    condition = (
        "trustScore > 80 && "
        "(role == 'admin' || (department == 'IT' && hasAccess)) && "
        "location == 'US'"
    )
    
    result, explanation = evaluate_condition(condition, context)
    assert result is True
    assert "AND" in explanation
    assert "OR" in explanation
    assert "85 > 80" in explanation
    assert "admin == admin" in explanation
    assert "IT == IT" in explanation
    assert "US == US" in explanation 