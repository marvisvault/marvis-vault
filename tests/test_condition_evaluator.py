import pytest
from vault.engine.condition_evaluator import (
    evaluate_condition, 
    ConditionValidationError,
    CircularReferenceError
)

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

def test_invalid_numeric_string_fails():
    """Test that string values cannot be coerced to numbers."""
    context = {"trustScore": "85"}  # String instead of number
    
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition("trustScore > 80", context)
    assert "must be numeric" in str(exc_info.value)

def test_trustscore_bounds_check():
    """Test that trustScore must be between 0 and 100."""
    # Test below bounds
    context = {"trustScore": -1}
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition("trustScore > 0", context)
    assert "must be between 0 and 100" in str(exc_info.value)
    
    # Test above bounds
    context = {"trustScore": 101}
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition("trustScore > 0", context)
    assert "must be between 0 and 100" in str(exc_info.value)
    
    # Test valid bounds
    context = {"trustScore": 0}
    result, _ = evaluate_condition("trustScore >= 0", context)
    assert result is True
    
    context = {"trustScore": 100}
    result, _ = evaluate_condition("trustScore <= 100", context)
    assert result is True

def test_malformed_token_sequence_raises():
    """Test that malformed token sequences are rejected."""
    context = {"trustScore": 85}
    
    # Test invalid operator sequences
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition("trustScore >> 80", context)
    assert "Invalid operator sequence" in str(exc_info.value)
    
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition("trustScore << 80", context)
    assert "Invalid operator sequence" in str(exc_info.value)
    
    # Test token limit
    long_condition = " && ".join(["trustScore > 80"] * 51)  # 101 tokens
    with pytest.raises(ConditionValidationError) as exc_info:
        evaluate_condition(long_condition, context)
    assert "exceeds maximum token limit" in str(exc_info.value)

def test_direct_circular_reference_fails():
    """Test that direct self-references are detected."""
    context = {
        "score": "score"  # score references itself
    }
    
    with pytest.raises(CircularReferenceError) as exc_info:
        evaluate_condition("score > 0", context)
    assert "Circular reference detected" in str(exc_info.value)
    assert "score -> score" in str(exc_info.value)

def test_indirect_circular_reference_chain_fails():
    """Test that indirect circular references are detected."""
    context = {
        "score": "trustScore",
        "trustScore": "score"  # score -> trustScore -> score
    }
    
    with pytest.raises(CircularReferenceError) as exc_info:
        evaluate_condition("score > 0", context)
    assert "Circular reference detected" in str(exc_info.value)
    assert "score -> trustScore -> score" in str(exc_info.value)

def test_max_recursion_depth_enforced():
    """Test that maximum recursion depth is enforced."""
    # Create a long but valid chain
    context = {}
    for i in range(19):  # Just under the limit
        context[f"field{i}"] = f"field{i+1}"
    context["field19"] = 100  # Terminal value
    
    # This should pass
    result, _ = evaluate_condition("field0 > 0", context)
    assert result is True
    
    # Create an infinite chain
    context = {
        "field0": "field1",
        "field1": "field2",
        "field2": "field0"  # Creates a cycle
    }
    
    with pytest.raises(CircularReferenceError) as exc_info:
        evaluate_condition("field0 > 0", context)
    assert "Circular reference detected" in str(exc_info.value)
    assert "field0 -> field1 -> field2 -> field0" in str(exc_info.value) 