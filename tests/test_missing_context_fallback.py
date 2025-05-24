"""Test fallback behavior for missing context values like trustScore"""

import pytest
from vault.engine.condition_evaluator import evaluate_condition


class TestMissingContextFallback:
    """Test that missing context values cause ValueError exceptions (caught by SDK layer)"""
    
    def test_missing_trustscore_simple(self):
        """Test simple condition with missing trustScore"""
        context = {"role": "admin"}
        condition = "trustScore > 80"
        
        # Should raise ValueError for missing context key
        with pytest.raises(ValueError, match="trustScore"):
            evaluate_condition(condition, context)
    
    def test_missing_trustscore_with_and(self):
        """Test AND condition with missing trustScore"""
        context = {"role": "analyst"}
        condition = "role == 'analyst' && trustScore > 70"
        
        # Should raise ValueError for missing trustScore in AND condition
        with pytest.raises(ValueError, match="trustScore"):
            evaluate_condition(condition, context)
    
    def test_missing_trustscore_with_or(self):
        """Test OR condition with missing trustScore"""
        context = {"role": "admin"}
        condition = "role == 'admin' || trustScore > 90"
        
        # Should still pass because first condition is true
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is True
        # Should show the OR evaluation
        assert "admin" in explanation
    
    def test_missing_field_in_comparison(self):
        """Test comparison with missing field on left side"""
        context = {"role": "user"}
        condition = "department == 'IT'"
        
        # Should raise ValueError for missing department
        with pytest.raises(ValueError, match="department"):
            evaluate_condition(condition, context)
    
    def test_numeric_comparison_with_missing_value(self):
        """Test numeric comparison with missing value"""
        context = {"name": "John"}
        condition = "age > 18"
        
        # Should raise ValueError for missing age
        with pytest.raises(ValueError, match="age"):
            evaluate_condition(condition, context)
    
    def test_multiple_missing_values(self):
        """Test condition with multiple missing values"""
        context = {"name": "Alice"}
        condition = "role == 'admin' && trustScore > 80"
        
        # Should raise ValueError for first missing value (role)
        with pytest.raises(ValueError, match="role"):
            evaluate_condition(condition, context)
    
    def test_existing_behavior_not_affected(self):
        """Test that existing behavior with all values present is not affected"""
        context = {"role": "admin", "trustScore": 85}
        condition = "role == 'admin' && trustScore > 80"
        
        # Should work as before
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is True
        # Should show both conditions evaluated
        assert "admin" in explanation
        assert "85" in explanation  # The trustScore value
        assert fields == ["role", "trustScore"]