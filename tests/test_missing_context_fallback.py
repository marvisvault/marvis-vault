"""Test fallback behavior for missing context values like trustScore"""

import pytest
from vault.engine.condition_evaluator import evaluate_condition


class TestMissingContextFallback:
    """Test that missing context values default to false instead of throwing errors"""
    
    def test_missing_trustscore_simple(self):
        """Test simple condition with missing trustScore"""
        context = {"role": "admin"}
        condition = "trustScore > 80"
        
        # Should not raise an error, should return False
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is False
        assert "missing" in explanation.lower()
        # Note: fields_affected only includes fields that exist in context
        assert fields == []
    
    def test_missing_trustscore_with_and(self):
        """Test AND condition with missing trustScore"""
        context = {"role": "analyst"}
        condition = "role == 'analyst' && trustScore > 70"
        
        # Even though role matches, missing trustScore should make it false
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is False
        assert "missing" in explanation
        # The exact format varies but should show both conditions
        assert "analyst" in explanation
        assert "trustScore" in explanation
    
    def test_missing_trustscore_with_or(self):
        """Test OR condition with missing trustScore"""
        context = {"role": "admin"}
        condition = "role == 'admin' || trustScore > 90"
        
        # Should raise ValueError even in OR condition when trustScore is missing
        with pytest.raises(ValueError, match="trustScore"):
            evaluate_condition(condition, context)
    
    def test_missing_field_in_comparison(self):
        """Test comparison with missing field on left side"""
        context = {"role": "user"}
        condition = "department == 'IT'"
        
        # Missing department should default to false
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is False
        assert "missing" in explanation.lower()
        # fields_affected only includes fields that exist in context
        assert fields == []
    
    def test_numeric_comparison_with_missing_value(self):
        """Test numeric comparison with missing value"""
        context = {"name": "John"}
        condition = "age > 18"
        
        # Missing age should default to false (safe for numeric comparisons)
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is False
        assert "missing" in explanation.lower()
    
    def test_multiple_missing_values(self):
        """Test condition with multiple missing values"""
        context = {"name": "Alice"}
        condition = "role == 'admin' && trustScore > 80"
        
        # Both role and trustScore are missing
        result, explanation, fields = evaluate_condition(condition, context)
        
        assert result is False
        # Both values are missing, so no fields from context are used
        assert fields == []
    
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
        assert set(fields) == {"role", "trustScore"}