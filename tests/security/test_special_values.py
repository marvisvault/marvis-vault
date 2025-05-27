"""
Test protection against special numeric values.

This module tests that special values that could bypass security checks
are properly handled:
- Infinity (positive and negative)
- NaN (Not a Number)
- Boolean values
- Extreme numeric values
"""

import pytest
import math
import json
from vault.utils.security import (
    validate_trust_score,
    validate_agent_context,
    SecurityValidationError,
)


class TestInfinityProtection:
    """Test that Infinity values are rejected."""
    
    def test_positive_infinity_rejected(self):
        """Positive infinity should be rejected."""
        with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
            validate_trust_score(float('inf'))
    
    def test_negative_infinity_rejected(self):
        """Negative infinity should be rejected."""
        with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
            validate_trust_score(float('-inf'))
    
    def test_string_infinity_rejected(self):
        """String representations of infinity should be rejected."""
        infinity_strings = [
            "Infinity",
            "infinity", 
            "INFINITY",
            "inf",
            "Inf",
            "INF",
            "-Infinity",
            "-infinity",
            "-inf",
        ]
        
        for inf_str in infinity_strings:
            with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
                validate_trust_score(inf_str)
    
    def test_infinity_in_context_rejected(self):
        """Infinity in agent context should be rejected."""
        # Direct float infinity
        with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
            validate_agent_context({
                "role": "user",
                "trustScore": float('inf')
            })
        
        # String infinity
        with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
            validate_agent_context({
                "role": "user",
                "trustScore": "infinity"
            })


class TestNaNProtection:
    """Test that NaN values are rejected."""
    
    def test_nan_rejected(self):
        """NaN should be rejected."""
        with pytest.raises(SecurityValidationError, match="cannot be NaN"):
            validate_trust_score(float('nan'))
    
    def test_string_nan_rejected(self):
        """String representations of NaN should be rejected."""
        nan_strings = [
            "NaN",
            "nan",
            "NAN",
            "nAn",
        ]
        
        for nan_str in nan_strings:
            with pytest.raises(SecurityValidationError, match="cannot be NaN"):
                validate_trust_score(nan_str)
    
    def test_nan_from_operations(self):
        """NaN resulting from operations should be caught."""
        # Create NaN through operation
        nan_value = float('inf') / float('inf')
        assert math.isnan(nan_value)
        
        with pytest.raises(SecurityValidationError, match="cannot be NaN"):
            validate_trust_score(nan_value)
    
    def test_nan_comparison_vulnerability(self):
        """Test that NaN comparison vulnerability is prevented."""
        # NaN has special comparison properties:
        # - NaN != NaN
        # - NaN > X is always False
        # - NaN < X is always False
        # This could be exploited to bypass checks
        
        # Ensure NaN is rejected before any comparisons
        with pytest.raises(SecurityValidationError, match="cannot be NaN"):
            validate_trust_score(float('nan'))


class TestBooleanProtection:
    """Test that boolean values are properly handled."""
    
    def test_boolean_true_rejected(self):
        """Boolean True should be rejected as trustScore."""
        with pytest.raises(SecurityValidationError, match="cannot be a boolean"):
            validate_trust_score(True)
    
    def test_boolean_false_rejected(self):
        """Boolean False should be rejected as trustScore."""
        with pytest.raises(SecurityValidationError, match="cannot be a boolean"):
            validate_trust_score(False)
    
    def test_boolean_numeric_equivalence_prevented(self):
        """Prevent boolean-to-numeric conversion exploits."""
        # In Python: True == 1, False == 0
        # This could bypass security if not handled
        
        # Both should be rejected
        with pytest.raises(SecurityValidationError, match="cannot be a boolean"):
            validate_trust_score(True)
        
        with pytest.raises(SecurityValidationError, match="cannot be a boolean"):
            validate_trust_score(False)
    
    def test_boolean_in_context(self):
        """Boolean trustScore in context should be rejected."""
        with pytest.raises(SecurityValidationError, match="cannot be a boolean"):
            validate_agent_context({
                "role": "user",
                "trustScore": True
            })


class TestExtremeValues:
    """Test handling of extreme but valid numeric values."""
    
    def test_very_small_positive_values(self):
        """Very small positive values should work."""
        small_values = [
            0.0000001,
            1e-10,
            0.00000000001,
        ]
        
        for value in small_values:
            result = validate_trust_score(value)
            assert result == value
            assert isinstance(result, float)
    
    def test_boundary_values(self):
        """Boundary values should be handled correctly."""
        # Valid boundaries
        assert validate_trust_score(0) == 0.0
        assert validate_trust_score(0.0) == 0.0
        assert validate_trust_score(100) == 100.0
        assert validate_trust_score(100.0) == 100.0
        
        # Just outside boundaries
        with pytest.raises(SecurityValidationError, match="between 0-100"):
            validate_trust_score(-0.00001)
        
        with pytest.raises(SecurityValidationError, match="between 0-100"):
            validate_trust_score(100.00001)
    
    def test_negative_values_rejected(self):
        """Negative trustScores should be rejected."""
        negative_values = [
            -1,
            -0.1,
            -50,
            -100,
            -1000,
        ]
        
        for value in negative_values:
            with pytest.raises(SecurityValidationError, match="between 0-100"):
                validate_trust_score(value)
    
    def test_large_values_rejected(self):
        """trustScores over 100 should be rejected."""
        large_values = [
            101,
            100.1,
            150,
            1000,
            999999,
        ]
        
        for value in large_values:
            with pytest.raises(SecurityValidationError, match="between 0-100"):
                validate_trust_score(value)


class TestNumericEdgeCases:
    """Test other numeric edge cases."""
    
    def test_scientific_notation(self):
        """Scientific notation should be handled correctly."""
        valid_scientific = [
            ("1e1", 10.0),
            ("5e1", 50.0),
            ("1e2", 100.0),
            ("5.5e1", 55.0),
        ]
        
        for sci_str, expected in valid_scientific:
            result = validate_trust_score(sci_str)
            assert result == expected
        
        # Out of range scientific notation
        with pytest.raises(SecurityValidationError, match="between 0-100"):
            validate_trust_score("1e3")  # 1000
    
    def test_hex_and_octal_strings(self):
        """Hex and octal strings should not be interpreted."""
        # These should be rejected as non-numeric
        invalid_formats = [
            "0x50",   # Hex 80
            "0o120",  # Octal 80
            "0b1010", # Binary 10
        ]
        
        for fmt in invalid_formats:
            with pytest.raises(SecurityValidationError, match="must be numeric"):
                validate_trust_score(fmt)
    
    def test_special_float_values(self):
        """Test handling of special float scenarios."""
        # Very precise floats
        result = validate_trust_score(50.123456789)
        assert abs(result - 50.123456789) < 0.0000001
        
        # Repeating decimals
        result = validate_trust_score(33.333333333333)
        assert abs(result - 33.333333333333) < 0.0000001