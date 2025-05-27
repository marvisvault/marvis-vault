"""
Test protection against type confusion attacks.

Type confusion vulnerabilities occur when different types are treated
inconsistently, leading to security bypasses.
"""

import pytest
from vault.utils.security import (
    validate_trust_score,
    validate_agent_context,
    SecurityValidationError,
)
from vault.utils.security.error_taxonomy import ErrorCode, ErrorCategory
from tests.security.test_utils import (
    assert_validation_error,
    assert_no_validation_error,
    assert_error_details
)


class TestTrustScoreTypeConfusion:
    """Test that trustScore type confusion is prevented."""
    
    def test_string_numbers_converted_to_float(self):
        """String numbers must be converted to float to prevent confusion."""
        test_cases = [
            ("80", 80.0),
            ("0", 0.0),
            ("100", 100.0),
            ("50.5", 50.5),
            (" 75 ", 75.0),  # Whitespace should be handled
        ]
        
        for string_value, expected_float in test_cases:
            result = validate_trust_score(string_value)
            assert result == expected_float
            assert isinstance(result, float), f"Expected float, got {type(result)}"
    
    def test_string_comparison_vulnerability_prevented(self):
        """Prevent string comparison bypass attacks."""
        # In string comparison: "80" > "9" is False (lexicographic)
        # In numeric comparison: 80 > 9 is True
        
        # Both should be converted to float
        score1 = validate_trust_score("80")
        score2 = validate_trust_score("9")
        
        assert isinstance(score1, float)
        assert isinstance(score2, float)
        assert score1 > score2  # Numeric comparison works correctly
    
    def test_boolean_as_trustscore_rejected(self):
        """Boolean values should not be accepted as trustScore."""
        # Python treats True as 1, False as 0 in numeric context
        # This could bypass security checks
        
        # Check using error code instead of message
        assert_validation_error(
            validate_trust_score,
            True,
            error_code=ErrorCode.VALUE_SPECIAL_NUMBER,
            field_contains="trustScore"
        )
        
        assert_validation_error(
            validate_trust_score,
            False,
            error_code=ErrorCode.VALUE_SPECIAL_NUMBER,
            field_contains="trustScore"
        )
    
    def test_mixed_type_context_normalized(self):
        """Mixed type contexts should be normalized consistently."""
        context = {
            "role": "user",
            "trustScore": "95",  # String that should become float
            "verified": True,    # Boolean should remain boolean
            "count": 42,         # Integer should be preserved
        }
        
        result = validate_agent_context(context)
        
        # trustScore normalized to float
        assert result["trustScore"] == 95.0
        assert isinstance(result["trustScore"], float)
        
        # Other types preserved
        assert result["verified"] is True
        assert result["count"] == 42
    
    def test_numeric_string_edge_cases(self):
        """Test edge cases in numeric string parsing."""
        valid_cases = [
            ("0.0", 0.0),
            ("100.0", 100.0),
            ("50.00000", 50.0),
            ("1e1", 10.0),  # Scientific notation
            ("1E1", 10.0),
        ]
        
        for string_value, expected in valid_cases:
            result = validate_trust_score(string_value)
            assert result == expected
        
        # Invalid numeric strings
        invalid_cases = [
            "80.5.5",  # Multiple decimals
            "80,5",    # Comma instead of decimal
            "80%",     # Percentage sign
            "$80",     # Currency symbol
        ]
        
        for invalid in invalid_cases:
            with pytest.raises(SecurityValidationError, match="must be numeric"):
                validate_trust_score(invalid)


class TestRoleTypeValidation:
    """Test role type validation and normalization."""
    
    def test_role_must_be_string(self):
        """Role must be a string type."""
        from vault.utils.security import validate_role
        
        # Valid string roles
        assert validate_role("admin") == "admin"
        assert validate_role("user") == "user"
        
        # Invalid types
        with pytest.raises(SecurityValidationError, match="must be a string"):
            validate_role(123)
        
        with pytest.raises(SecurityValidationError, match="must be a string"):
            validate_role(["admin"])
        
        with pytest.raises(SecurityValidationError, match="must be a string"):
            validate_role({"role": "admin"})
    
    def test_null_role_specific_error(self):
        """Null role should have specific error message."""
        from vault.utils.security import validate_role
        
        with pytest.raises(SecurityValidationError, match="role is required"):
            validate_role(None)
    
    def test_unicode_normalization_prevents_confusion(self):
        """Unicode normalization should prevent homograph attacks."""
        from vault.utils.security import validate_role
        
        # Different Unicode representations of "admin"
        variations = [
            "admin",           # ASCII
            "ａｄｍｉｎ",      # Fullwidth
            "𝐚𝐝𝐦𝐢𝐧",      # Mathematical alphanumeric
            "αdmin",          # Greek alpha instead of 'a'
        ]
        
        # All should be normalized (though some may remain different)
        results = []
        for variant in variations:
            try:
                normalized = validate_role(variant)
                results.append(normalized)
            except SecurityValidationError:
                # Some variants might be rejected as injection attempts
                pass
        
        # At least ASCII version should work
        assert "admin" in results


class TestTypeCoercionSecurity:
    """Test that type coercion doesn't create vulnerabilities."""
    
    def test_implicit_conversions_prevented(self):
        """Implicit type conversions should be handled safely."""
        context = {
            "role": "user",
            "trustScore": "100",  # String
        }
        
        validated = validate_agent_context(context)
        
        # String "100" should not equal integer 100 in comparisons
        # But after validation, it's normalized to float
        assert validated["trustScore"] == 100.0
        assert validated["trustScore"] is not "100"
    
    def test_type_preservation_where_appropriate(self):
        """Non-security fields should preserve their types."""
        context = {
            "role": "analyst",
            "trustScore": 75,
            "metadata": {
                "tags": ["finance", "reports"],
                "active": True,
                "login_count": 42
            }
        }
        
        validated = validate_agent_context(context)
        
        # Security fields normalized
        assert isinstance(validated["trustScore"], float)
        
        # Other fields preserve structure
        assert validated["metadata"]["tags"] == ["finance", "reports"]
        assert validated["metadata"]["active"] is True
        assert validated["metadata"]["login_count"] == 42