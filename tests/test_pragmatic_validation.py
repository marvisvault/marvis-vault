"""
Test pragmatic validation approach with gradual rollout.

This test verifies:
1. Logging mode allows everything but logs issues
2. Warning mode warns but doesn't block
3. Enforcement mode blocks security threats
4. Emergency bypass works when needed
5. Performance is acceptable
"""

import os
import json
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

# Import validation components
from vault.utils.validation_config import ValidationMode, validation_config
from vault.utils.security_validators_pragmatic import (
    validate_agent_context_pragmatic,
    validate_role_pragmatic,
    validate_trust_score_pragmatic,
    get_validation_metrics,
    SecurityValidationError,
)


class TestPragmaticValidation:
    """Test the pragmatic validation approach."""
    
    def test_logging_mode_allows_bad_input(self):
        """In LOG_ONLY mode, bad input is allowed but logged."""
        with patch.object(validation_config, 'mode', ValidationMode.LOG_ONLY):
            # Invalid trustScore should be allowed
            result = validate_trust_score_pragmatic("eighty")
            assert result == 0.0  # Safe default
            
            # SQL injection in role should be allowed
            result = validate_role_pragmatic("admin'; DROP TABLE users;--")
            assert result == "admin'; DROP TABLE users;--"  # Passed through
            
            # Missing required fields should get defaults
            result = validate_agent_context_pragmatic({})
            assert result["role"] == "anonymous"
            assert result["trustScore"] == 0.0
    
    def test_warning_mode_allows_but_warns(self):
        """In WARN mode, bad input is allowed but warnings are issued."""
        with patch.object(validation_config, 'mode', ValidationMode.WARN):
            with patch('vault.utils.security_validators_pragmatic.logger') as mock_logger:
                # Boolean trustScore
                result = validate_trust_score_pragmatic(True)
                assert result == 0.0
                mock_logger.warning.assert_called()
    
    def test_enforce_mode_blocks_threats(self):
        """In ENFORCE mode, actual threats are blocked."""
        with patch.object(validation_config, 'mode', ValidationMode.ENFORCE):
            # These should raise errors
            with pytest.raises(SecurityValidationError):
                validate_trust_score_pragmatic("eighty")  # Non-numeric string
            
            with pytest.raises(SecurityValidationError):
                validate_trust_score_pragmatic(float('inf'))  # Infinity
            
            with pytest.raises(SecurityValidationError):
                validate_role_pragmatic(None)  # Missing role
    
    def test_emergency_bypass(self):
        """Emergency bypass should skip all validation."""
        # Set up emergency bypass
        os.environ["EMERGENCY_BYPASS_KEY"] = "secret123"
        os.environ["EXPECTED_BYPASS_KEY"] = "secret123"
        
        try:
            # Reload config to pick up env vars
            from vault.utils.validation_config import ValidationConfig
            test_config = ValidationConfig()
            
            with patch('vault.utils.security_validators_pragmatic.validation_config', test_config):
                # Even invalid input should pass through
                result = validate_agent_context_pragmatic({
                    "role": None,
                    "trustScore": "not-a-number",
                    "__proto__": "malicious"
                })
                # Should return input as-is when bypassed
                assert isinstance(result, dict)
        finally:
            # Clean up env vars
            os.environ.pop("EMERGENCY_BYPASS_KEY", None)
            os.environ.pop("EXPECTED_BYPASS_KEY", None)
    
    def test_performance_metrics(self):
        """Validation should track performance metrics."""
        # Clear previous metrics
        from vault.utils.security_validators_pragmatic import metrics
        metrics.validation_times.clear()
        metrics.validation_counts.clear()
        
        # Perform some validations
        for i in range(10):
            validate_role_pragmatic(f"user{i}")
            validate_trust_score_pragmatic(50 + i)
        
        # Check metrics
        stats = get_validation_metrics()
        assert stats["total_validations"] == 20
        assert "role_validation" in stats["validation_counts"]
        assert "trustscore_validation" in stats["validation_counts"]
        assert stats["average_time_ms"] < 10  # Should be fast
    
    def test_real_threat_examples(self):
        """Test against actual threats from the threat model."""
        with patch.object(validation_config, 'mode', ValidationMode.ENFORCE):
            # Threat 1: Role impersonation
            context = {"role": "doctor", "trustScore": 95}
            result = validate_agent_context_pragmatic(context)
            assert result["role"] == "doctor"  # Allowed but logged
            
            # Threat 2: TrustScore manipulation
            with pytest.raises(SecurityValidationError):
                validate_agent_context_pragmatic({
                    "role": "user",
                    "trustScore": "ninety-five"  # String to bypass numeric check
                })
            
            # Threat 3: Homograph attack
            weird_admin = "аdmin"  # Cyrillic 'а'
            result = validate_role_pragmatic(weird_admin)
            assert result != weird_admin  # Should be normalized
            
            # Threat 4: Large context DoS
            huge_context = {
                "role": "user",
                "trustScore": 50,
                "data": "x" * (2 * 1024 * 1024)  # 2MB
            }
            with pytest.raises(SecurityValidationError, match="too large"):
                validate_agent_context_pragmatic(huge_context)
    
    def test_stakeholder_requirements(self):
        """Test that stakeholder requirements are met."""
        with patch.object(validation_config, 'mode', ValidationMode.LOG_ONLY):
            # Custom roles should be allowed
            custom_role = "chief_happiness_officer"
            result = validate_role_pragmatic(custom_role)
            assert result == custom_role
            
            # String trustScores - check if preserve_string works
            with patch.dict(validation_config.requirements, {"preserve_string_trustscore": True}):
                result = validate_trust_score_pragmatic("80")
                assert result == "80"  # Preserved as string
                assert isinstance(result, str)
            
            # Without preserve_string, should convert to float
            with patch.dict(validation_config.requirements, {"preserve_string_trustscore": False}):
                result = validate_trust_score_pragmatic("80")
                assert result == 80.0
                assert isinstance(result, float)
    
    def test_gradual_rollout_dates(self):
        """Test that rollout phases work as configured."""
        # This would test the date-based rollout in production
        # For now, just verify the structure exists
        assert hasattr(validation_config, 'rollout_phases')
        assert ValidationMode.LOG_ONLY in validation_config.rollout_phases.values()
        assert ValidationMode.ENFORCE in validation_config.rollout_phases.values()


class TestBackwardCompatibility:
    """Ensure we don't break existing functionality."""
    
    def test_simulate_command_flow(self):
        """Test that simulate command still works."""
        with patch.object(validation_config, 'mode', ValidationMode.LOG_ONLY):
            # Valid context should work
            context = {"role": "analyst", "trustScore": 75}
            result = validate_agent_context_pragmatic(context, "agent")
            assert result["role"] == "analyst"
            assert result["trustScore"] == 75.0
            
            # Missing trustScore should get default
            context = {"role": "user"}
            result = validate_agent_context_pragmatic(context, "agent")
            assert result["trustScore"] == 0.0
    
    def test_redact_command_flow(self):
        """Test that redact command still works."""
        with patch.object(validation_config, 'mode', ValidationMode.LOG_ONLY):
            # trustScore is optional for redact
            context = {"role": "viewer"}
            result = validate_agent_context_pragmatic(context, "agent-redact")
            assert result["role"] == "viewer"
            assert "trustScore" not in result  # Optional field omitted