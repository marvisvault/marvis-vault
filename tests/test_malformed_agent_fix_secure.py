"""
Test that malformed agent files are properly rejected with clear errors.

This is the SECURE version that expects:
1. String trustScores to be converted to float
2. Specific error messages for different failure types
3. Injection patterns to be rejected
"""

import json
import tempfile
from pathlib import Path
import pytest

# Import the validation functions
from vault.cli.simulate import load_agent_context as simulate_load


class TestMalformedAgentValidation:
    """Test validation of malformed agent files."""
    
    def test_valid_agents(self):
        """Valid agents should load successfully with normalized values."""
        valid_cases = [
            ({"role": "user", "trustScore": 80}, {"role": "user", "trustScore": 80.0}),
            ({"role": "admin", "trustScore": 0}, {"role": "admin", "trustScore": 0.0}),
            ({"role": "analyst", "trustScore": 100}, {"role": "analyst", "trustScore": 100.0}),
            ({"role": "viewer", "trustScore": 50.5}, {"role": "viewer", "trustScore": 50.5}),
            # String trustScore should be converted to float
            ({"role": "user", "trustScore": "80"}, {"role": "user", "trustScore": 80.0}),
        ]
        
        for input_agent, expected_output in valid_cases:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(input_agent, f)
                temp_path = Path(f.name)
            
            try:
                result = simulate_load(temp_path)
                assert result == expected_output
                # Ensure trustScore is always float
                if "trustScore" in result:
                    assert isinstance(result["trustScore"], float)
            finally:
                temp_path.unlink()
    
    def test_empty_file(self):
        """Empty file should fail with clear error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("")
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="Agent file is empty"):
                simulate_load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_invalid_json(self):
        """Invalid JSON should fail with clear error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid json")
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                simulate_load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_not_json_object(self):
        """Non-object JSON should fail."""
        test_cases = [
            ('"just a string"', "string"),
            ('[1, 2, 3]', "array"),
            ('42', "number"),
            ('true', "boolean"),
        ]
        
        for content, desc in test_cases:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(content)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match="must be a JSON object|must contain a JSON object"):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_missing_role(self):
        """Missing role should fail with specific error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"trustScore": 80}, f)
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="must contain 'role' field"):
                simulate_load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_invalid_role_type(self):
        """Non-string role should fail with appropriate errors."""
        invalid_roles = [
            (123, "role must be a string"),
            (None, "role is required"),
            (True, "role must be a string"),
            (["admin"], "role must be a string"),
            ({"type": "admin"}, "role must be a string"),
        ]
        
        for role, expected_error in invalid_roles:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": role, "trustScore": 80}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match=expected_error):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_empty_role(self):
        """Empty role should fail."""
        empty_roles = ["", "   ", "\t", "\n"]
        
        for role in empty_roles:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": role, "trustScore": 80}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match="role cannot be empty"):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_missing_trustscore(self):
        """Missing trustScore should fail for simulate."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"role": "user"}, f)
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="must contain 'trustScore' field"):
                simulate_load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_invalid_trustscore_type(self):
        """Non-numeric trustScore should fail appropriately."""
        invalid_scores = [
            ("high", "trustScore must be numeric"),
            ("80", None),  # String number should work (converted to float)
            (True, "trustScore cannot be a boolean"),
            ([80], "trustScore must be numeric"),
            ({"value": 80}, "trustScore must be numeric"),
        ]
        
        for score, expected_error in invalid_scores:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": "user", "trustScore": score}, f)
                temp_path = Path(f.name)
            
            try:
                if expected_error is None:  # "80" should work
                    result = simulate_load(temp_path)
                    assert result["trustScore"] == 80.0  # Converted to float
                    assert isinstance(result["trustScore"], float)
                else:
                    with pytest.raises(ValueError, match=expected_error):
                        simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_trustscore_out_of_range(self):
        """trustScore outside 0-100 should fail."""
        invalid_scores = [-1, -10, 101, 150, 1000]
        
        for score in invalid_scores:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": "user", "trustScore": score}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match="trustScore must be between 0-100"):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_special_numeric_values(self):
        """Special values like Infinity and NaN should be rejected."""
        # Note: JSON doesn't support Infinity/NaN directly, but they can come from:
        # 1. String values that get parsed
        # 2. Direct Python object manipulation
        
        special_values = [
            ("Infinity", "trustScore cannot be Infinity"),
            ("inf", "trustScore cannot be Infinity"),
            ("-Infinity", "trustScore cannot be Infinity"),
            ("NaN", "trustScore cannot be NaN"),
            ("nan", "trustScore cannot be NaN"),
        ]
        
        for value, expected_error in special_values:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": "user", "trustScore": value}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match=expected_error):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_injection_attempts(self):
        """Injection attempts should be rejected."""
        injection_cases = [
            # SQL injection in role
            ("admin'; DROP TABLE users;--", "SQL injection"),
            ("admin' OR '1'='1", "SQL injection"),
            
            # XSS in role
            ("<script>alert('xss')</script>", "XSS|script|injection"),
            ("admin<img src=x onerror=alert(1)>", "XSS|tag|injection"),
            
            # Command injection
            ("admin; rm -rf /", "Shell metacharacter"),
            ("admin && cat /etc/passwd", "Shell metacharacter"),
        ]
        
        for role, expected_error in injection_cases:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": role, "trustScore": 80}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match=expected_error):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()