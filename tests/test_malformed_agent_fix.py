"""Test that malformed agent files are properly rejected with clear errors."""

import json
import tempfile
from pathlib import Path
import pytest

# Import the validation functions
from vault.cli.simulate import load_agent_context as simulate_load


class TestMalformedAgentValidation:
    """Test validation of malformed agent files."""
    
    def test_valid_agents(self):
        """Valid agents should load successfully."""
        valid_cases = [
            {"role": "user", "trustScore": 80},
            {"role": "admin", "trustScore": 0},
            {"role": "analyst", "trustScore": 100},
            {"role": "viewer", "trustScore": 50.5},
        ]
        
        for agent in valid_cases:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(agent, f)
                temp_path = Path(f.name)
            
            try:
                result = simulate_load(temp_path)
                assert result == agent
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
                with pytest.raises(ValueError, match="must contain a JSON object"):
                    simulate_load(temp_path)
            finally:
                temp_path.unlink()
    
    def test_missing_role(self):
        """Missing role should fail."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"trustScore": 80}, f)
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="must contain 'role' field"):
                simulate_load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_invalid_role_type(self):
        """Non-string role should fail."""
        invalid_roles = [
            123,
            None,
            True,
            ["admin"],
            {"type": "admin"},
        ]
        
        for role in invalid_roles:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": role, "trustScore": 80}, f)
                temp_path = Path(f.name)
            
            try:
                with pytest.raises(ValueError, match="role.*must be a string"):
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
                with pytest.raises(ValueError, match="role.*cannot be empty"):
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
        """Non-numeric trustScore should fail."""
        invalid_scores = [
            "high",
            "80",  # String number should work after conversion
            True,
            [80],
            {"value": 80},
        ]
        
        for score in invalid_scores:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({"role": "user", "trustScore": score}, f)
                temp_path = Path(f.name)
            
            try:
                if score == "80":  # This should work
                    result = simulate_load(temp_path)
                    assert result["trustScore"] == "80"
                elif score is True:  # Boolean gets special error message
                    with pytest.raises(ValueError, match="trustScore cannot be a boolean"):
                        simulate_load(temp_path)
                else:
                    with pytest.raises(ValueError, match="trustScore must be numeric"):
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