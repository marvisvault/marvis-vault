import pytest
from pathlib import Path
import json
import yaml
from vault.engine.policy_parser import parse_policy, Policy, PolicyCondition

@pytest.fixture
def valid_json_policy(tmp_path):
    policy = {
        "mask": "****",
        "unmask_roles": ["admin", "manager"],
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 80
            }
        ]
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def valid_yaml_policy(tmp_path):
    policy = {
        "mask": "****",
        "unmask_roles": ["admin", "manager"],
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 80
            }
        ]
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(policy))
    return path

def test_parse_valid_json_policy(valid_json_policy):
    """Test parsing a valid JSON policy file."""
    policy = parse_policy(valid_json_policy)
    assert isinstance(policy, Policy)
    assert policy.mask == "****"
    assert policy.unmask_roles == ["admin", "manager"]
    assert len(policy.conditions) == 1
    assert policy.conditions[0].field == "trust_score"
    assert policy.conditions[0].operator == ">="
    assert policy.conditions[0].value == 80

def test_parse_valid_yaml_policy(valid_yaml_policy):
    """Test parsing a valid YAML policy file."""
    policy = parse_policy(valid_yaml_policy)
    assert isinstance(policy, Policy)
    assert policy.mask == "****"
    assert policy.unmask_roles == ["admin", "manager"]
    assert len(policy.conditions) == 1
    assert policy.conditions[0].field == "trust_score"
    assert policy.conditions[0].operator == ">="
    assert policy.conditions[0].value == 80

def test_missing_required_fields(tmp_path):
    """Test handling of missing required fields."""
    policy = {
        "mask": "****",
        # missing unmask_roles and conditions
    }
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(policy))
    
    with pytest.raises(ValueError) as exc_info:
        parse_policy(path)
    assert "unmask_roles" in str(exc_info.value)

def test_invalid_json(tmp_path):
    """Test handling of invalid JSON."""
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json}")
    
    with pytest.raises(ValueError) as exc_info:
        parse_policy(path)
    assert "Invalid JSON" in str(exc_info.value)

def test_invalid_yaml(tmp_path):
    """Test handling of invalid YAML."""
    path = tmp_path / "invalid.yaml"
    path.write_text("invalid: yaml: :")
    
    with pytest.raises(ValueError) as exc_info:
        parse_policy(path)
    assert "Invalid YAML" in str(exc_info.value)

def test_nonexistent_file():
    """Test handling of nonexistent file."""
    with pytest.raises(FileNotFoundError):
        parse_policy("nonexistent.json")

def test_unsupported_format(tmp_path):
    """Test handling of unsupported file format."""
    path = tmp_path / "policy.txt"
    path.write_text("some text")
    
    with pytest.raises(ValueError) as exc_info:
        parse_policy(path)
    assert "Unsupported file format" in str(exc_info.value) 