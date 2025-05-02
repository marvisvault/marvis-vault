import pytest
import json
from pathlib import Path
from typing import Dict, Any, List

def load_template(template_name: str) -> Dict[str, Any]:
    """Load a policy template from the templates directory."""
    template_path = Path("vault/templates") / f"{template_name}.json"
    with template_path.open() as f:
        return json.load(f)

def validate_template_structure(template: Dict[str, Any]) -> None:
    """Validate the structure of a policy template."""
    # Check required fields
    required_fields = {"mask", "unmaskRoles", "conditions"}
    missing_fields = required_fields - set(template.keys())
    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")
    
    # Check field types
    if not isinstance(template["mask"], list):
        raise ValueError("mask must be a list")
    if not isinstance(template["unmaskRoles"], list):
        raise ValueError("unmaskRoles must be a list")
    if not isinstance(template["conditions"], list):
        raise ValueError("conditions must be a list")
    
    # Check for empty lists
    if not template["mask"]:
        raise ValueError("mask list cannot be empty")
    if not template["unmaskRoles"]:
        raise ValueError("unmaskRoles list cannot be empty")
    if not template["conditions"]:
        raise ValueError("conditions list cannot be empty")
    
    # Check string values
    for field in template["mask"]:
        if not isinstance(field, str):
            raise ValueError(f"mask field must be string: {field}")
    for role in template["unmaskRoles"]:
        if not isinstance(role, str):
            raise ValueError(f"unmaskRoles role must be string: {role}")
    for condition in template["conditions"]:
        if not isinstance(condition, str):
            raise ValueError(f"conditions condition must be string: {condition}")

@pytest.fixture
def template_names():
    """List of template names to test."""
    return ["gdpr-lite", "pii-basic", "healthcare", "finance-trust"]

def test_load_templates(template_names):
    """Test loading all template files."""
    for name in template_names:
        template = load_template(name)
        assert isinstance(template, dict)
        assert template  # Not empty

def test_validate_template_structure(template_names):
    """Test template structure validation."""
    for name in template_names:
        template = load_template(name)
        validate_template_structure(template)

def test_gdpr_lite_template():
    """Test GDPR-lite template specific fields."""
    template = load_template("gdpr-lite")
    assert "email" in template["mask"]
    assert "phone" in template["mask"]
    assert "admin" in template["unmaskRoles"]
    assert "data_protection_officer" in template["unmaskRoles"]
    assert any("trustScore > 80" in cond for cond in template["conditions"])

def test_pii_basic_template():
    """Test PII-basic template specific fields."""
    template = load_template("pii-basic")
    assert "name" in template["mask"]
    assert "dob" in template["mask"]
    assert "ssn" in template["mask"]
    assert "admin" in template["unmaskRoles"]
    assert "hr_manager" in template["unmaskRoles"]
    assert any("trustScore > 85" in cond for cond in template["conditions"])

def test_healthcare_template():
    """Test healthcare template specific fields."""
    template = load_template("healthcare")
    assert "medicalHistory" in template["mask"]
    assert "diagnosis" in template["mask"]
    assert "insuranceID" in template["mask"]
    assert "admin" in template["unmaskRoles"]
    assert "doctor" in template["unmaskRoles"]
    assert "nurse" in template["unmaskRoles"]
    assert any("trustScore > 90" in cond for cond in template["conditions"])

def test_finance_trust_template():
    """Test finance-trust template specific fields."""
    template = load_template("finance-trust")
    assert "bankAccount" in template["mask"]
    assert "transactionHistory" in template["mask"]
    assert "creditScore" in template["mask"]
    assert "admin" in template["unmaskRoles"]
    assert "financial_advisor" in template["unmaskRoles"]
    assert any("trustScore > 95" in cond for cond in template["conditions"])

def test_template_missing_file():
    """Test handling of missing template file."""
    with pytest.raises(FileNotFoundError):
        load_template("nonexistent")

def test_template_invalid_json(tmp_path):
    """Test handling of invalid JSON in template file."""
    template_path = tmp_path / "invalid.json"
    template_path.write_text("{invalid json}")
    with pytest.raises(json.JSONDecodeError):
        with template_path.open() as f:
            json.load(f) 