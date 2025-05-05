import pytest
from vault.sdk.redact import redact, validate_policy, create_field_patterns, RedactionError

@pytest.fixture
def valid_policy():
    """Create a valid policy dictionary."""
    return {
        "mask": ["email", "phone", "ssn"],
        "unmaskRoles": ["admin"],
        "conditions": ["trustScore > 80 && role != 'auditor'"]
    }

@pytest.fixture
def invalid_policy():
    """Create an invalid policy dictionary."""
    return {
        "mask": ["email"],
        "unmaskRoles": [],  # Empty list
        "conditions": ["trustScore > 80"]
    }

@pytest.fixture
def sample_text():
    """Create sample text with various fields."""
    return """
    User Information:
    Name: John Doe
    Email: john.doe@example.com
    Phone: +1-555-123-4567
    SSN: 123-45-6789
    Address: 123 Main St
    """

def test_validate_policy_valid(valid_policy):
    """Test validation of valid policy."""
    assert validate_policy(valid_policy)

def test_validate_policy_invalid(invalid_policy):
    """Test validation of invalid policy."""
    assert not validate_policy(invalid_policy)

def test_validate_policy_missing_fields():
    """Test validation of policy with missing fields."""
    policy = {"mask": ["email"]}
    assert not validate_policy(policy)

def test_validate_policy_wrong_types():
    """Test validation of policy with wrong field types."""
    policy = {
        "mask": "email",  # Should be list
        "unmaskRoles": ["admin"],
        "conditions": ["trustScore > 80"]
    }
    assert not validate_policy(policy)

def test_create_field_patterns(valid_policy):
    """Test creation of field patterns."""
    patterns = create_field_patterns(valid_policy["mask"])
    assert len(patterns) == 3
    assert all(isinstance(pattern, type(re.compile(""))) for pattern in patterns.values())

def test_redact_fields(valid_policy, sample_text):
    """Test redaction of fields listed in mask."""
    redacted = redact(sample_text, valid_policy)
    
    # Check that masked fields are redacted
    assert "[REDACTED]" in redacted
    assert "Email: [REDACTED]" in redacted
    assert "Phone: [REDACTED]" in redacted
    assert "SSN: [REDACTED]" in redacted
    
    # Check that unmasked fields are preserved
    assert "Name: John Doe" in redacted
    assert "Address: 123 Main St" in redacted

def test_redact_preserves_formatting(valid_policy, sample_text):
    """Test that redaction preserves formatting."""
    redacted = redact(sample_text, valid_policy)
    
    # Check that line breaks and indentation are preserved
    assert redacted.startswith("\n    User Information:")
    assert "\n    " in redacted
    assert redacted.endswith("\n    ")

def test_redact_case_insensitive(valid_policy):
    """Test case-insensitive field matching."""
    text = "EMAIL: test@example.com\nemail: test2@example.com"
    redacted = redact(text, valid_policy)
    assert "EMAIL: [REDACTED]" in redacted
    assert "email: [REDACTED]" in redacted

def test_redact_with_context(valid_policy, sample_text):
    """Test redaction with context evaluation."""
    # Context that passes conditions
    context = {"trustScore": 90, "role": "admin"}
    redacted = redact(sample_text, valid_policy, context)
    assert "[REDACTED]" in redacted
    
    # Context that fails conditions
    context = {"trustScore": 70, "role": "user"}
    not_redacted = redact(sample_text, valid_policy, context)
    assert not_redacted == sample_text

def test_redact_empty_input(valid_policy):
    """Test redaction with empty input."""
    assert redact("", valid_policy) == ""
    assert redact("   ", valid_policy) == "   "

def test_redact_malformed_policy(sample_text):
    """Test redaction with malformed policy."""
    # Missing required fields
    policy = {"mask": ["email"]}
    assert redact(sample_text, policy) == sample_text
    
    # Empty lists
    policy = {"mask": [], "unmaskRoles": ["admin"], "conditions": ["trustScore > 80"]}
    assert redact(sample_text, policy) == sample_text
    
    # Wrong types
    policy = {"mask": "email", "unmaskRoles": ["admin"], "conditions": ["trustScore > 80"]}
    assert redact(sample_text, policy) == sample_text

def test_redact_no_matches(valid_policy):
    """Test redaction when no fields match."""
    text = "No sensitive fields here"
    assert redact(text, valid_policy) == text

def test_multiline_field_redaction():
    """Test redaction of fields with multiline values."""
    text = """{
        "password": "my\\nsecret\\npassword",
        "apiKey": "key123"
    }"""
    
    policy = {
        "mask": ["password", "apiKey"],
        "unmaskRoles": ["admin"],
        "conditions": ["isAdmin"]
    }
    
    redacted = redact(text, policy)
    assert "password: [REDACTED]" in redacted
    assert "apiKey: [REDACTED]" in redacted
    assert "my\\nsecret\\npassword" not in redacted

def test_missing_field_error():
    """Test that RedactionError is raised when a required field is missing."""
    text = """{
        "username": "testuser",
        "email": "test@example.com"
    }"""
    
    policy = {
        "mask": ["password", "username"],  # password field doesn't exist
        "unmaskRoles": ["admin"],
        "conditions": ["isAdmin"]
    }
    
    with pytest.raises(RedactionError) as exc_info:
        redact(text, policy)
    
    assert exc_info.value.field == "password"
    assert "Field not found in input text" in str(exc_info.value) 