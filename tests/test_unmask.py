import pytest
from vault.sdk.unmask import unmask, validate_policy, is_role_authorized, create_unmask_patterns

@pytest.fixture
def valid_policy():
    """Create a valid policy dictionary."""
    return {
        "mask": ["email", "phone", "ssn"],
        "unmaskRoles": ["admin", "hr_manager"],
        "conditions": ["trustScore > 80 && role != 'auditor'"]
    }

@pytest.fixture
def redacted_text():
    """Create sample redacted text."""
    return """
    User Information:
    Name: John Doe
    Email: [REDACTED]
    Phone: [REDACTED]
    SSN: [REDACTED]
    Address: 123 Main St
    """

@pytest.fixture
def original_values():
    """Create mapping of original field values."""
    return {
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4567",
        "ssn": "123-45-6789"
    }

def test_validate_policy_valid(valid_policy):
    """Test validation of valid policy."""
    assert validate_policy(valid_policy)

def test_validate_policy_invalid():
    """Test validation of invalid policy."""
    policy = {
        "mask": ["email"],
        "unmaskRoles": [],  # Empty list
        "conditions": ["trustScore > 80"]
    }
    assert not validate_policy(policy)

def test_is_role_authorized(valid_policy):
    """Test role authorization check."""
    assert is_role_authorized("admin", valid_policy)
    assert is_role_authorized("hr_manager", valid_policy)
    assert not is_role_authorized("user", valid_policy)

def test_create_unmask_patterns(valid_policy):
    """Test creation of unmask patterns."""
    patterns = create_unmask_patterns(valid_policy["mask"])
    assert len(patterns) == 3
    assert all(isinstance(pattern, type(re.compile(""))) for pattern in patterns.values())

def test_unmask_authorized_role(valid_policy, redacted_text, original_values):
    """Test unmasking with authorized role."""
    unmasked = unmask(redacted_text, "admin", valid_policy, original_values)
    
    # Check that redacted fields are restored
    assert "Email: john.doe@example.com" in unmasked
    assert "Phone: +1-555-123-4567" in unmasked
    assert "SSN: 123-45-6789" in unmasked
    
    # Check that unmasked fields are preserved
    assert "Name: John Doe" in unmasked
    assert "Address: 123 Main St" in unmasked

def test_unmask_unauthorized_role(valid_policy, redacted_text, original_values):
    """Test unmasking with unauthorized role."""
    unmasked = unmask(redacted_text, "user", valid_policy, original_values)
    assert unmasked == redacted_text  # Should be unchanged

def test_unmask_mixed_content(valid_policy, original_values):
    """Test unmasking with mixed content."""
    text = """
    Some fields are redacted:
    Email: [REDACTED]
    Phone: +1-555-123-4567  # Not redacted
    SSN: [REDACTED]
    """
    unmasked = unmask(text, "admin", valid_policy, original_values)
    assert "Email: john.doe@example.com" in unmasked
    assert "Phone: +1-555-123-4567" in unmasked  # Should be preserved
    assert "SSN: 123-45-6789" in unmasked

def test_unmask_multiple_entries(valid_policy, original_values):
    """Test unmasking with multiple [REDACTED] entries."""
    text = """
    Multiple redactions:
    Email: [REDACTED]
    Email: [REDACTED]
    Phone: [REDACTED]
    """
    unmasked = unmask(text, "admin", valid_policy, original_values)
    assert unmasked.count("john.doe@example.com") == 2
    assert unmasked.count("+1-555-123-4567") == 1

def test_unmask_no_redacted(valid_policy, original_values):
    """Test unmasking with no [REDACTED] markers."""
    text = "No redacted fields here"
    assert unmask(text, "admin", valid_policy, original_values) == text

def test_unmask_empty_input(valid_policy, original_values):
    """Test unmasking with empty input."""
    assert unmask("", valid_policy, original_values) == ""
    assert unmask("   ", valid_policy, original_values) == "   "

def test_unmask_malformed_policy(redacted_text, original_values):
    """Test unmasking with malformed policy."""
    # Missing required fields
    policy = {"mask": ["email"]}
    assert unmask(redacted_text, "admin", policy, original_values) == redacted_text
    
    # Empty lists
    policy = {"mask": [], "unmaskRoles": ["admin"], "conditions": ["trustScore > 80"]}
    assert unmask(redacted_text, "admin", policy, original_values) == redacted_text
    
    # Wrong types
    policy = {"mask": "email", "unmaskRoles": ["admin"], "conditions": ["trustScore > 80"]}
    assert unmask(redacted_text, "admin", policy, original_values) == redacted_text

def test_unmask_no_original_values(valid_policy, redacted_text):
    """Test unmasking without original values."""
    unmasked = unmask(redacted_text, "admin", valid_policy)
    assert "Email:" in unmasked
    assert "Phone:" in unmasked
    assert "SSN:" in unmasked
    assert "[REDACTED]" not in unmasked 