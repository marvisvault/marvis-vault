import pytest
from unittest.mock import patch, MagicMock
from vault.sdk.audit import audit, validate_event

@pytest.fixture
def valid_event():
    """Create a valid audit event dictionary."""
    return {
        "action": "redact",
        "field": "email",
        "agent": {
            "role": "admin",
            "trustScore": 90
        },
        "result": "masked"
    }

@pytest.fixture
def invalid_event_missing_fields():
    """Create an invalid audit event with missing fields."""
    return {
        "action": "redact",
        "field": "email"
        # Missing agent and result
    }

@pytest.fixture
def invalid_event_wrong_types():
    """Create an invalid audit event with wrong field types."""
    return {
        "action": 123,  # Should be str
        "field": "email",
        "agent": "admin",  # Should be dict
        "result": "masked"
    }

@pytest.fixture
def invalid_event_missing_agent_fields():
    """Create an invalid audit event with missing agent fields."""
    return {
        "action": "redact",
        "field": "email",
        "agent": {
            "role": "admin"
            # Missing trustScore
        },
        "result": "masked"
    }

def test_validate_event_valid(valid_event):
    """Test validation of valid event."""
    assert validate_event(valid_event)

def test_validate_event_missing_fields(invalid_event_missing_fields):
    """Test validation of event with missing fields."""
    assert not validate_event(invalid_event_missing_fields)

def test_validate_event_wrong_types(invalid_event_wrong_types):
    """Test validation of event with wrong field types."""
    assert not validate_event(invalid_event_wrong_types)

def test_validate_event_missing_agent_fields(invalid_event_missing_agent_fields):
    """Test validation of event with missing agent fields."""
    assert not validate_event(invalid_event_missing_agent_fields)

@patch('vault.sdk.audit.log_event')
def test_audit_valid_event(mock_log_event, valid_event):
    """Test audit with valid event."""
    audit(valid_event)
    
    # Verify log_event was called with correct arguments
    mock_log_event.assert_called_once_with(
        action="redact",
        field="email",
        agent_role="admin",
        agent_trust_score=90,
        result="masked"
    )

@patch('vault.sdk.audit.log_event')
def test_audit_missing_fields(mock_log_event, invalid_event_missing_fields):
    """Test audit with event missing required fields."""
    audit(invalid_event_missing_fields)
    
    # Verify log_event was not called
    mock_log_event.assert_not_called()

@patch('vault.sdk.audit.log_event')
def test_audit_wrong_types(mock_log_event, invalid_event_wrong_types):
    """Test audit with event having wrong field types."""
    audit(invalid_event_wrong_types)
    
    # Verify log_event was not called
    mock_log_event.assert_not_called()

@patch('vault.sdk.audit.log_event')
def test_audit_missing_agent_fields(mock_log_event, invalid_event_missing_agent_fields):
    """Test audit with event missing agent fields."""
    audit(invalid_event_missing_agent_fields)
    
    # Verify log_event was not called
    mock_log_event.assert_not_called()

@patch('vault.sdk.audit.log_event')
def test_audit_log_event_error(mock_log_event, valid_event):
    """Test audit when log_event raises an error."""
    mock_log_event.side_effect = Exception("Logging error")
    
    # Should not raise exception
    audit(valid_event)
    
    # Verify log_event was called
    mock_log_event.assert_called_once() 