from typing import Dict, Any
import warnings
from vault.audit.audit_logger import log_event

def validate_event(event: Dict[str, Any]) -> bool:
    """
    Validate that the event dictionary contains all required keys and correct types.
    
    Args:
        event: The event dictionary to validate
        
    Returns:
        bool: True if event is valid, False otherwise
    """
    required_fields = {
        "action": str,
        "field": str,
        "agent": dict,
        "result": str
    }
    
    # Check all required fields are present
    if not all(field in event for field in required_fields):
        return False
    
    # Check types of required fields
    for field, expected_type in required_fields.items():
        if not isinstance(event[field], expected_type):
            return False
    
    # Check agent has required fields
    if not all(key in event["agent"] for key in ["role", "trustScore"]):
        return False
    
    # Check agent field types
    if not isinstance(event["agent"]["role"], str):
        return False
    if not isinstance(event["agent"]["trustScore"], (int, float)):
        return False
    
    return True

def audit(event: Dict[str, Any]) -> None:
    """
    Log an audit event by forwarding it to the audit logger.
    
    Args:
        event: Dictionary containing event details:
            - action: The action performed (e.g., "redact", "unmask")
            - field: The field affected (e.g., "email", "ssn")
            - agent: Dictionary containing role and trustScore
            - result: The result of the action (e.g., "masked", "unmasked")
            
    Returns:
        None
    """
    # Validate event structure
    if not validate_event(event):
        warnings.warn("Invalid audit event structure")
        return
    
    # Forward to audit logger
    log_event(
        action=event["action"],
        field=event["field"],
        agent_role=event["agent"]["role"],
        agent_trust_score=event["agent"]["trustScore"],
        result=event["result"]
    ) 