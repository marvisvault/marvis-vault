import re
from typing import Dict, Any, Optional
from vault.engine.policy_engine import evaluate

def validate_policy(policy: Dict[str, Any]) -> bool:
    """Validate that the policy has required fields and correct types."""
    if not isinstance(policy, dict):
        return False
    
    required_fields = {"mask", "unmaskRoles", "conditions"}
    if not all(field in policy for field in required_fields):
        return False
    
    if not all(isinstance(policy[field], list) for field in required_fields):
        return False
    
    if not all(policy[field] for field in required_fields):  # Check for empty lists
        return False
    
    return True

def create_field_patterns(fields: list) -> Dict[str, re.Pattern]:
    """Create case-insensitive regex patterns for each field."""
    patterns = {}
    for field in fields:
        # Create a pattern that matches the field name followed by a colon and value
        pattern = rf"{field}\s*:\s*([^\n,}}]+)"
        patterns[field] = re.compile(pattern, re.IGNORECASE)
    return patterns

def redact(text: str, policy: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
    """
    Redact sensitive fields from text based on policy rules.
    
    Args:
        text: The input text to redact
        policy: The policy dictionary containing mask rules
        context: Optional context for policy evaluation
        
    Returns:
        The redacted text if policy is valid and conditions pass,
        otherwise returns the original text
    """
    # Validate policy
    if not validate_policy(policy):
        return text
    
    # Evaluate policy conditions if context is provided
    if context is not None:
        result = evaluate(policy, context)
        if not result.get("status", False):
            return text
    
    # Create patterns for each field to mask
    patterns = create_field_patterns(policy["mask"])
    
    # Apply redaction to each field
    redacted_text = text
    for field, pattern in patterns.items():
        # Replace each match with [REDACTED]
        redacted_text = pattern.sub(f"{field}: [REDACTED]", redacted_text)
    
    return redacted_text 