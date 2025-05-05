import re
import unicodedata
from typing import Dict, Any, Optional
from vault.engine.policy_engine import evaluate

class RedactionError(Exception):
    """Custom exception for redaction failures."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"Redaction failed for field '{field}': {message}")

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

def sanitize_control_chars(text: str) -> str:
    """
    Sanitize control characters in text by replacing them with visible placeholders.
    This prevents regex matching issues and ensures safe logging.
    """
    # Replace control characters with visible placeholders
    # ASCII control characters (0-31) except \n, \r, \t
    control_chars = ''.join(chr(i) for i in range(32) if chr(i) not in '\n\r\t')
    return ''.join(
        f'<0x{ord(c):02x}>' if c in control_chars else c
        for c in text
    )

def create_field_patterns(fields: list) -> Dict[str, re.Pattern]:
    """Create case-insensitive regex patterns for each field with proper escaping."""
    patterns = {}
    for field in fields:
        # Normalize field name to NFC form to handle Unicode equivalence
        normalized_field = unicodedata.normalize('NFC', field)
        # Escape field name to prevent regex injection and handle special characters
        escaped_field = re.escape(normalized_field)
        # Create a pattern that matches the field name followed by a colon and value
        # Using DOTALL flag to match across multiple lines
        pattern = rf"{escaped_field}\s*:\s*([^\n,}}]+(?:\n[^\n,}}]+)*)"
        patterns[field] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
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
        
    Raises:
        RedactionError: If redaction fails for any required field
    """
    # Validate policy
    if not validate_policy(policy):
        return text
    
    # Evaluate policy conditions if context is provided
    if context is not None:
        result = evaluate(policy, context)
        if not result.get("status", False):
            return text
    
    # Normalize text to NFC form and sanitize control characters
    # This ensures consistent matching and prevents regex issues
    normalized_text = unicodedata.normalize('NFC', text)
    sanitized_text = sanitize_control_chars(normalized_text)
    
    # Create patterns for each field to mask
    patterns = create_field_patterns(policy["mask"])
    
    # Apply redaction to each field with error checking
    redacted_text = sanitized_text
    for field, pattern in patterns.items():
        # Check if field exists in text before attempting redaction
        if not pattern.search(redacted_text):
            raise RedactionError(field, "Field not found in input text")
        
        # Replace each match with [REDACTED]
        redacted_text = pattern.sub(f"{field}: [REDACTED]", redacted_text)
        
        # Verify redaction was successful
        if pattern.search(redacted_text):
            raise RedactionError(field, "Redaction failed - field still present after masking")
    
    return redacted_text 