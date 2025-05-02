import re
from typing import Dict, Any, Optional
import warnings

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

def is_role_authorized(role: str, policy: Dict[str, Any]) -> bool:
    """Check if the role is authorized to unmask fields."""
    return role in policy["unmaskRoles"]

def create_unmask_patterns(fields: list) -> Dict[str, re.Pattern]:
    """Create patterns to match redacted fields."""
    patterns = {}
    for field in fields:
        # Match field: [REDACTED] pattern
        pattern = rf"{field}\s*:\s*\[REDACTED\]"
        patterns[field] = re.compile(pattern, re.IGNORECASE)
    return patterns

def unmask(text: str, role: str, policy: Dict[str, Any], 
          original_values: Optional[Dict[str, str]] = None) -> str:
    """
    Unmask redacted fields in text based on role and policy.
    
    Args:
        text: The redacted text containing [REDACTED] markers
        role: The role attempting to unmask
        policy: The policy dictionary containing unmask rules
        original_values: Optional mapping of field names to original values
        
    Returns:
        The unmasked text if role is authorized, otherwise returns input unchanged
    """
    # Validate policy
    if not validate_policy(policy):
        warnings.warn("Invalid policy provided")
        return text
    
    # Check role authorization
    if not is_role_authorized(role, policy):
        return text
    
    # If no [REDACTED] markers, return as-is
    if "[REDACTED]" not in text:
        return text
    
    # Create patterns for each field
    patterns = create_unmask_patterns(policy["mask"])
    
    # Apply unmasking to each field
    unmasked_text = text
    for field, pattern in patterns.items():
        # If we have original values, use them
        if original_values and field in original_values:
            replacement = f"{field}: {original_values[field]}"
        else:
            # If no original values, just remove [REDACTED]
            replacement = f"{field}:"
        
        # Replace each match
        unmasked_text = pattern.sub(replacement, unmasked_text)
    
    return unmasked_text 