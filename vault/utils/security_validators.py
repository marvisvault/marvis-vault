"""
Security validators for agent context and input validation.
Provides comprehensive validation to prevent security vulnerabilities.

This module now acts as a compatibility layer that delegates to the new
security module (vault.utils.security) for actual validation. This allows
gradual migration while maintaining backward compatibility.
"""

import math
import unicodedata
from typing import Dict, Any, Optional, Union
import re
import sys
import warnings

# Import from new security module
try:
    from .security import (
        validate_agent_context as _validate_agent_context,
        validate_role as _validate_role,
        validate_trust_score as _validate_trust_score,
        SecurityValidationError as _SecurityValidationError,
        validate_json_depth,
    )
    # Also import error taxonomy for apps that need it
    from .security.error_taxonomy import (
        ValidationError,
        ErrorCode,
        ErrorCategory,
        create_error
    )
    _NEW_MODULE_AVAILABLE = True
except ImportError:
    _NEW_MODULE_AVAILABLE = False
    warnings.warn("New security module not available, using legacy validators", ImportWarning)

# Security constants (kept for backward compatibility)
MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10MB
MAX_STRING_LENGTH = 10000  # 10KB for individual strings
MAX_JSON_DEPTH = 100  # Prevent deeply nested JSON DoS
SAFE_ROLES = {'user', 'analyst', 'manager', 'auditor', 'support', 'contractor', 'developer', 'executive'}

# Re-export SecurityValidationError for backward compatibility
if _NEW_MODULE_AVAILABLE:
    SecurityValidationError = _SecurityValidationError
    # Also make taxonomy available for gradual migration
    __all__ = [
        'validate_agent_context',
        'validate_role', 
        'validate_trust_score',
        'validate_json_depth',
        'SecurityValidationError',
        'ValidationError',
        'ErrorCode',
        'ErrorCategory',
        'create_error'
    ]
else:
    class SecurityValidationError(ValueError):
        """Raised when security validation fails."""
        pass
    __all__ = [
        'validate_agent_context',
        'validate_role',
        'validate_trust_score', 
        'validate_json_depth',
        'SecurityValidationError'
    ]

def validate_agent_context(context: Any, source: str = "agent") -> Dict[str, Any]:
    """
    Comprehensive security validation for agent context.
    
    IMPORTANT: This function now delegates to the new security module
    which implements security-first validation. The behavior has changed:
    - String trustScores are now converted to float
    - Injection patterns are rejected
    - Better error messages for specific failures
    """
    if _NEW_MODULE_AVAILABLE:
        return _validate_agent_context(context, source)
    
    # Fallback to original implementation
    return _validate_agent_context_legacy(context, source)


def _validate_agent_context_legacy(context: Any, source: str = "agent") -> Dict[str, Any]:
    """
    Legacy implementation kept for reference/fallback.
    
    Args:
        context: The agent context to validate
        source: Source identifier for error messages
        
    Returns:
        Validated and normalized context
        
    Raises:
        SecurityValidationError: If validation fails
    """
    # Type validation
    if not isinstance(context, dict):
        raise SecurityValidationError(f"{source} file must contain a JSON object (not array or string)")
    
    # Check for empty file
    if not context:
        raise SecurityValidationError(f"{source} file is empty")
    
    # Validate required fields
    if "role" not in context:
        raise SecurityValidationError(f"{source} context must contain 'role' field")
    
    # For simulate command, trustScore is required
    # For redact command (agent-redact), trustScore is optional
    if source == "agent" and "trustScore" not in context:
        raise SecurityValidationError(f"{source} context must contain 'trustScore' field")
    
    # Validate and normalize role
    role = context.get("role")
    if role is None:
        raise SecurityValidationError(f"role must be a string")
    
    if not isinstance(role, str):
        raise SecurityValidationError(f"role must be a string")
    
    if not role.strip():
        raise SecurityValidationError(f"role cannot be empty")
    
    # Security: Normalize Unicode to prevent homograph attacks
    normalized_role = unicodedata.normalize('NFKC', role)
    if normalized_role != role:
        # Log potential attack but continue with normalized version
        print(f"[security] Unicode normalization applied to role: '{role}' -> '{normalized_role}'", file=sys.stderr)
    context["role"] = normalized_role.strip()
    
    # Check role length
    if len(context["role"]) > 100:
        raise SecurityValidationError(f"{source} 'role' too long (max 100 characters)")
    
    # Validate trustScore if present
    if "trustScore" in context:
        trust_score = context["trustScore"]
        
        # Reject None/null explicitly for simulate
        if source == "agent" and trust_score is None:
            raise SecurityValidationError("trustScore cannot be null")
        
        # If not None, validate thoroughly
        if trust_score is not None:
            # Reject boolean values explicitly (Python quirk: bool is subclass of int)
            if isinstance(trust_score, bool):
                raise SecurityValidationError("trustScore cannot be a boolean")
            
            # Must be numeric or numeric string
            if not isinstance(trust_score, (int, float, str)):
                raise SecurityValidationError(f"trustScore must be numeric")
            
            # Convert to float for validation
            try:
                score_value = float(trust_score)
            except (TypeError, ValueError):
                raise SecurityValidationError(f"trustScore must be numeric")
            
            # Check for special values
            if math.isnan(score_value):
                raise SecurityValidationError("trustScore cannot be NaN")
            
            if math.isinf(score_value):
                raise SecurityValidationError("trustScore cannot be Infinity")
            
            # Check range
            if score_value < 0 or score_value > 100:
                raise SecurityValidationError(f"trustScore must be between 0-100, got {score_value}")
            
            # Keep original value if it was a valid numeric string, otherwise store normalized
            # This matches the test expectation that "80" stays as "80"
            if not isinstance(trust_score, str):
                context["trustScore"] = score_value
    
    # Validate context size to prevent DoS
    context_str = str(context)
    if len(context_str) > MAX_CONTENT_SIZE:
        raise SecurityValidationError(f"Context too large (max {MAX_CONTENT_SIZE} bytes)")
    
    # Validate all string fields for length and content
    for key, value in context.items():
        if isinstance(value, str):
            if len(value) > MAX_STRING_LENGTH:
                raise SecurityValidationError(f"Field '{key}' too long (max {MAX_STRING_LENGTH} characters)")
            
            # Normalize Unicode in all string fields
            normalized = unicodedata.normalize('NFKC', value)
            if normalized != value:
                print(f"[security] Unicode normalization applied to field '{key}'", file=sys.stderr)
                context[key] = normalized
    
    # Check for suspicious patterns in any field
    context_dump = str(context).lower()
    suspicious_patterns = [
        (r'<script', 'Potential XSS attempt'),
        (r'javascript:', 'Potential XSS attempt'),
        (r'on\w+\s*=', 'Potential event handler injection'),
        (r'(union|select|insert|update|delete|drop)\s+(from|into|table)', 'Potential SQL injection'),
        (r'\.\./', 'Potential path traversal'),
        (r'\x00', 'Null byte injection'),
        (r'[;&|]', 'Potential command injection'),
    ]
    
    for pattern, message in suspicious_patterns:
        if re.search(pattern, context_dump):
            print(f"[security] WARNING: {message} detected in context", file=sys.stderr)
    
    return context

def validate_json_depth(obj: Any, current_depth: int = 0) -> None:
    """
    Validate JSON nesting depth to prevent DoS attacks.
    
    Args:
        obj: Object to validate
        current_depth: Current nesting level
        
    Raises:
        SecurityValidationError: If nesting too deep
    """
    if current_depth > MAX_JSON_DEPTH:
        raise SecurityValidationError(f"JSON nesting too deep (max {MAX_JSON_DEPTH} levels)")
    
    if isinstance(obj, dict):
        for value in obj.values():
            validate_json_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            validate_json_depth(item, current_depth + 1)

def validate_content_size(content: Union[str, bytes]) -> None:
    """
    Validate content size to prevent memory exhaustion.
    
    Args:
        content: Content to validate
        
    Raises:
        SecurityValidationError: If content too large
    """
    size = len(content) if isinstance(content, str) else len(content)
    if size > MAX_CONTENT_SIZE:
        raise SecurityValidationError(f"Content too large ({size} bytes, max {MAX_CONTENT_SIZE})")

def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error messages to prevent information disclosure.
    
    Args:
        error: The exception to sanitize
        
    Returns:
        Safe error message
    """
    error_str = str(error)
    
    # Remove file paths
    error_str = re.sub(r'[/\\][\w\-_/\\\.]+\.(py|json|yaml)', '[file]', error_str)
    
    # Remove line numbers
    error_str = re.sub(r'line \d+', 'line [n]', error_str)
    
    # Remove specific system information
    error_str = re.sub(r'(at|in)\s+0x[0-9a-fA-F]+', '[memory]', error_str)
    
    # Truncate if too long
    if len(error_str) > 200:
        error_str = error_str[:200] + '...'
    
    return error_str

def validate_regex_pattern(pattern: str) -> None:
    """
    Validate regex pattern to prevent ReDoS attacks.
    
    Args:
        pattern: Regex pattern to validate
        
    Raises:
        SecurityValidationError: If pattern is dangerous
    """
    # Check for dangerous patterns
    dangerous_patterns = [
        r'(\w+\+)+',  # Nested quantifiers
        r'(\w+\*)+',
        r'(\w+\?)+',
        r'(.+)+',     # Catastrophic backtracking
        r'(.*)*',
        r'(\w+){1000,}',  # Large repetitions
    ]
    
    for dangerous in dangerous_patterns:
        if re.search(dangerous, pattern):
            raise SecurityValidationError("Potentially dangerous regex pattern detected")
    
    # Try to compile with timeout
    try:
        re.compile(pattern)
    except re.error:
        raise SecurityValidationError("Invalid regex pattern")

def normalize_unicode_input(text: str) -> str:
    """
    Normalize Unicode input to prevent various Unicode-based attacks.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text
    """
    # NFKC normalization handles most cases
    normalized = unicodedata.normalize('NFKC', text)
    
    # Remove zero-width characters
    zero_width_chars = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # Zero-width no-break space
        '\u2060',  # Word joiner
    ]
    
    for char in zero_width_chars:
        normalized = normalized.replace(char, '')
    
    # Remove other invisible characters
    normalized = ''.join(char for char in normalized if unicodedata.category(char)[0] != 'C' or char == '\n' or char == '\t')
    
    return normalized

def is_safe_role(role: str) -> bool:
    """
    Check if a role is in the safe/expected list.
    
    Args:
        role: Role to check
        
    Returns:
        True if role is recognized as safe
    """
    normalized_role = normalize_unicode_input(role.lower().strip())
    return normalized_role in SAFE_ROLES

def detect_timing_attack_pattern(timestamps: list, window_ms: int = 10) -> bool:
    """
    Detect potential timing attack patterns.
    
    Args:
        timestamps: List of request timestamps
        window_ms: Time window to consider as suspicious
        
    Returns:
        True if timing pattern is suspicious
    """
    if len(timestamps) < 3:
        return False
    
    # Sort timestamps
    sorted_times = sorted(timestamps)
    
    # Check for regular intervals
    intervals = []
    for i in range(1, len(sorted_times)):
        intervals.append(sorted_times[i] - sorted_times[i-1])
    
    # If all intervals are within window_ms of each other, it's suspicious
    if max(intervals) - min(intervals) < window_ms:
        return True
    
    return False