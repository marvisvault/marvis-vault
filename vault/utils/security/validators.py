"""
Core security validators for Marvis Vault.

This module implements security-first validation that:
1. Prevents type confusion attacks
2. Blocks injection attempts
3. Handles special numeric values
4. Provides clear error messages
"""

import math
import unicodedata
import re
from typing import Dict, Any, Optional, Union
import logging

from .monitoring import monitor_validation
from .runtime_bypass import is_bypass_active
from .error_taxonomy import (
    ValidationError, ErrorCode, ErrorCategory,
    create_error, ERROR_MESSAGES
)

logger = logging.getLogger(__name__)

# Security constants
MAX_CONTENT_SIZE = 1 * 1024 * 1024  # 1MB (reduced from 10MB based on analysis)
MAX_STRING_LENGTH = 10 * 1024  # 10KB for individual strings (10240 bytes)
MAX_JSON_DEPTH = 100  # Prevent deeply nested JSON DoS

# High-privilege roles that need extra logging
HIGH_PRIVILEGE_ROLES = {
    'admin', 'administrator', 'root', 'superuser', 
    'doctor', 'nurse', 'physician',
    'data_protection_officer', 'dpo',
    'auditor', 'security_admin'
}

# Injection patterns to block - ordered by specificity (most specific first)
INJECTION_PATTERNS = [
    # Null byte first (most specific)
    (r"\x00", "Null byte injection"),
    
    # JavaScript/XSS patterns (before command injection to avoid misclassification)
    (r"javascript\s*:", "JavaScript protocol"),
    (r"<\s*(script|iframe|object|embed|form|input|button)", "XSS tag injection"),
    (r"\bon\w+\s*=", "Event handler injection"),
    
    # Path traversal (before SQL to catch /etc paths correctly)
    (r"\.\.[/\\]", "Path traversal"),
    (r"^[/\\](etc|usr|var|tmp)[/\\]", "System path access"),  # Start of string
    (r"\s[/\\](etc|usr|var|tmp)[/\\]", "System path access"),  # After space
    
    # SQL injection patterns - enhanced to catch no-space variants
    (r"'\s*(or|and)\s*['\"]?\s*\d+\s*=\s*['\"]?\s*\d+", "SQL boolean injection"),  # '1'='1' with spaces
    (r'"\s*(or|and)\s*["\']?\s*\d+\s*=\s*["\']?\s*\d+', "SQL boolean injection"),  # "1"="1" with spaces
    (r"'(or|and)['\"]?\d+['\"]?=['\"]?\d+", "SQL boolean injection"),  # '1'='1' no spaces
    (r'"(or|and)["\']?\d+["\']?=["\']?\d+', "SQL boolean injection"),  # "1"="1" no spaces
    (r"'\s*(or|and)\s+", "SQL boolean injection"),  # Simple OR/AND after quote
    (r'"\s*(or|and)\s+', "SQL boolean injection"),  # Simple OR/AND after double quote
    (r"'(or|and)", "SQL boolean injection"),  # OR/AND directly after quote
    (r'"(or|and)', "SQL boolean injection"),  # OR/AND directly after double quote
    (r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|declare|cast|convert)\b)", "SQL injection"),
    (r"(--|/\*|\*/|@@|@)", "SQL comment injection"),
    
    # Command injection patterns
    (r"[;&|`$()]", "Command injection"),
    (r"\b(sh|bash|cmd|powershell|nc|netcat|wget|curl)\b", "Command execution"),
    
    # Other patterns
    (r"__(proto|constructor|prototype)__", "Prototype pollution"),
]


# Use ValidationError from error_taxonomy instead
SecurityValidationError = ValidationError


@monitor_validation("role")
def validate_role(role: Any, source: str = "agent") -> str:
    """
    Validate and normalize role with security checks.
    
    Security properties enforced:
    - Required (not None)
    - Must be string type
    - Non-empty after stripping
    - Unicode normalized
    - No injection patterns
    - Length limited
    
    Args:
        role: The role value to validate
        source: Source identifier for error messages
        
    Returns:
        Validated and normalized role string
        
    Raises:
        SecurityValidationError: If validation fails
    """
    # Check bypass
    if is_bypass_active():
        logger.warning(f"Role validation bypassed for {source}")
        return str(role) if role is not None else "anonymous"
    
    # Null check with clear error
    if role is None:
        raise create_error(ErrorCode.FIELD_REQUIRED, field=f"{source} role")
    
    # Type check with specific error
    if not isinstance(role, str):
        raise create_error(ErrorCode.TYPE_STRING_EXPECTED, field=f"{source} role")
    
    # Empty check
    stripped_role = role.strip()
    if not stripped_role:
        raise create_error(ErrorCode.FIELD_EMPTY, field=f"{source} role")
    
    # Unicode normalization (prevent homograph attacks)
    normalized_role = unicodedata.normalize('NFKC', stripped_role)
    if normalized_role != stripped_role:
        logger.info(f"Unicode normalization applied to role: {repr(stripped_role)} -> {repr(normalized_role)}")
    
    # Length check
    if len(normalized_role) > 100:
        raise create_error(
            ErrorCode.SIZE_TOO_LARGE, 
            field=f"{source} role",
            details={"max_length": 100, "actual_length": len(normalized_role)}
        )
    
    # Injection pattern check
    role_lower = normalized_role.lower()
    for pattern, attack_type in INJECTION_PATTERNS:
        if re.search(pattern, role_lower, re.IGNORECASE):
            # Map attack types to error codes
            error_code = ErrorCode.INJECTION_SQL  # Default
            if "null byte" in attack_type.lower():
                error_code = ErrorCode.INJECTION_NULLBYTE
            elif "xss" in attack_type.lower() or "javascript" in attack_type.lower() or "event handler" in attack_type.lower():
                error_code = ErrorCode.INJECTION_XSS
            elif "command injection" in attack_type.lower() or "command execution" in attack_type.lower():
                error_code = ErrorCode.INJECTION_COMMAND
            elif "path traversal" in attack_type.lower():
                error_code = ErrorCode.INJECTION_PATH_TRAVERSAL
            elif "sql" in attack_type.lower():
                error_code = ErrorCode.INJECTION_SQL
            
            raise create_error(
                error_code,
                field=f"{source} role",
                details={"pattern": attack_type, "value_snippet": role_lower[:50]}
            )
    
    # Log high-privilege role requests
    if normalized_role.lower() in HIGH_PRIVILEGE_ROLES:
        logger.warning(f"High-privilege role requested: {normalized_role} from {source}")
    
    return normalized_role


@monitor_validation("trustScore") 
def validate_trust_score(score: Any, required: bool = True, source: str = "agent") -> Optional[float]:
    """
    Validate and normalize trust score.
    
    Security properties enforced:
    - Converts string numbers to float (prevents type confusion)
    - Rejects Infinity, NaN, and boolean values
    - Enforces 0-100 range
    - Clear error messages
    
    Args:
        score: The trust score value
        required: Whether the score is required
        source: Source identifier for error messages
        
    Returns:
        Normalized trust score as float, or None if optional and missing
        
    Raises:
        SecurityValidationError: If validation fails
    """
    # Check bypass
    if is_bypass_active():
        logger.warning(f"TrustScore validation bypassed for {source}")
        if score is None:
            return None if not required else 0.0
        try:
            return float(score)
        except:
            return 0.0
    
    # Handle missing score
    if score is None:
        if required:
            raise create_error(ErrorCode.FIELD_REQUIRED, field=f"{source} trustScore")
        return None
    
    # Reject boolean explicitly (Python treats True as 1, False as 0)
    if isinstance(score, bool):
        raise create_error(
            ErrorCode.VALUE_SPECIAL_NUMBER,
            field=f"{source} trustScore", 
            value="boolean"
        )
    
    # Convert to float
    if isinstance(score, str):
        # Check for special string values
        score_lower = score.lower().strip()
        if 'inf' in score_lower:
            raise create_error(
                ErrorCode.VALUE_SPECIAL_NUMBER,
                field=f"{source} trustScore",
                value="Infinity"
            )
        if score_lower == 'nan':
            raise create_error(
                ErrorCode.VALUE_SPECIAL_NUMBER,
                field=f"{source} trustScore",
                value="NaN"
            )
        
        # Try conversion
        try:
            numeric_score = float(score)
        except ValueError:
            raise create_error(
                ErrorCode.TYPE_NUMBER_EXPECTED,
                field=f"{source} trustScore"
            )
    elif isinstance(score, (int, float)):
        numeric_score = float(score)
    else:
        raise create_error(
            ErrorCode.TYPE_NUMBER_EXPECTED,
            field=f"{source} trustScore"
        )
    
    # Check for special float values
    if math.isnan(numeric_score):
        raise create_error(
            ErrorCode.VALUE_SPECIAL_NUMBER,
            field=f"{source} trustScore",
            value="NaN"
        )
    if math.isinf(numeric_score):
        raise create_error(
            ErrorCode.VALUE_SPECIAL_NUMBER,
            field=f"{source} trustScore",
            value="Infinity"
        )
    
    # Range validation
    if numeric_score < 0 or numeric_score > 100:
        raise create_error(
            ErrorCode.VALUE_OUT_OF_RANGE,
            field=f"{source} trustScore",
            value=numeric_score,
            details={"min": 0, "max": 100}
        )
    
    return numeric_score


@monitor_validation("context")
def validate_agent_context(context: Any, source: str = "agent") -> Dict[str, Any]:
    """
    Comprehensive validation for agent context.
    
    Security properties enforced:
    - Must be a dictionary
    - Role validation (always required)
    - TrustScore validation (required for simulate, optional for redact)
    - Size limits to prevent DoS
    - Injection detection in all fields
    - Prototype pollution prevention
    
    Args:
        context: The agent context to validate
        source: Source identifier ("agent" for simulate, "agent-redact" for redact)
        
    Returns:
        Validated and normalized context
        
    Raises:
        SecurityValidationError: If validation fails
    """
    # Check bypass
    if is_bypass_active():
        logger.warning(f"Context validation bypassed for {source}")
        if not isinstance(context, dict):
            return {"role": "anonymous", "trustScore": 0.0}
        return context
    
    # Type validation
    if not isinstance(context, dict):
        raise create_error(
            ErrorCode.TYPE_DICT_EXPECTED,
            field=source
        )
    
    # Empty check
    if not context:
        raise create_error(
            ErrorCode.FIELD_EMPTY,
            field=source
        )
    
    # Size check (DoS prevention)
    context_size = len(str(context))
    if context_size > MAX_CONTENT_SIZE:
        raise create_error(
            ErrorCode.DOS_LARGE_PAYLOAD,
            field=source,
            details={"size": context_size, "max_size": MAX_CONTENT_SIZE}
        )
    
    # Create clean validated context
    validated = {}
    
    # Validate role (always required)
    if "role" not in context:
        raise create_error(
            ErrorCode.FIELD_REQUIRED,
            field=f"{source}.role"
        )
    validated["role"] = validate_role(context["role"], source)
    
    # Validate trustScore
    if source == "agent":  # simulate command
        if "trustScore" not in context:
            raise create_error(
                ErrorCode.FIELD_REQUIRED,
                field=f"{source}.trustScore"
            )
        validated["trustScore"] = validate_trust_score(context["trustScore"], required=True, source=source)
    elif source == "agent-redact":  # redact command
        if "trustScore" in context:
            score = validate_trust_score(context["trustScore"], required=False, source=source)
            if score is not None:
                validated["trustScore"] = score
    
    # Validate other fields
    for key, value in context.items():
        if key in ["role", "trustScore"]:
            continue
        
        # Prevent prototype pollution
        if key in ["__proto__", "constructor", "prototype"]:
            logger.warning(f"Prototype pollution attempt blocked: {key}")
            continue
        
        # Validate string fields
        if isinstance(value, str):
            if len(value) > MAX_STRING_LENGTH:
                raise create_error(
                    ErrorCode.SIZE_TOO_LARGE,
                    field=f"{source}.{key}",
                    details={"max_length": MAX_STRING_LENGTH, "actual_length": len(value)}
                )
            
            # Normalize unicode
            normalized = unicodedata.normalize('NFKC', value)
            
            # Check for injection in string fields
            value_lower = normalized.lower()
            for pattern, attack_type in INJECTION_PATTERNS:
                if re.search(pattern, value_lower, re.IGNORECASE):
                    # Map attack types to error codes
                    error_code = ErrorCode.INJECTION_SQL
                    if "XSS" in attack_type:
                        error_code = ErrorCode.INJECTION_XSS
                    elif "command" in attack_type.lower() or "shell" in attack_type.lower():
                        error_code = ErrorCode.INJECTION_COMMAND
                    elif "path" in attack_type.lower():
                        error_code = ErrorCode.INJECTION_PATH_TRAVERSAL
                    elif "null" in attack_type.lower():
                        error_code = ErrorCode.INJECTION_NULLBYTE
                    
                    raise create_error(
                        error_code,
                        field=f"{source}.{key}",
                        details={"pattern": attack_type}
                    )
            
            validated[key] = normalized
        else:
            # Recursively validate nested structures
            validated[key] = validate_nested_value(value, f"{source}.{key}")
    
    # Validate JSON depth for nested structures
    validate_json_depth(validated)
    
    # Final size check on complete validated context
    final_size = len(str(validated))
    if final_size > MAX_CONTENT_SIZE:
        raise create_error(
            ErrorCode.DOS_LARGE_PAYLOAD,
            field=source,
            details={"size": final_size, "max_size": MAX_CONTENT_SIZE}
        )
    
    return validated


def validate_nested_value(value: Any, path: str, current_depth: int = 0) -> Any:
    """
    Recursively validate nested values for injection and size limits.
    
    Args:
        value: Value to validate
        path: Current path for error messages (e.g., "agent.config.settings")
        current_depth: Current nesting depth
        
    Returns:
        Validated and normalized value
        
    Raises:
        ValidationError: If validation fails
    """
    # Check depth
    if current_depth > MAX_JSON_DEPTH:
        raise create_error(
            ErrorCode.DEPTH_EXCEEDED,
            details={"max_depth": MAX_JSON_DEPTH, "current_depth": current_depth}
        )
    
    # Handle strings
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise create_error(
                ErrorCode.SIZE_TOO_LARGE,
                field=path,
                details={"max_length": MAX_STRING_LENGTH, "actual_length": len(value)}
            )
        
        # Normalize unicode
        normalized = unicodedata.normalize('NFKC', value)
        
        # Check for injection
        value_lower = normalized.lower()
        for pattern, attack_type in INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                # Map attack types to error codes
                error_code = ErrorCode.INJECTION_SQL  # Default
                if "null byte" in attack_type.lower():
                    error_code = ErrorCode.INJECTION_NULLBYTE
                elif "xss" in attack_type.lower() or "javascript" in attack_type.lower() or "event handler" in attack_type.lower():
                    error_code = ErrorCode.INJECTION_XSS
                elif "command injection" in attack_type.lower() or "command execution" in attack_type.lower():
                    error_code = ErrorCode.INJECTION_COMMAND
                elif "path traversal" in attack_type.lower():
                    error_code = ErrorCode.INJECTION_PATH_TRAVERSAL
                elif "sql" in attack_type.lower():
                    error_code = ErrorCode.INJECTION_SQL
                
                raise create_error(
                    error_code,
                    field=path,
                    details={"pattern": attack_type}
                )
        
        return normalized
    
    # Handle dictionaries
    elif isinstance(value, dict):
        validated_dict = {}
        for key, val in value.items():
            # Prevent prototype pollution
            if key in ["__proto__", "constructor", "prototype"]:
                logger.warning(f"Prototype pollution attempt blocked: {key} at {path}")
                continue
            
            validated_dict[key] = validate_nested_value(val, f"{path}.{key}", current_depth + 1)
        
        return validated_dict
    
    # Handle lists
    elif isinstance(value, list):
        return [validate_nested_value(item, f"{path}[{i}]", current_depth + 1) 
                for i, item in enumerate(value)]
    
    # Pass through other types (numbers, booleans, None)
    else:
        return value


def validate_json_depth(obj: Any, current_depth: int = 0, max_depth: int = MAX_JSON_DEPTH) -> None:
    """
    Validate JSON nesting depth to prevent DoS.
    
    Args:
        obj: Object to validate
        current_depth: Current nesting level
        max_depth: Maximum allowed depth
        
    Raises:
        ValidationError: If nesting too deep
    """
    if current_depth > max_depth:
        raise create_error(
            ErrorCode.DEPTH_EXCEEDED,
            details={"max_depth": max_depth, "current_depth": current_depth}
        )
    
    if isinstance(obj, dict):
        for value in obj.values():
            validate_json_depth(value, current_depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            validate_json_depth(item, current_depth + 1, max_depth)