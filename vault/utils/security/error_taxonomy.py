"""
Error taxonomy system for security validation.

This provides a structured way to handle validation errors with consistent
error codes, allowing tests to check error types rather than exact messages.
"""

from enum import Enum
from typing import Optional, Dict, Any


class ErrorCategory(Enum):
    """High-level error categories."""
    TYPE_ERROR = "TYPE_ERROR"
    MISSING_FIELD = "MISSING_FIELD"
    INJECTION_ATTACK = "INJECTION_ATTACK"
    DOS_ATTACK = "DOS_ATTACK"
    INVALID_VALUE = "INVALID_VALUE"
    SIZE_LIMIT = "SIZE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"


class ErrorCode(Enum):
    """Specific error codes for validation failures."""
    # Type errors
    TYPE_STRING_EXPECTED = "E001"
    TYPE_NUMBER_EXPECTED = "E002"
    TYPE_DICT_EXPECTED = "E003"
    TYPE_LIST_EXPECTED = "E004"
    
    # Missing fields
    FIELD_REQUIRED = "E100"
    FIELD_EMPTY = "E101"
    
    # Injection attacks
    INJECTION_SQL = "E200"
    INJECTION_XSS = "E201"
    INJECTION_COMMAND = "E202"
    INJECTION_PATH_TRAVERSAL = "E203"
    INJECTION_LDAP = "E204"
    INJECTION_REGEX = "E205"
    INJECTION_NULLBYTE = "E206"
    INJECTION_UNICODE = "E207"
    
    # DoS attacks
    DOS_LARGE_PAYLOAD = "E300"
    DOS_DEEP_NESTING = "E301"
    DOS_EXCESSIVE_FIELDS = "E302"
    
    # Invalid values
    VALUE_OUT_OF_RANGE = "E400"
    VALUE_INVALID_FORMAT = "E401"
    VALUE_SPECIAL_NUMBER = "E402"
    VALUE_CONTROL_CHARACTER = "E403"
    
    # Size limits
    SIZE_TOO_LARGE = "E500"
    SIZE_TOO_SMALL = "E501"
    
    # Depth limits
    DEPTH_EXCEEDED = "E600"


class ValidationError(ValueError):
    """Enhanced validation error with structured information."""
    
    def __init__(
        self,
        code: ErrorCode,
        category: ErrorCategory,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.code = code
        self.category = category
        self.field = field
        self.value = value
        self.details = details or {}
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to structured dictionary."""
        result = {
            "code": self.code.value,
            "category": self.category.value,
            "message": str(self)
        }
        
        if self.field:
            result["field"] = self.field
        
        if self.details:
            result["details"] = self.details
            
        return result
    
    @property
    def is_security_error(self) -> bool:
        """Check if this is a security-related error."""
        return self.category in {
            ErrorCategory.INJECTION_ATTACK,
            ErrorCategory.DOS_ATTACK
        }


# Error message templates for consistency
ERROR_MESSAGES = {
    ErrorCode.TYPE_STRING_EXPECTED: "{field} must be a string",
    ErrorCode.TYPE_NUMBER_EXPECTED: "{field} must be a number",
    ErrorCode.TYPE_DICT_EXPECTED: "{field} must be a dictionary",
    ErrorCode.TYPE_LIST_EXPECTED: "{field} must be a list",
    
    ErrorCode.FIELD_REQUIRED: "{field} is required",
    ErrorCode.FIELD_EMPTY: "{field} cannot be empty",
    
    ErrorCode.INJECTION_SQL: "SQL injection detected in {field}",
    ErrorCode.INJECTION_XSS: "XSS injection detected in {field}",
    ErrorCode.INJECTION_COMMAND: "Command injection detected in {field}",
    ErrorCode.INJECTION_PATH_TRAVERSAL: "Path traversal detected in {field}",
    ErrorCode.INJECTION_LDAP: "LDAP injection detected in {field}",
    ErrorCode.INJECTION_REGEX: "Regex injection detected in {field}",
    ErrorCode.INJECTION_NULLBYTE: "Null byte injection detected in {field}",
    ErrorCode.INJECTION_UNICODE: "Unicode attack detected in {field}",
    
    ErrorCode.DOS_LARGE_PAYLOAD: "Payload too large: {details}",
    ErrorCode.DOS_DEEP_NESTING: "Maximum nesting depth exceeded",
    ErrorCode.DOS_EXCESSIVE_FIELDS: "Too many fields in {field}",
    
    ErrorCode.VALUE_OUT_OF_RANGE: "{field} value out of range: {value}",
    ErrorCode.VALUE_INVALID_FORMAT: "Invalid format for {field}",
    ErrorCode.VALUE_SPECIAL_NUMBER: "Special numeric value not allowed: {value}",
    ErrorCode.VALUE_CONTROL_CHARACTER: "Control characters not allowed in {field}",
    
    ErrorCode.SIZE_TOO_LARGE: "{field} exceeds maximum size: {details}",
    ErrorCode.SIZE_TOO_SMALL: "{field} below minimum size: {details}",
    
    ErrorCode.DEPTH_EXCEEDED: "Maximum depth {max_depth} exceeded at level {current_depth}"
}


def create_error(
    code: ErrorCode,
    field: Optional[str] = None,
    value: Optional[Any] = None,
    details: Optional[Dict[str, Any]] = None,
    custom_message: Optional[str] = None
) -> ValidationError:
    """Create a structured validation error."""
    # Determine category from code
    code_value = code.value
    if code_value.startswith("E0"):
        category = ErrorCategory.TYPE_ERROR
    elif code_value.startswith("E1"):
        category = ErrorCategory.MISSING_FIELD
    elif code_value.startswith("E2"):
        category = ErrorCategory.INJECTION_ATTACK
    elif code_value.startswith("E3"):
        category = ErrorCategory.DOS_ATTACK
    elif code_value.startswith("E4"):
        category = ErrorCategory.INVALID_VALUE
    elif code_value.startswith("E5"):
        category = ErrorCategory.SIZE_LIMIT
    elif code_value.startswith("E6"):
        category = ErrorCategory.DEPTH_LIMIT
    else:
        category = ErrorCategory.INVALID_VALUE
    
    # Generate message
    if custom_message:
        message = custom_message
    else:
        template = ERROR_MESSAGES.get(code, "Validation error in {field}")
        format_args = {
            "field": field or "value",
            "value": value,
            "details": details
        }
        
        # Add details to format args
        if details:
            format_args.update(details)
            
        message = template.format(**format_args)
    
    return ValidationError(
        code=code,
        category=category,
        message=message,
        field=field,
        value=value,
        details=details
    )