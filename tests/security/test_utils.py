"""
Test utilities for security tests.

Provides helpers for checking error types instead of exact messages.
"""

import pytest
from typing import Type, Optional, Callable, Any
from vault.utils.security.error_taxonomy import ValidationError, ErrorCode, ErrorCategory


def assert_validation_error(
    func: Callable,
    *args,
    error_code: Optional[ErrorCode] = None,
    error_category: Optional[ErrorCategory] = None,
    field_contains: Optional[str] = None,
    **kwargs
) -> ValidationError:
    """
    Assert that a validation error is raised with specific properties.
    
    Args:
        func: Function to call
        *args: Arguments to pass to function
        error_code: Expected error code (optional)
        error_category: Expected error category (optional)
        field_contains: String that should be in the field name (optional)
        **kwargs: Keyword arguments to pass to function
        
    Returns:
        The raised ValidationError for further inspection
        
    Raises:
        AssertionError: If expectations not met
    """
    with pytest.raises(ValidationError) as exc_info:
        func(*args, **kwargs)
    
    error = exc_info.value
    
    # Check error code if specified
    if error_code is not None:
        assert error.code == error_code, f"Expected error code {error_code}, got {error.code}"
    
    # Check error category if specified
    if error_category is not None:
        assert error.category == error_category, f"Expected category {error_category}, got {error.category}"
    
    # Check field contains string if specified
    if field_contains is not None and error.field is not None:
        assert field_contains in error.field, f"Expected field to contain '{field_contains}', got '{error.field}'"
    
    return error


def assert_no_validation_error(func: Callable, *args, **kwargs) -> Any:
    """
    Assert that no validation error is raised.
    
    Args:
        func: Function to call
        *args: Arguments to pass to function
        **kwargs: Keyword arguments to pass to function
        
    Returns:
        The result of the function call
    """
    try:
        return func(*args, **kwargs)
    except ValidationError as e:
        pytest.fail(f"Unexpected validation error: {e}")


def assert_error_details(
    error: ValidationError,
    detail_key: str,
    expected_value: Any
) -> None:
    """
    Assert that an error contains specific details.
    
    Args:
        error: The ValidationError to check
        detail_key: Key to look for in details
        expected_value: Expected value for the key
    """
    assert detail_key in error.details, f"Expected detail key '{detail_key}' not found in {error.details}"
    assert error.details[detail_key] == expected_value, \
        f"Expected {detail_key}={expected_value}, got {error.details[detail_key]}"


def matches_any_error_code(error: ValidationError, codes: list) -> bool:
    """Check if error matches any of the provided codes."""
    return error.code in codes


def is_injection_error(error: ValidationError) -> bool:
    """Check if error is any type of injection error."""
    return error.category == ErrorCategory.INJECTION_ATTACK


def is_dos_error(error: ValidationError) -> bool:
    """Check if error is any type of DoS error."""
    return error.category == ErrorCategory.DOS_ATTACK