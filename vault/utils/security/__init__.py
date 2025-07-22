"""
Security module for Marvis Vault.

Provides comprehensive validation and security features:
- Input validation with protection against injection attacks
- Type normalization to prevent confusion attacks
- Runtime bypass API for emergencies
- Performance monitoring
"""

from .validators import (
    validate_agent_context,
    validate_role,
    validate_trust_score,
    SecurityValidationError,
    validate_json_depth,
)

from .runtime_bypass import (
    bypass_validation,
    is_bypass_active,
    BypassContext,
)

from .monitoring import (
    get_validation_metrics,
    reset_metrics,
    ValidationMetrics,
)

from .error_taxonomy import (
    ValidationError,
    ErrorCode,
    ErrorCategory,
    create_error,
)

__all__ = [
    'validate_agent_context',
    'validate_role', 
    'validate_trust_score',
    'SecurityValidationError',
    'validate_json_depth',
    'bypass_validation',
    'is_bypass_active',
    'BypassContext',
    'get_validation_metrics',
    'reset_metrics',
    'ValidationMetrics',
    'ValidationError',
    'ErrorCode',
    'ErrorCategory',
    'create_error',
]