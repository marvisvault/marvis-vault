# Marvis Vault Security Implementation

## Overview

This document describes the security implementation for Marvis Vault, focusing on protecting against real-world attacks while maintaining usability through a gradual migration approach.

## Critical Security Vulnerabilities Addressed

### 1. Type Confusion Attacks (HIGH SEVERITY)

**Vulnerability**: String trustScores like `"80"` behave differently than numeric values in comparisons.

```python
# INSECURE - String comparison
"80" > "9"   # False (lexicographic comparison)

# SECURE - Numeric comparison  
80 > 9       # True (numeric comparison)
```

**Attack Vector**: Attackers submit string values to bypass numeric threshold checks.

**Solution**: All trustScores are normalized to float values, preventing type confusion.

### 2. Special Numeric Values (HIGH SEVERITY)

**Vulnerability**: Infinity, NaN, and boolean values can bypass security checks.

```python
# Attack examples
trustScore = float('inf')  # Always passes > X checks
trustScore = float('nan')  # Makes all comparisons false
trustScore = True          # Treated as 1 in numeric context
```

**Solution**: Explicit validation rejects Infinity, NaN, and boolean values.

### 3. Injection Attacks (CRITICAL SEVERITY)

**Vulnerability**: Unvalidated input could contain malicious payloads.

**Attack Vectors**:
- SQL Injection: `role = "admin'; DROP TABLE users;--"`
- XSS: `name = "<script>alert(document.cookie)</script>"`
- Command Injection: `dept = "IT; rm -rf /"`
- Path Traversal: `file = "../../../etc/passwd"`

**Solution**: Input validation rejects patterns matching known attack vectors.

### 4. Denial of Service (MEDIUM SEVERITY)

**Vulnerability**: Large or deeply nested JSON can exhaust resources.

**Attack Vectors**:
- Oversized payloads (>1MB)
- Deeply nested JSON (>100 levels)
- Extremely long strings

**Solution**: Size and depth limits with early rejection.

### 5. Role Impersonation (HIGH SEVERITY)

**Vulnerability**: Agents claiming high-privilege roles without verification.

**Attack Vector**: `role = "admin"` or `role = "doctor"` to gain elevated access.

**Solution**: Role validation with logging of high-privilege role claims.

## Implementation Architecture

### Security Validation Module

```python
vault/
├── utils/
│   ├── security/
│   │   ├── __init__.py
│   │   ├── validators.py      # Core validation logic
│   │   ├── runtime_bypass.py  # Emergency bypass API
│   │   └── monitoring.py      # Performance tracking
│   └── security_validators.py  # Legacy compatibility layer
```

### Migration Strategy

1. **New Module**: Create `vault.utils.security` with proper validation
2. **Compatibility Layer**: Existing code continues to work during migration
3. **Feature Flags**: Runtime configuration for validation behavior
4. **Monitoring**: Track validation performance and failures

## Runtime Emergency Bypass API

For critical situations requiring validation bypass:

```python
from vault.utils.security import bypass_validation

# Temporary bypass with reason logging
with bypass_validation(reason="Emergency fix for production issue #123"):
    # Validation is relaxed here
    result = process_agent_context(context)
```

## Security Test Suite

### Attack Simulation Tests

Located in `tests/security/`:
- `test_type_confusion.py` - String vs numeric attacks
- `test_injection_attacks.py` - SQL, XSS, command injection
- `test_dos_attacks.py` - Large payload, deep nesting
- `test_special_values.py` - Infinity, NaN, boolean attacks
- `test_role_impersonation.py` - Privilege escalation attempts

### Running Security Tests

```bash
# Run all security tests
pytest tests/security/ -v

# Run specific attack category
pytest tests/security/test_injection_attacks.py -v

# Run with performance monitoring
MONITOR_PERFORMANCE=1 pytest tests/security/ -v
```

## Performance Monitoring

### Metrics Tracked

- Validation time per request
- Memory usage for large payloads
- Cache hit rates
- Rejection rates by attack type

### Accessing Metrics

```python
from vault.utils.security import get_validation_metrics

metrics = get_validation_metrics()
print(f"Average validation time: {metrics['avg_time_ms']}ms")
print(f"Requests rejected: {metrics['rejection_rate']}%")
```

## Breaking Changes

### For API Consumers

1. **String trustScores**: Now converted to float
   - Before: `{"trustScore": "80"}` returns `"80"`
   - After: `{"trustScore": "80"}` returns `80.0`

2. **Invalid Input**: Now rejected instead of logged
   - Before: SQL injection logged but processed
   - After: SQL injection causes validation error

3. **Error Messages**: More specific for security
   - Before: "role must be a string"
   - After: "role is required" or "role must be string type"

### Migration Guide

```python
# Old code expecting string trustScore
if context['trustScore'] > "70":  # BROKEN

# New code with numeric trustScore  
if context['trustScore'] > 70:    # CORRECT

# Handle validation errors
try:
    validated = validate_agent_context(context)
except SecurityValidationError as e:
    # Handle validation failure
    log.error(f"Validation failed: {e}")
```

## Security Principles

1. **Fail Secure**: When in doubt, reject the input
2. **Defense in Depth**: Multiple validation layers
3. **Least Privilege**: Default to minimal permissions
4. **Audit Everything**: Log security-relevant events
5. **Performance Matters**: Security shouldn't break usability

## Future Enhancements

1. **Machine Learning**: Detect anomalous patterns
2. **Rate Limiting**: Prevent brute force attacks
3. **Cryptographic Signatures**: Verify agent identity
4. **Zero Trust**: Validate every request fully

## Contact

For security concerns or questions, contact the Marvis Vault security team.