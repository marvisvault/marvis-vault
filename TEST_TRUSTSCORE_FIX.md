# Testing the TrustScore Missing Fallback Fix

## Overview
This test verifies that the system now properly handles missing `trustScore` values by defaulting to safe behavior (redacting sensitive data) instead of crashing or exposing data.

## What Was Fixed
- **Bug**: When `trustScore` was missing from the context, sensitive data was exposed instead of being redacted
- **Fix**: Missing `trustScore` now causes conditions to fail safely, resulting in data redaction
- **Security**: The system now follows "fail-closed" principle - when uncertain, protect the data

## Quick Test (Python)

Run this test to verify the fix is working:

```bash
python tests/test_redaction_fallback.py
```

### Expected Output:
```
Test 1: Context WITHOUT trustScore
Result: {
  "email": "[REDACTED]",
  "ssn": "[REDACTED]"
}
✅ GOOD: Sensitive data is redacted when trustScore is missing

Test 2: Context WITH high trustScore  
Result: {
  "email": "john@example.com",
  "ssn": "123-45-6789"
}
✅ GOOD: Data is visible when trustScore condition is met

Test 3: Admin role WITHOUT trustScore
Result: {
  "email": "john@example.com",
  "ssn": "123-45-6789"  
}
✅ GOOD: Admin can see data even without trustScore
```

## CLI Test (if using updated CLI)

### Setup Test Files:
```bash
# Create test data with sensitive info
echo {"name": "John Doe", "email": "john@example.com", "ssn": "123-45-6789"} > test_data.json

# Create policy requiring trustScore > 80
echo {"mask": ["email", "ssn"], "unmask_roles": ["admin"], "conditions": ["trustScore > 80"]} > test_policy.json

# Create agents for testing
echo {"role": "user"} > agent_no_trust.json
echo {"role": "user", "trustScore": 85} > agent_with_trust.json
echo {"role": "admin"} > agent_admin.json
```

### Run Tests:
```bash
# Test 1: Missing trustScore - should REDACT sensitive fields
vault redact -i test_data.json -p test_policy.json -g agent_no_trust.json

# Test 2: High trustScore - should NOT redact
vault redact -i test_data.json -p test_policy.json -g agent_with_trust.json

# Test 3: Admin role - should NOT redact (even without trustScore)
vault redact -i test_data.json -p test_policy.json -g agent_admin.json
```

## Manual Verification (SDK)

Create a file `verify_fix.py`:

```python
from vault.sdk.redact import redact
import json

# Test data
data = '{"email": "secret@example.com", "ssn": "123-45-6789", "status": "active"}'
policy = {
    "mask": ["email", "ssn"],
    "unmask_roles": ["admin"],
    "conditions": ["trustScore > 80"]
}

print("=== TrustScore Fallback Test ===\n")

# Scenario 1: Missing trustScore (THE BUG CASE)
print("1. User role WITHOUT trustScore:")
result = redact(data, policy, {"role": "user"})
parsed = json.loads(result.content)
print(f"   Email: {parsed['email']}")
print(f"   SSN: {parsed['ssn']}")
print(f"   Status: {parsed['status']}")
if parsed['email'] == '[REDACTED]':
    print("   ✓ PASS - Data is safely redacted when trustScore is missing\n")
else:
    print("   ✗ FAIL - Security issue! Data exposed without trustScore\n")

# Scenario 2: With high trustScore
print("2. User role WITH trustScore > 80:")
result = redact(data, policy, {"role": "user", "trustScore": 85})
parsed = json.loads(result.content)
print(f"   Email: {parsed['email']}")
if parsed['email'] != '[REDACTED]':
    print("   ✓ PASS - Data visible with high trustScore\n")

# Scenario 3: Admin role
print("3. Admin role WITHOUT trustScore:")
result = redact(data, policy, {"role": "admin"})
parsed = json.loads(result.content)
print(f"   Email: {parsed['email']}")
if parsed['email'] != '[REDACTED]':
    print("   ✓ PASS - Admin can access data regardless of trustScore")
```

Run with:
```bash
python verify_fix.py
```

## What Success Looks Like

✅ **The fix is working if:**
1. Missing `trustScore` → sensitive fields show as `[REDACTED]`
2. `trustScore > 80` → sensitive fields are visible
3. Admin role → can see data even without `trustScore`
4. No crashes or errors when `trustScore` is missing

❌ **The bug still exists if:**
- Missing `trustScore` → sensitive data is visible (security issue!)
- System crashes with "Context key 'trustScore' not found" error

## Technical Details

The fix was implemented in `vault/sdk/redact.py`:
- Added proper role-based checks
- Implemented safe condition evaluation that defaults to "deny" on errors
- When `trustScore` is missing, conditions fail → data gets redacted

This ensures the system follows security best practices: when in doubt, protect the data.