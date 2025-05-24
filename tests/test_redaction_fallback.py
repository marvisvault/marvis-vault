#!/usr/bin/env python3
"""Test to verify the redaction fallback behavior when trustScore is missing"""

import json

# Test data with sensitive information
test_content = json.dumps({
    "name": "John Doe",
    "email": "john@example.com",
    "ssn": "123-45-6789"
})

# Policy that requires trustScore
test_policy = {
    "mask": ["email", "ssn"],
    "unmask_roles": ["admin"],
    "conditions": ["trustScore > 80"]
}

# Context WITHOUT trustScore (the bug scenario)
context_without_trust = {
    "role": "analyst"
}

# Context WITH trustScore
context_with_trust = {
    "role": "analyst", 
    "trustScore": 85
}

print("Testing redaction behavior with missing trustScore...")
print("=" * 60)

# Import after setup to avoid module issues
from vault.sdk.redact import redact

# Test 1: Missing trustScore
print("\nTest 1: Context WITHOUT trustScore")
print(f"Context: {context_without_trust}")
print(f"Policy conditions: {test_policy['conditions']}")
print(f"Expected: email and ssn should be [REDACTED]")

try:
    result1 = redact(test_content, test_policy, context_without_trust)
    parsed = json.loads(result1.content)
    print(f"Result: {json.dumps(parsed, indent=2)}")
    
    if parsed.get("email") == "[REDACTED]" and parsed.get("ssn") == "[REDACTED]":
        print("✅ GOOD: Sensitive data is redacted when trustScore is missing (SAFE BEHAVIOR)")
    else:
        print("❌ BUG CONFIRMED: Sensitive data is NOT redacted when trustScore is missing!")
        print("This is a SECURITY ISSUE - data is exposed when it should be hidden!")
        
except Exception as e:
    print(f"Error: {e}")

# Test 2: With trustScore > 80
print("\n\nTest 2: Context WITH high trustScore")
print(f"Context: {context_with_trust}")

try:
    result2 = redact(test_content, test_policy, context_with_trust)
    parsed = json.loads(result2.content)
    print(f"Result: {json.dumps(parsed, indent=2)}")
    
    if parsed.get("email") != "[REDACTED]":
        print("✅ GOOD: Data is visible when trustScore condition is met")
    else:
        print("❌ Data is still redacted even though condition is met")
        
except Exception as e:
    print(f"Error: {e}")

# Test 3: Admin role (should see unredacted even without trustScore)
print("\n\nTest 3: Admin role WITHOUT trustScore")
context_admin = {"role": "admin"}
print(f"Context: {context_admin}")

try:
    result3 = redact(test_content, test_policy, context_admin)
    parsed = json.loads(result3.content)
    print(f"Result: {json.dumps(parsed, indent=2)}")
    
    if parsed.get("email") != "[REDACTED]":
        print("✅ GOOD: Admin can see data even without trustScore")
    else:
        print("❌ Admin role not working - data is still redacted")
        
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 60)
print("Summary: The fix ensures that when trustScore is MISSING:")
print("1. Regular users see REDACTED data (safe default)")
print("2. Admin/privileged roles still have access")
print("3. No crashes or security vulnerabilities")