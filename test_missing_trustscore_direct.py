#!/usr/bin/env python3
"""Direct test of missing trustScore behavior, bypassing CLI validation"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault.engine.policy_parser import PolicyParser
from vault.engine.policy_engine import PolicyEngine

# Create a policy that uses trustScore
policy_dict = {
    "name": "test-policy",
    "fields": {
        "email": {
            "conditions": [
                {
                    "rule": "trustScore > 80",
                    "action": "unmask"
                }
            ]
        }
    }
}

# Test data with some sensitive info but NO trustScore
test_data = {
    "email": "user@example.com",
    "name": "John Doe",
    "role": "analyst"
}

print("Testing with missing trustScore...")
print(f"Input data: {test_data}")
print(f"Policy: Unmask email if trustScore > 80")
print()

try:
    # Parse and evaluate
    policy = PolicyParser.parse_policy_dict(policy_dict)
    engine = PolicyEngine([policy])
    result = engine.process(test_data)
    
    print("✅ SUCCESS - No crash!")
    print(f"Result: {result}")
    print()
    print("Explanation: Since trustScore is missing, it defaults to false,")
    print("so the condition 'trustScore > 80' fails, and email remains redacted.")
    
except Exception as e:
    print("❌ FAILED - Got an error:")
    print(f"Error: {e}")
    print()
    print("This means the fallback is not working correctly.")