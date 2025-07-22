#!/usr/bin/env python3
"""Test case to verify behavior when trustScore is missing from context

This test demonstrates the bug fix:
- BEFORE: Missing trustScore would throw a ValueError
- AFTER: Missing trustScore defaults to False (safe fallback)
"""

# NOTE: This requires the package to be installed with dependencies
# Run: pip install -e . 
# before running this test

from vault.engine.policy_engine import PolicyEngine
from vault.engine.policy_parser import PolicyParser

# Test policy that uses trustScore
policy_json = """
{
    "name": "trust-based-policy",
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
"""

# Test data WITHOUT trustScore
test_data = {
    "email": "user@example.com",
    "name": "John Doe"
}

# Parse policy and create engine
policy = PolicyParser.parse_policy_json(policy_json)
engine = PolicyEngine([policy])

# Process the data
result = engine.process(test_data)
print("Original data:", test_data)
print("Processed result:", result)
print("\nNote: If email is masked, it means the fallback is working (masking when trustScore is missing)")