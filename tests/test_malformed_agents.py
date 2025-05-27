#!/usr/bin/env python3
"""Test malformed agent validation fix"""

import json
import os

print("Testing malformed agent validation...")
print("=" * 60)

# Create test data
test_data = {"email": "test@example.com", "ssn": "123-45-6789"}
with open("test_data.json", "w") as f:
    json.dump(test_data, f)

# Create policy
policy = {
    "mask": ["email", "ssn"],
    "unmask_roles": ["admin"],
    "conditions": ["trustScore > 80"]
}
with open("test_policy.json", "w") as f:
    json.dump(policy, f)

# Test cases for malformed agents
test_cases = [
    ("Empty file", ""),
    ("Invalid JSON", "{invalid json"),
    ("Not an object", '"just a string"'),
    ("Missing role", '{"trustScore": 80}'),
    ("Empty role", '{"role": "", "trustScore": 80}'),
    ("Non-string role", '{"role": 123, "trustScore": 80}'),
    ("Invalid trustScore type", '{"role": "user", "trustScore": "high"}'),
    ("TrustScore out of range", '{"role": "user", "trustScore": 150}'),
    ("Negative trustScore", '{"role": "user", "trustScore": -10}'),
    ("Null values", '{"role": null, "trustScore": null}'),
]

print("\nTesting REDACT command with malformed agents:")
print("-" * 60)

for name, content in test_cases:
    print(f"\nTest: {name}")
    print(f"Content: {content}")
    
    # Write malformed agent file
    with open("malformed_agent.json", "w") as f:
        f.write(content)
    
    # Test with redact command
    result = os.system("vault redact -i test_data.json -p test_policy.json -g malformed_agent.json 2>&1")
    if result != 0:
        print("PASS: Command failed as expected (validation working)")
    else:
        print("FAIL: Command succeeded - validation NOT working!")

print("\n" + "=" * 60)
print("Testing SIMULATE command with malformed agents:")
print("-" * 60)

# Simulate requires trustScore, so test that specifically
simulate_cases = [
    ("Missing trustScore", '{"role": "user"}'),
    ("Null trustScore", '{"role": "user", "trustScore": null}'),
]

for name, content in simulate_cases:
    print(f"\nTest: {name}")
    print(f"Content: {content}")
    
    with open("malformed_agent.json", "w") as f:
        f.write(content)
    
    result = os.system("vault simulate --agent malformed_agent.json --policy test_policy.json 2>&1")
    if result != 0:
        print("PASS: Command failed as expected (validation working)")
    else:
        print("FAIL: Command succeeded - validation NOT working!")

# Cleanup
for f in ["test_data.json", "test_policy.json", "malformed_agent.json"]:
    if os.path.exists(f):
        os.remove(f)

print("\n" + "=" * 60)
print("Summary: Malformed agent files should now cause clear error messages")