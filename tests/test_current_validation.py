#!/usr/bin/env python3
"""Test current validation behavior to understand the problem"""

import json
import tempfile
from pathlib import Path

# Test the current validation in simulate.py
from vault.cli.simulate import load_agent_context as simulate_load

print("Testing CURRENT validation behavior")
print("=" * 60)

# Test cases that should fail
test_cases = [
    ("Not a dict", '"just a string"', "Should fail - not a JSON object"),
    ("Missing role", '{"trustScore": 80}', "Should fail - no role"),
    ("Missing trustScore", '{"role": "user"}', "Should fail for simulate - no trustScore"),
    ("Non-string role", '{"role": 123, "trustScore": 80}', "Currently PASSES - no type check"),
    ("String trustScore", '{"role": "user", "trustScore": "80"}', "Currently might PASS - converts to float"),
    ("Invalid trustScore", '{"role": "user", "trustScore": "high"}', "Should fail - not numeric"),
    ("Negative trustScore", '{"role": "user", "trustScore": -10}', "Currently PASSES - no range check"),
    ("Too high trustScore", '{"role": "user", "trustScore": 150}', "Currently PASSES - no range check"),
    ("Null role", '{"role": null, "trustScore": 80}', "Currently PASSES - no null check"),
    ("Empty role", '{"role": "", "trustScore": 80}', "Currently PASSES - no empty check"),
]

print("\nTesting simulate.py validation:")
print("-" * 60)

for name, content, expected in test_cases:
    print(f"\nTest: {name}")
    print(f"Input: {content}")
    print(f"Expected: {expected}")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(content)
        temp_path = Path(f.name)
    
    try:
        result = simulate_load(temp_path)
        print(f"Result: FAIL - PASSED (loaded successfully)")
        print(f"Loaded context: {result}")
    except Exception as e:
        print(f"Result: PASS - FAILED with error: {e}")
    finally:
        temp_path.unlink()

print("\n" + "=" * 60)
print("Testing redact.py validation:")
print("(Currently has NO validation - just loads JSON)")
print("-" * 60)

# For redact, we need to check the current code manually
print("\nCurrent redact.py code just does:")
print("  agent_context = json.loads(agent.read_text())")
print("  # No validation at all!")
print("\nThis means ALL malformed agents (except invalid JSON) will be accepted!")