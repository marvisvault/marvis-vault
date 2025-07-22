#!/usr/bin/env python3
"""Test trustScore validation edge cases"""

import sys
sys.path.append('../../../')

from vault.cli.simulate import load_agent_context
from pathlib import Path
import json
import tempfile

test_cases = [
    # (trustScore value, should_pass, description)
    (100, True, "Maximum valid value"),
    (0, True, "Minimum valid value"),
    (50, True, "Middle value"),
    (99.9, True, "Decimal below 100"),
    (100.0, True, "100 as float"),
    (100.1, False, "Just over 100"),
    (101, False, "Over 100"),
    (150, False, "Way over 100"),
    (-1, False, "Just below 0"),
    (-10, False, "Negative"),
    (50.5, True, "Valid decimal"),
    ("80", True, "String number (should convert)"),
    ("100", True, "String 100 (should convert)"),
    ("101", False, "String over 100"),
    ("high", False, "Non-numeric string"),
    (None, True, "None/null is allowed"),
    (True, False, "Boolean true"),
    (False, False, "Boolean false"),
]

print("Testing trustScore validation edge cases")
print("=" * 60)

for value, should_pass, description in test_cases:
    print(f"\nTest: {description}")
    print(f"Value: {value} (type: {type(value).__name__})")
    
    agent = {"role": "user", "trustScore": value}
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(agent, f)
        temp_path = Path(f.name)
    
    try:
        result = load_agent_context(temp_path)
        if should_pass:
            print("PASS - Loaded successfully")
            print(f"  Loaded value: {result['trustScore']}")
        else:
            print("FAIL - Should have been rejected but wasn't!")
    except ValueError as e:
        if not should_pass:
            print(f"PASS - Correctly rejected: {e}")
        else:
            print(f"FAIL - Should have passed but got: {e}")
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}")
    finally:
        temp_path.unlink()

print("\n" + "=" * 60)
print("Summary: trustScore validation should:")
print("- Accept: 0-100 (inclusive), decimals, string numbers, None")
print("- Reject: <0, >100, non-numeric strings, booleans")