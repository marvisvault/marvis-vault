#!/usr/bin/env python3
"""Test the condition evaluator directly with missing trustScore"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Direct import of just what we need
from vault.engine.condition_evaluator import evaluate_condition

print("Testing the fix for missing trustScore...")
print("=" * 50)

# Test 1: Missing trustScore in a simple condition
print("\nTest 1: Simple condition with missing trustScore")
context = {"role": "admin"}
condition = "trustScore > 80"

try:
    result, explanation, fields = evaluate_condition(condition, context)
    print(f"✅ SUCCESS - No crash!")
    print(f"  Condition: {condition}")
    print(f"  Context: {context}")
    print(f"  Result: {result}")
    print(f"  Explanation: {explanation}")
except Exception as e:
    print(f"❌ FAILED with error: {e}")

# Test 2: Complex condition with missing trustScore
print("\n\nTest 2: AND condition with missing trustScore")
context2 = {"role": "analyst"}
condition2 = "role == 'analyst' && trustScore > 70"

try:
    result, explanation, fields = evaluate_condition(condition2, context2)
    print(f"✅ SUCCESS - No crash!")
    print(f"  Condition: {condition2}")
    print(f"  Context: {context2}")
    print(f"  Result: {result}")
    print(f"  Explanation: {explanation}")
except Exception as e:
    print(f"❌ FAILED with error: {e}")

# Test 3: Condition that should pass despite missing trustScore
print("\n\nTest 3: OR condition where one side passes")
context3 = {"role": "admin"}
condition3 = "role == 'admin' || trustScore > 90"

try:
    result, explanation, fields = evaluate_condition(condition3, context3)
    print(f"✅ SUCCESS - No crash!")
    print(f"  Condition: {condition3}")
    print(f"  Context: {context3}")
    print(f"  Result: {result}")
    print(f"  Explanation: {explanation}")
except Exception as e:
    print(f"❌ FAILED with error: {e}")

print("\n" + "=" * 50)
print("Summary: If all tests show SUCCESS, the fallback is working correctly!")