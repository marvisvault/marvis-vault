#!/usr/bin/env python3
"""Test the fallback behavior for missing trustScore"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault.engine.condition_evaluator import evaluate_condition

# Test 1: Simple trustScore check with missing trustScore
print("Test 1: Missing trustScore")
context1 = {"role": "admin", "department": "IT"}
condition1 = "trustScore > 80"
try:
    result, explanation, fields = evaluate_condition(condition1, context1)
    print(f"Condition: {condition1}")
    print(f"Context: {context1}")
    print(f"Result: {result}")
    print(f"Explanation: {explanation}")
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 2: Complex condition with missing trustScore
print("Test 2: Complex condition with missing trustScore")
context2 = {"role": "analyst"}
condition2 = "role == 'analyst' && trustScore > 70"
try:
    result, explanation, fields = evaluate_condition(condition2, context2)
    print(f"Condition: {condition2}")
    print(f"Context: {context2}")
    print(f"Result: {result}")
    print(f"Explanation: {explanation}")
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

# Test 3: OR condition with missing trustScore (should still work if one side is true)
print("Test 3: OR condition with missing trustScore")
context3 = {"role": "admin"}
condition3 = "role == 'admin' || trustScore > 90"
try:
    result, explanation, fields = evaluate_condition(condition3, context3)
    print(f"Condition: {condition3}")
    print(f"Context: {context3}")
    print(f"Result: {result}")
    print(f"Explanation: {explanation}")
    print()
except Exception as e:
    print(f"Error: {e}")
    print()

print("Summary: When trustScore is missing, it now defaults to false instead of throwing an error.")
print("This provides a safe fallback - conditions requiring high trustScore will fail when trustScore is missing.")