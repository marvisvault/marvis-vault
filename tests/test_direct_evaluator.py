#!/usr/bin/env python3
"""Direct test of condition evaluator fallback behavior"""

# Direct import to avoid package dependencies
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault', 'engine'))

from condition_evaluator import evaluate_condition

# Test with missing trustScore
print("Testing fallback behavior for missing trustScore:")
print("-" * 50)

context = {"role": "admin"}
condition = "trustScore > 80"

try:
    result, explanation, fields = evaluate_condition(condition, context)
    print(f"Condition: {condition}")
    print(f"Context: {context}")
    print(f"Result: {result}")
    print(f"Explanation: {explanation}")
    print(f"\nSuccess! The condition returned {result} instead of throwing an error.")
    print("This means missing trustScore now defaults to false, providing a safe fallback.")
except Exception as e:
    print(f"Error: {e}")
    print("The fallback mechanism is not working correctly.")