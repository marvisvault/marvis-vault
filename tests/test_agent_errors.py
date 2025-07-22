#!/usr/bin/env python3
"""Show actual error messages for malformed agents"""

from vault.cli.agent_validator import validate_agent_context

print("Demonstrating agent validation error messages:")
print("=" * 60)

test_cases = [
    ("Valid agent", {"role": "user", "trustScore": 80}),
    ("Missing role", {"trustScore": 80}),
    ("Empty role", {"role": ""}),
    ("Non-string role", {"role": 123}),
    ("Invalid trustScore", {"role": "user", "trustScore": "high"}),
    ("TrustScore too high", {"role": "user", "trustScore": 150}),
    ("Negative trustScore", {"role": "user", "trustScore": -10}),
]

for name, agent in test_cases:
    print(f"\nTest: {name}")
    print(f"Agent: {agent}")
    try:
        validate_agent_context(agent)
        print("PASS: Valid agent")
    except ValueError as e:
        print(f"FAIL: Validation error: {e}")

print("\n" + "=" * 60)
print("Special case - simulate requires trustScore:")
print("=" * 60)

agent_no_trust = {"role": "admin"}
print(f"\nAgent: {agent_no_trust}")

try:
    validate_agent_context(agent_no_trust, require_trustscore=False)
    print("PASS: Valid for redact command (trustScore optional)")
except ValueError as e:
    print(f"FAIL: Error: {e}")

try:
    validate_agent_context(agent_no_trust, require_trustscore=True)
    print("PASS: Valid for simulate command")
except ValueError as e:
    print(f"FAIL: Error for simulate: {e}")