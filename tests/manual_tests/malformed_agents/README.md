# Malformed Agent Validation Tests

This directory contains tests for Issue #7: CLI silently proceeds on malformed agent input.

## Quick Test

Run all tests:
```bash
cd tests/manual_tests/malformed_agents
bash test_malformed_agents.sh
```

## Manual Testing

If you want to test individual cases:

```bash
cd tests/manual_tests/malformed_agents

# Create a malformed agent
echo '{"role": 123, "trustScore": 80}' > bad_agent.json

# Test with simulate (requires trustScore)
vault simulate --agent bad_agent.json --policy ../../../vault/templates/pii-basic.json

# Test with redact (trustScore optional)
echo '{"email": "test@example.com"}' > data.json
vault redact -i data.json -p ../../../vault/templates/pii-basic.json -g bad_agent.json
```

## Expected Errors

You should see clear error messages like:
- "Error: Invalid agent - Agent file is empty"
- "Error: Invalid agent - Agent 'role' must be a string, got int"
- "Error: Invalid agent - trustScore must be between 0-100, got 150"

## Cleanup

Remove test files:
```bash
rm *.json
```