# CLI Test Instructions for Marvis Vault Security Updates

## Prerequisites

Ensure you have Python 3.10+ and the required dependencies installed:

```bash
pip install -e ".[dev]"
```

## 1. Test Original GitHub Issues

### Bug #7: CLI silently proceeds on malformed agent input

```bash
# Test that malformed agents are now rejected with clear errors
echo '{"trustScore": "eighty"}' > test_malformed.json
vault simulate --agent test_malformed.json --policy examples/agents/agent.json

# Expected: Error message "agent must contain 'role' field"

# Test non-numeric trustScore
echo '{"role": "user", "trustScore": "high"}' > test_non_numeric.json
vault simulate --agent test_non_numeric.json --policy examples/agents/agent.json

# Expected: Error message "agent trustScore must be numeric"

# Test boolean trustScore
echo '{"role": "user", "trustScore": true}' > test_boolean.json
vault simulate --agent test_boolean.json --policy examples/agents/agent.json

# Expected: Error message "agent trustScore cannot be a boolean"
```

### Bug #8: No redaction fallback when trustScore is missing

```bash
# Test that missing trustScore leads to safe redaction
echo '{"role": "viewer"}' > test_no_score.json
echo '{"name": "John Doe", "ssn": "123-45-6789"}' > test_data.json

vault redact --input test_data.json --agent test_no_score.json --policy templates/pii-basic.json

# Expected: SSN should be redacted (shown as [REDACTED])
# Without fix: SSN would be exposed
```

## 2. Test Security Vulnerabilities

### Type Confusion Attack

```bash
# String trustScore that would bypass numeric comparison
echo '{"role": "user", "trustScore": "80"}' > test_string_score.json
vault simulate --agent test_string_score.json --policy examples/agents/agent.json

# Expected: trustScore shown as 80.0 (float), not "80" (string)
```

### Special Numeric Values

```bash
# Test Infinity
echo '{"role": "admin", "trustScore": "Infinity"}' > test_infinity.json
vault simulate --agent test_infinity.json --policy examples/agents/agent.json

# Expected: Error "agent trustScore cannot be Infinity"

# Test NaN
echo '{"role": "admin", "trustScore": "NaN"}' > test_nan.json
vault simulate --agent test_nan.json --policy examples/agents/agent.json

# Expected: Error "agent trustScore cannot be NaN"
```

### Injection Attacks

```bash
# SQL injection in role
echo '{"role": "admin'\''; DROP TABLE users;--", "trustScore": 90}' > test_sql.json
vault simulate --agent test_sql.json --policy examples/agents/agent.json

# Expected: Error "agent role contains potential SQL injection"

# XSS in role
echo '{"role": "<script>alert(1)</script>", "trustScore": 80}' > test_xss.json
vault simulate --agent test_xss.json --policy examples/agents/agent.json

# Expected: Error "agent role contains potential XSS tag injection"

# Command injection
echo '{"role": "user; rm -rf /", "trustScore": 70}' > test_cmd.json
vault simulate --agent test_cmd.json --policy examples/agents/agent.json

# Expected: Error "agent role contains potential Shell metacharacters"
```

### DoS Protection

```bash
# Create large payload (over 1MB)
python -c "import json; json.dump({'role': 'user', 'trustScore': 80, 'data': 'x' * (1024*1024 + 1)}, open('test_large.json', 'w'))"
vault simulate --agent test_large.json --policy examples/agents/agent.json

# Expected: Error "agent too large"

# Create deeply nested JSON
python -c "
import json
def nest(n): return {'n': nest(n-1)} if n > 0 else 'end'
json.dump({'role': 'user', 'trustScore': 80, 'deep': nest(101)}, open('test_deep.json', 'w'))
"
vault simulate --agent test_deep.json --policy examples/agents/agent.json

# Expected: Error about nesting depth
```

## 3. Test Runtime Bypass API

```bash
# Create a test script that uses bypass
cat > test_bypass.py << 'EOF'
from vault.utils.security import bypass_validation, validate_role

# This would normally fail
dangerous_role = "admin'; DROP TABLE users;--"

try:
    validate_role(dangerous_role)
    print("ERROR: Should have failed without bypass")
except:
    print("PASS: Validation correctly rejected dangerous input")

# With bypass
with bypass_validation("Emergency fix for production issue #123", user="admin"):
    result = validate_role(dangerous_role)
    print(f"PASS: With bypass, dangerous role accepted: {result}")

# After bypass ends
try:
    validate_role(dangerous_role)
    print("ERROR: Should have failed after bypass ended")
except:
    print("PASS: Validation correctly rejected after bypass")
EOF

python test_bypass.py
```

## 4. Test Performance Monitoring

```bash
# Run validation performance test
cat > test_performance.py << 'EOF'
from vault.utils.security import validate_agent_context, get_validation_metrics
import time

# Reset metrics
from vault.utils.security import reset_metrics
reset_metrics()

# Perform many validations
start = time.time()
for i in range(1000):
    context = {"role": f"user{i}", "trustScore": i % 101}
    validate_agent_context(context)

duration = time.time() - start

# Get metrics
metrics = get_validation_metrics()
print(f"Performed {metrics['total_validations']} validations in {duration:.2f}s")
print(f"Average time per validation: {metrics['timing']['avg_ms']:.2f}ms")
print(f"Slowest validation: {metrics['timing']['max_ms']:.2f}ms")
print(f"Rejection rate: {metrics['overall_rejection_rate']:.1f}%")
EOF

python test_performance.py
```

## 5. Run Full Test Suite

### Unit Tests

```bash
# Run security tests
pytest tests/security/ -v

# Run updated malformed agent tests
pytest tests/test_malformed_agent_fix_secure.py -v

# Run all tests
pytest -v
```

### Integration Tests

```bash
# Test real CLI with various attack vectors
for f in tests/security_hardening/test_*.json; do
    echo "Testing $f"
    vault simulate --agent "$f" --policy templates/pii-basic.json 2>&1 | head -2
done
```

## 6. Verify Backward Compatibility

```bash
# Test that normal usage still works
vault simulate --agent examples/agents/agent.json --policy templates/pii-basic.json

# Test redaction with valid agent
vault redact --input examples/before.json --agent examples/agents/agent.json --policy templates/healthcare.json --output test_output.json

# Verify output
cat test_output.json | jq .
```

## 7. Cleanup

```bash
# Remove test files
rm -f test_*.json test_*.py
```

## Expected Outcomes

1. **Security First**: All injection attempts should be rejected
2. **Type Safety**: String trustScores converted to float
3. **Clear Errors**: Specific error messages for each failure type
4. **Performance**: Sub-millisecond validation for normal inputs
5. **Monitoring**: Metrics available for operational monitoring
6. **Emergency Bypass**: Available but logged for audit

## Troubleshooting

If tests fail:

1. Check Python version: `python --version` (need 3.10+)
2. Reinstall: `pip install -e ".[dev]" --force-reinstall`
3. Check imports: `python -c "from vault.utils.security import validate_agent_context"`
4. Run with debug: `PYTHONPATH=. python -m vault.cli.main simulate ...`