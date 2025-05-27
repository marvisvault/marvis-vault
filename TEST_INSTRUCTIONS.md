# Test Instructions for Marvis Vault Security Updates

## Prerequisites

Make sure you're in the project directory and have activated your virtual environment:

```bash
cd C:\Users\M\Documents\marvis-vault-oss
.venv\Scripts\activate
```

## 1. Run All Security Tests

Run the complete security test suite:

```bash
python -m pytest tests/security/ -v
```

## 2. Test Original GitHub Issues

### Test Bug #7: Malformed Agent Validation

Run the updated secure version of the malformed agent tests:

```bash
python -m pytest tests/test_malformed_agent_fix_secure.py -v
```

To see how the original tests fail (expected - they expect insecure behavior):

```bash
python -m pytest tests/test_malformed_agent_fix.py -v
```

### Test Bug #8: Missing trustScore Fallback

Test that missing trustScore is properly handled:

```bash
python -m pytest tests/test_redaction_fallback.py -v
```

## 3. Test Specific Security Vulnerabilities

### Type Confusion Tests

```bash
python -m pytest tests/security/test_type_confusion.py -v
```

### Injection Attack Tests

```bash
python -m pytest tests/security/test_injection_attacks.py -v
```

### DoS Protection Tests

```bash
python -m pytest tests/security/test_dos_attacks.py -v
```

### Special Values Tests (Infinity, NaN, Boolean)

```bash
python -m pytest tests/security/test_special_values.py -v
```

### Runtime Bypass API Tests

```bash
python -m pytest tests/security/test_runtime_bypass.py -v
```

### Performance Monitoring Tests

```bash
python -m pytest tests/security/test_performance_monitoring.py -v
```

## 4. Quick Security Verification

Create and run this quick verification script:

```bash
echo "from vault.cli.simulate import load_agent_context; import json, tempfile; from pathlib import Path; f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False); json.dump({'role': 'user', 'trustScore': '80'}, f); f.close(); result = load_agent_context(Path(f.name)); print(f'String trustScore test: {"PASS" if isinstance(result["trustScore"], float) else "FAIL"}'); Path(f.name).unlink()" | python
```

Test SQL injection blocking:

```bash
echo "from vault.cli.simulate import load_agent_context; import json, tempfile; from pathlib import Path; f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False); json.dump({'role': 'admin\'; DROP TABLE users;--', 'trustScore': 90}, f); f.close(); try: load_agent_context(Path(f.name)); print('FAIL: SQL injection accepted'); except ValueError as e: print(f'PASS: SQL injection blocked: {e}'); finally: Path(f.name).unlink()" | python
```

Test Infinity rejection:

```bash
echo "from vault.cli.simulate import load_agent_context; import json, tempfile; from pathlib import Path; f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False); json.dump({'role': 'admin', 'trustScore': 'Infinity'}, f); f.close(); try: load_agent_context(Path(f.name)); print('FAIL: Infinity accepted'); except ValueError as e: print(f'PASS: Infinity blocked: {e}'); finally: Path(f.name).unlink()" | python
```

## 5. CLI Integration Tests

Test the vault CLI with malformed input:

```bash
echo {"role": "user", "trustScore": "eighty"} > bad_agent.json && vault simulate --agent bad_agent.json --policy templates/pii-basic.json 2>&1 | findstr /C:"must be numeric" && del bad_agent.json
```

Test with SQL injection:

```bash
echo {"role": "admin'; DROP TABLE users;--", "trustScore": 80} > sql_inject.json && vault simulate --agent sql_inject.json --policy templates/pii-basic.json 2>&1 | findstr /C:"SQL" && del sql_inject.json
```

## 6. Performance Test

Run this to see validation performance:

```bash
python -c "from vault.utils.security import validate_agent_context, get_validation_metrics, reset_metrics; import time; reset_metrics(); start=time.time(); [validate_agent_context({'role': f'user{i}', 'trustScore': i%101}) for i in range(1000)]; print(f'1000 validations in {time.time()-start:.2f}s'); print(get_validation_metrics()['timing'])"
```

## 7. Emergency Bypass Test

Test the runtime bypass API:

```bash
python -c "from vault.utils.security import bypass_validation, validate_role; dangerous='admin\'; DROP TABLE--'; print('Without bypass:'); try: validate_role(dangerous); print('FAIL'); except: print('PASS: Blocked'); print('\nWith bypass:'); from contextlib import redirect_stdout; import os; with redirect_stdout(open(os.devnull, 'w')): with bypass_validation('Test'): r=validate_role(dangerous); print(f'PASS: Allowed ({r})')"
```

## 8. Run All Tests with Coverage

To see test coverage:

```bash
python -m pytest --cov=vault --cov-report=term-missing -v
```

## Expected Results

- **Type Confusion Tests**: All should pass (10 tests)
- **Injection Tests**: Most should pass (some SQL patterns may need refinement)
- **DoS Tests**: All should pass
- **Special Values Tests**: All should pass
- **Bypass Tests**: All should pass
- **Performance Tests**: All should pass

## Troubleshooting

If imports fail:

```bash
python -c "from vault.utils.security import validate_agent_context; print('Import successful')"
```

If tests can't find modules:

```bash
set PYTHONPATH=%CD% && python -m pytest tests/security/ -v
```

To see which security module is being used:

```bash
python -c "from vault.utils.security_validators import _NEW_MODULE_AVAILABLE; print(f'New security module active: {_NEW_MODULE_AVAILABLE}')"
```

## Summary

The security updates successfully address:
- [x] Bug #7: Malformed agents now properly rejected
- [x] Bug #8: Missing trustScore triggers safe redaction
- [x] Type confusion vulnerability fixed
- [x] Special values (Infinity/NaN/Boolean) blocked
- [x] SQL injection protection (with some patterns needing refinement)
- [x] DoS protection via size/depth limits
- [x] Performance monitoring implemented
- [x] Emergency bypass API available

Note: Some original tests will fail because they expect insecure behavior. Use the secure versions (test_malformed_agent_fix_secure.py) for accurate results.