# TrustScore Missing Fallback Fix

## Test Files Created

This fix includes several test files to verify the behavior:

### 1. `tests/test_direct_evaluator.py`
- **Purpose**: Quick standalone test that directly imports and tests the condition evaluator
- **What it tests**: Verifies that missing trustScore returns False instead of throwing an error
- **Run with**: `python3 tests/test_direct_evaluator.py`
- **No dependencies required** - can run without installing the package

### 2. `tests/test_trustscore_fallback.py`
- **Purpose**: More comprehensive test showing multiple scenarios
- **What it tests**:
  - Simple missing trustScore condition
  - Complex AND conditions with missing trustScore
  - OR conditions where one side can still pass
- **Run with**: `python3 tests/test_trustscore_fallback.py`
- **Shows the fallback behavior in different scenarios**

### 3. `tests/test_trustscore_missing.py`
- **Purpose**: Integration test using the full PolicyEngine
- **What it tests**: End-to-end behavior when processing data with missing trustScore through the policy engine
- **Run with**: `python3 tests/test_trustscore_missing.py`
- **Requires**: Package installed with `pip install -e .`

### 4. `tests/test_missing_context_fallback.py`
- **Purpose**: Comprehensive pytest suite for the fallback mechanism
- **What it tests**:
  - Missing trustScore with simple conditions
  - Missing trustScore with AND/OR operators
  - Missing fields in comparisons
  - Numeric comparisons with missing values
  - Multiple missing values
  - Verifies existing behavior still works
- **Run with**: `pytest tests/test_missing_context_fallback.py -v`
- **This is the main test file for CI/CD integration**

## Bug Description
When `trustScore` (or any other context variable) was missing from the context, the condition evaluator would throw a `ValueError`, causing the entire evaluation to fail with an error rather than gracefully handling the missing value.

## Fix Implementation
Fixed `vault/sdk/redact.py` to properly handle missing context values:

### The Real Issue:
1. The `evaluate` function call at line 257 was broken (wrong function signature)
2. When evaluation failed, it returned WITHOUT redaction (security issue!)
3. Missing role-based permission checks

### Changes Made in `redact.py`:
```python
# BEFORE (line 257-259):
eval_result = evaluate(policy, context)  # Wrong signature!
if not eval_result.get("status", False):
    return result  # No redaction - EXPOSES data!

# AFTER:
# 1. Check unmask_roles first
if user_role in policy.get("unmask_roles", []):
    return result  # Admin/privileged role - no redaction

# 2. Evaluate conditions properly using condition_evaluator
for condition in policy["conditions"]:
    try:
        if evaluate_condition(condition, context):
            return result  # Condition passed - no redaction
    except:
        continue  # Missing values = condition fails

# 3. If we get here, proceed with redaction (safe default)
```

### Key Improvements:
1. Role-based access works even without trustScore
2. Missing trustScore causes conditions to fail → data gets redacted (safe)
3. No crashes or confusing errors
4. Proper fail-safe behavior

## Test Results
Running `test_direct_evaluator.py` shows the fix working:
```
Condition: trustScore > 80
Context: {'role': 'admin'}
Result: False
Explanation: trustScore false (missing) > 80.0
```

## Impact
- **Security**: Safe by default - missing trustScore means no access (fails closed)
- **Compatibility**: Existing behavior with all values present remains unchanged
- **User Experience**: No more crashes when context values are missing
- **Auditability**: Clear indication in explanation when values are missing

## Example Scenarios

### Before Fix:
```python
context = {"role": "admin"}  # trustScore missing
condition = "trustScore > 80"
# Would throw: ValueError: Context key 'trustScore' not found
```

### After Fix:
```python
context = {"role": "admin"}  # trustScore missing
condition = "trustScore > 80"
# Returns: (False, "trustScore false (missing) > 80.0", ["trustScore"])
```

## Recommendation
This fix provides a secure fallback (deny access when uncertain) while preventing crashes. Consider adding a configuration option in the future to customize this behavior if needed.