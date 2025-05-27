#!/usr/bin/env python3
"""
Test CLI security features for assessment.
Demonstrates that the security hardening works correctly with CLI commands.
"""

import json
import os
import sys
import tempfile
import subprocess

def create_test_files():
    """Create test files for security testing."""
    test_dir = tempfile.mkdtemp()
    
    # Test 1: Valid agent
    valid_agent = {
        "role": "analyst",
        "trustScore": 85
    }
    with open(f"{test_dir}/valid_agent.json", "w") as f:
        json.dump(valid_agent, f)
    
    # Test 2: SQL injection in role
    sql_injection_agent = {
        "role": "admin' OR '1'='1",
        "trustScore": 100
    }
    with open(f"{test_dir}/sql_injection_agent.json", "w") as f:
        json.dump(sql_injection_agent, f)
    
    # Test 3: Type confusion - string trustScore
    type_confusion_agent = {
        "role": "user",
        "trustScore": "80"  # String instead of number
    }
    with open(f"{test_dir}/type_confusion_agent.json", "w") as f:
        json.dump(type_confusion_agent, f)
    
    # Test 4: Special values - boolean trustScore
    boolean_agent = {
        "role": "manager",
        "trustScore": True  # Boolean instead of number
    }
    with open(f"{test_dir}/boolean_agent.json", "w") as f:
        json.dump(boolean_agent, f)
    
    # Test 5: Missing trustScore (Bug #8)
    missing_trust_agent = {
        "role": "viewer"
        # trustScore missing - should fail safely
    }
    with open(f"{test_dir}/missing_trust_agent.json", "w") as f:
        json.dump(missing_trust_agent, f)
    
    # Test 6: Malformed JSON (Bug #7)
    with open(f"{test_dir}/malformed_agent.json", "w") as f:
        f.write('{"role": "user", "trustScore": }')  # Invalid JSON
    
    # Test 7: Command injection
    command_injection_agent = {
        "role": "user; rm -rf /",
        "trustScore": 50
    }
    with open(f"{test_dir}/command_injection_agent.json", "w") as f:
        json.dump(command_injection_agent, f)
    
    # Test 8: XSS attempt
    xss_agent = {
        "role": "user",
        "trustScore": 75,
        "description": "<script>alert('xss')</script>"
    }
    with open(f"{test_dir}/xss_agent.json", "w") as f:
        json.dump(xss_agent, f)
    
    # Test 9: Large payload (DoS)
    large_agent = {
        "role": "user",
        "trustScore": 80,
        "data": "x" * (11 * 1024 * 1024)  # 11MB string
    }
    with open(f"{test_dir}/large_agent.json", "w") as f:
        json.dump(large_agent, f)
    
    # Test 10: Infinity trustScore
    infinity_agent = {
        "role": "admin",
        "trustScore": float('inf')
    }
    # JSON can't serialize infinity, so write it manually
    with open(f"{test_dir}/infinity_agent.json", "w") as f:
        f.write('{"role": "admin", "trustScore": Infinity}')
    
    # Sample content and policy for testing
    content = {
        "message": "Patient John Doe has appointment at 555-1234",
        "sensitive": True
    }
    with open(f"{test_dir}/content.json", "w") as f:
        json.dump(content, f)
    
    policy = {
        "rules": [
            {
                "pattern": r"\b\d{3}-\d{4}\b",
                "replacement": "[PHONE]"
            }
        ]
    }
    with open(f"{test_dir}/policy.json", "w") as f:
        json.dump(policy, f)
    
    return test_dir

def run_cli_test(command, args, expected_success=True):
    """Run a CLI command and check the result."""
    cmd = [sys.executable, "-m", f"vault.cli.{command}"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    success = result.returncode == 0
    if success != expected_success:
        print(f"FAILED: {' '.join(cmd)}")
        print(f"Expected {'success' if expected_success else 'failure'}, got {'success' if success else 'failure'}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        return False
    
    return True

def main():
    """Run security tests on CLI commands."""
    print("=== Marvis Vault CLI Security Test Suite ===\n")
    
    test_dir = create_test_files()
    passed = 0
    failed = 0
    
    tests = [
        # Valid cases
        ("simulate", [f"{test_dir}/valid_agent.json", f"{test_dir}/policy.json"], True, "Valid agent should work"),
        
        # Security violations
        ("simulate", [f"{test_dir}/sql_injection_agent.json", f"{test_dir}/policy.json"], False, "SQL injection should be blocked"),
        ("simulate", [f"{test_dir}/command_injection_agent.json", f"{test_dir}/policy.json"], False, "Command injection should be blocked"),
        ("simulate", [f"{test_dir}/xss_agent.json", f"{test_dir}/policy.json"], False, "XSS should be blocked"),
        
        # Type confusion (should succeed with conversion)
        ("simulate", [f"{test_dir}/type_confusion_agent.json", f"{test_dir}/policy.json"], True, "String trustScore should be converted"),
        
        # Special values
        ("simulate", [f"{test_dir}/boolean_agent.json", f"{test_dir}/policy.json"], False, "Boolean trustScore should be rejected"),
        ("simulate", [f"{test_dir}/infinity_agent.json", f"{test_dir}/policy.json"], False, "Infinity should be rejected"),
        
        # Bug fixes
        ("simulate", [f"{test_dir}/missing_trust_agent.json", f"{test_dir}/policy.json"], False, "Missing trustScore should fail (Bug #8)"),
        ("simulate", [f"{test_dir}/malformed_agent.json", f"{test_dir}/policy.json"], False, "Malformed JSON should fail (Bug #7)"),
        
        # DoS protection
        ("simulate", [f"{test_dir}/large_agent.json", f"{test_dir}/policy.json"], False, "Large payload should be rejected"),
        
        # Redact command tests
        ("redact", [f"{test_dir}/content.json", f"{test_dir}/policy.json", "-a", f"{test_dir}/valid_agent.json"], True, "Redact with valid agent"),
        ("redact", [f"{test_dir}/content.json", f"{test_dir}/policy.json", "-a", f"{test_dir}/sql_injection_agent.json"], False, "Redact blocks SQL injection"),
    ]
    
    for i, (command, args, should_pass, description) in enumerate(tests, 1):
        print(f"Test {i}: {description}")
        if run_cli_test(command, args, should_pass):
            print("PASSED\n")
            passed += 1
        else:
            print("FAILED\n")
            failed += 1
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    
    print(f"\n=== Summary ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")
    
    if failed == 0:
        print("\nAll security tests passed!")
        print("\nKey Security Features Demonstrated:")
        print("1. SQL injection protection")
        print("2. Command injection protection")
        print("3. XSS protection")
        print("4. Type confusion prevention (string to float conversion)")
        print("5. Special value rejection (boolean, infinity)")
        print("6. Missing field handling (Bug #8 fixed)")
        print("7. Malformed input rejection (Bug #7 fixed)")
        print("8. DoS protection (large payload rejection)")
        print("\nThe CLI is secure and ready for assessment!")
    else:
        print("\nSome tests failed. Please review the security implementation.")
        sys.exit(1)

if __name__ == "__main__":
    main()