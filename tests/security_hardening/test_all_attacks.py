#!/usr/bin/env python3
"""
Demonstrate all security fixes via CLI testing
"""

import subprocess
import json
import os
import sys

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
END = '\033[0m'

def run_test(name, cmd, should_fail=True):
    """Run a test and check if it behaves as expected"""
    print(f"\n{BLUE}Testing: {name}{END}")
    print(f"Command: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if should_fail:
        if result.returncode != 0 and "Error" in result.stderr + result.stdout:
            print(f"{GREEN}PASS{END} - Attack blocked as expected")
            error_msg = result.stderr.strip() or result.stdout.strip()
            print(f"  Error: {error_msg}")
            return True
        else:
            print(f"{RED}FAIL{END} - Attack was NOT blocked!")
            return False
    else:
        if result.returncode == 0:
            print(f"{GREEN}PASS{END} - Valid input accepted")
            return True
        else:
            print(f"{RED}FAIL{END} - Valid input rejected!")
            print(f"  Error: {result.stderr}")
            return False

def main():
    print(f"{YELLOW}=== Marvis Vault Security Hardening Test ==={END}")
    print("Testing that all security vulnerabilities are now fixed\n")
    
    passed = 0
    total = 0
    
    # Create test directory
    os.makedirs("test_security_hardening", exist_ok=True)
    
    # Test 1: Infinity attack
    with open("test_security_hardening/infinity.json", "w") as f:
        json.dump({"role": "admin", "trustScore": float('inf')}, f)
    
    total += 1
    if run_test(
        "Infinity trustScore attack",
        ["python3", "-m", "vault.cli.main", "simulate", 
         "-a", "test_security_hardening/infinity.json",
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Test 2: NaN attack
    with open("test_security_hardening/nan.json", "w") as f:
        json.dump({"role": "user", "trustScore": float('nan')}, f)
    
    total += 1
    if run_test(
        "NaN trustScore attack",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/nan.json",
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Test 3: Boolean type confusion
    with open("test_security_hardening/bool.json", "w") as f:
        json.dump({"role": "analyst", "trustScore": True}, f)
    
    total += 1
    if run_test(
        "Boolean trustScore type confusion",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/bool.json", 
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Test 4: Out of range
    with open("test_security_hardening/range.json", "w") as f:
        json.dump({"role": "manager", "trustScore": 150}, f)
    
    total += 1
    if run_test(
        "Out of range trustScore (150)",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/range.json",
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Test 5: Negative trustScore
    with open("test_security_hardening/negative.json", "w") as f:
        json.dump({"role": "user", "trustScore": -50}, f)
    
    total += 1
    if run_test(
        "Negative trustScore",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/negative.json",
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Test 6: Valid agent (should pass)
    with open("test_security_hardening/valid.json", "w") as f:
        json.dump({"role": "analyst", "trustScore": 85}, f)
    
    total += 1
    if run_test(
        "Valid agent",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/valid.json",
         "-p", "vault/templates/pii-basic.json"],
        should_fail=False
    ):
        passed += 1
    
    # Test 7: Redact with malformed agent
    total += 1
    if run_test(
        "Redact command with boolean trustScore",
        ["python3", "-m", "vault.cli.main", "redact",
         "-i", "examples/before.json",
         "-p", "vault/templates/pii-basic.json",
         "-g", "test_security_hardening/bool.json"]
    ):
        passed += 1
    
    # Test 8: Missing trustScore (original bug #8)
    with open("test_security_hardening/missing_trust.json", "w") as f:
        json.dump({"role": "admin"}, f)
    
    total += 1
    if run_test(
        "Missing trustScore (Bug #8 verification)",
        ["python3", "-m", "vault.cli.main", "simulate",
         "-a", "test_security_hardening/missing_trust.json",
         "-p", "vault/templates/pii-basic.json"]
    ):
        passed += 1
    
    # Summary
    print(f"\n{YELLOW}=== Test Summary ==={END}")
    print(f"Total tests: {total}")
    print(f"Passed: {GREEN}{passed}{END}")
    print(f"Failed: {RED}{total - passed}{END}")
    
    if passed == total:
        print(f"\n{GREEN}Success: All security hardening tests passed!{END}")
        print("The system is now protected against:")
        print("  - Infinity/NaN values")
        print("  - Boolean type confusion") 
        print("  - Out of range values")
        print("  - Missing trustScore")
        print("  - Malformed agents in both simulate and redact")
        return 0
    else:
        print(f"\n{RED}Error: Some tests failed - security vulnerabilities remain!{END}")
        return 1

if __name__ == "__main__":
    sys.exit(main())