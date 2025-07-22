#!/usr/bin/env python3
"""
Comprehensive security test suite for Marvis Vault.
Tests all security improvements including Bug #7 and Bug #8 fixes.
"""

import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from typing import Dict, Any, Tuple

class Colors:
    """Terminal colors for output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text:^60}{Colors.ENDC}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.ENDC}")

def print_test(name: str, passed: bool, details: str = ""):
    """Print test result"""
    status = f"{Colors.GREEN}PASS{Colors.ENDC}" if passed else f"{Colors.RED}FAIL{Colors.ENDC}"
    print(f"{status} {name}")
    if details:
        print(f"       {Colors.YELLOW}{details}{Colors.ENDC}")

def run_simulate(agent_file: str, policy_file: str = "vault/templates/pii-basic.json") -> Tuple[int, str, str]:
    """Run vault simulate command and return exit code, stdout, stderr"""
    cmd = [sys.executable, "-m", "vault.cli.simulate", "-a", agent_file, "-p", policy_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def create_test_agent(content: Dict[str, Any]) -> str:
    """Create a temporary agent file"""
    fd, path = tempfile.mkstemp(suffix='.json')
    with os.fdopen(fd, 'w') as f:
        json.dump(content, f)
    return path

def test_bug_7_malformed_json():
    """Test Bug #7: CLI should reject malformed JSON"""
    print_header("Bug #7: Malformed JSON Handling")
    
    tests = [
        ("Empty file", ""),
        ("Invalid JSON syntax", '{"role": "user", "trustScore":}'),
        ("Not a JSON object", '"just a string"'),
        ("Array instead of object", '["role", "user"]'),
        ("Trailing comma", '{"role": "user", "trustScore": 80,}'),
        ("Single quotes", "{'role': 'user', 'trustScore': 80}"),
        ("Missing quotes on key", '{role: "user", trustScore: 80}'),
        ("Comments in JSON", '{"role": "user", /* comment */ "trustScore": 80}'),
    ]
    
    passed = 0
    for test_name, json_content in tests:
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            f.write(json_content)
        
        exit_code, stdout, stderr = run_simulate(path)
        os.unlink(path)
        
        # Should fail with non-zero exit code
        test_passed = exit_code != 0
        print_test(test_name, test_passed, 
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_bug_8_missing_trustscore():
    """Test Bug #8: Missing trustScore should fail safely"""
    print_header("Bug #8: Missing trustScore Handling")
    
    tests = [
        ("Missing trustScore field", {"role": "user"}),
        ("trustScore is null", {"role": "user", "trustScore": None}),
        ("Empty object", {}),
        ("Only trustScore missing", {"role": "admin", "department": "IT"}),
    ]
    
    passed = 0
    for test_name, agent_data in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        # Should fail for simulate command (trustScore required)
        test_passed = exit_code != 0
        print_test(test_name, test_passed,
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_type_confusion():
    """Test type confusion prevention"""
    print_header("Type Confusion Prevention")
    
    tests = [
        ("String trustScore (should convert)", {"role": "user", "trustScore": "75"}, True),
        ("Boolean trustScore True", {"role": "user", "trustScore": True}, False),
        ("Boolean trustScore False", {"role": "user", "trustScore": False}, False),
        ("Numeric string role", {"role": 123, "trustScore": 80}, False),
        ("Null role", {"role": None, "trustScore": 80}, False),
        ("List as role", {"role": ["admin", "user"], "trustScore": 80}, False),
        ("Object as trustScore", {"role": "user", "trustScore": {"value": 80}}, False),
    ]
    
    passed = 0
    for test_name, agent_data, should_succeed in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        test_passed = (exit_code == 0) == should_succeed
        print_test(test_name, test_passed,
                  f"Expected {'success' if should_succeed else 'failure'}, got exit code: {exit_code}")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_injection_attacks():
    """Test injection attack prevention"""
    print_header("Injection Attack Prevention")
    
    tests = [
        ("SQL injection - OR 1=1", {"role": "admin' OR '1'='1", "trustScore": 100}),
        ("SQL injection - no spaces", {"role": "admin'OR'1'='1", "trustScore": 100}),
        ("SQL injection - UNION", {"role": "user' UNION SELECT * FROM users--", "trustScore": 80}),
        ("Command injection - semicolon", {"role": "user; rm -rf /", "trustScore": 50}),
        ("Command injection - pipe", {"role": "user | cat /etc/passwd", "trustScore": 50}),
        ("Command injection - backticks", {"role": "user`whoami`", "trustScore": 50}),
        ("XSS - script tag", {"role": "user", "trustScore": 80, "bio": "<script>alert('xss')</script>"}),
        ("XSS - javascript protocol", {"role": "user", "trustScore": 80, "link": "javascript:alert(1)"}),
        ("Path traversal", {"role": "../../../etc/passwd", "trustScore": 80}),
        ("System path access", {"role": "/etc/shadow", "trustScore": 80}),
        ("Null byte injection", {"role": "admin\x00.txt", "trustScore": 90}),
        ("Prototype pollution", {"role": "user", "__proto__": {"admin": true}, "trustScore": 80}),
    ]
    
    passed = 0
    for test_name, agent_data in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        # All injection attempts should fail
        test_passed = exit_code != 0
        print_test(test_name, test_passed,
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_special_values():
    """Test special numeric values"""
    print_header("Special Value Protection")
    
    # Create test cases programmatically
    tests = []
    
    # Infinity values
    tests.append(("Positive infinity", {"role": "admin", "trustScore": float('inf')}))
    tests.append(("Negative infinity", {"role": "admin", "trustScore": float('-inf')}))
    
    # String representations
    for inf_str in ["Infinity", "infinity", "INFINITY", "inf", "Inf", "-Infinity", "-inf"]:
        tests.append((f"String '{inf_str}'", {"role": "user", "trustScore": inf_str}))
    
    # NaN
    tests.append(("NaN float", {"role": "user", "trustScore": float('nan')}))
    for nan_str in ["NaN", "nan", "NAN"]:
        tests.append((f"String '{nan_str}'", {"role": "user", "trustScore": nan_str}))
    
    # Out of range
    tests.extend([
        ("Negative trustScore", {"role": "user", "trustScore": -10}),
        ("trustScore > 100", {"role": "user", "trustScore": 150}),
        ("Very large number", {"role": "user", "trustScore": 999999}),
        ("Very small negative", {"role": "user", "trustScore": -999999}),
    ])
    
    passed = 0
    for test_name, agent_data in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        # All special values should be rejected
        test_passed = exit_code != 0
        print_test(test_name, test_passed,
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_dos_protection():
    """Test DoS protection"""
    print_header("DoS Protection")
    
    tests = []
    
    # Large payload
    large_string = "x" * (2 * 1024 * 1024)  # 2MB
    tests.append(("Large payload (2MB)", {"role": "user", "trustScore": 80, "data": large_string}))
    
    # Deep nesting
    def create_deep_dict(depth):
        if depth == 0:
            return "end"
        return {"nested": create_deep_dict(depth - 1)}
    
    tests.append(("Deep nesting (101 levels)", {
        "role": "user",
        "trustScore": 80,
        "data": create_deep_dict(101)
    }))
    
    # Many fields
    many_fields = {"role": "user", "trustScore": 80}
    for i in range(10000):
        many_fields[f"field_{i}"] = f"value_{i}"
    tests.append(("10,000 fields", many_fields))
    
    # Long individual field
    tests.append(("Single field > 10KB", {
        "role": "user",
        "trustScore": 80,
        "comment": "x" * (11 * 1024)
    }))
    
    passed = 0
    for test_name, agent_data in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        # All DoS attempts should be rejected
        test_passed = exit_code != 0
        print_test(test_name, test_passed,
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def test_valid_scenarios():
    """Test valid scenarios that should work"""
    print_header("Valid Scenarios (Should Succeed)")
    
    tests = [
        ("Basic valid agent", {"role": "user", "trustScore": 75}),
        ("Admin with high trust", {"role": "admin", "trustScore": 95}),
        ("With additional fields", {"role": "analyst", "trustScore": 80, "department": "Finance"}),
        ("Edge of valid range - 0", {"role": "user", "trustScore": 0}),
        ("Edge of valid range - 100", {"role": "admin", "trustScore": 100}),
        ("String numbers converted", {"role": "user", "trustScore": "50.5"}),
        ("With nested data", {
            "role": "manager",
            "trustScore": 85,
            "metadata": {
                "team": "Engineering",
                "projects": ["API", "Frontend"]
            }
        }),
    ]
    
    passed = 0
    for test_name, agent_data in tests:
        agent_file = create_test_agent(agent_data)
        exit_code, stdout, stderr = run_simulate(agent_file)
        os.unlink(agent_file)
        
        # All valid cases should succeed
        test_passed = exit_code == 0
        print_test(test_name, test_passed,
                  f"Exit code: {exit_code}" if not test_passed else "")
        if test_passed:
            passed += 1
    
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    return passed == len(tests)

def explain_simulate_command():
    """Explain what vault simulate does"""
    print_header("Understanding 'vault simulate'")
    
    print(f"""
{Colors.BOLD}What does 'vault simulate -a agent.json -p policy.json' do?{Colors.ENDC}

The simulate command is a {Colors.CYAN}dry-run tool{Colors.ENDC} that shows you what would happen
if you used this agent and policy to redact data, {Colors.YELLOW}without actually 
processing any sensitive data{Colors.ENDC}.

{Colors.BOLD}Step-by-step breakdown:{Colors.ENDC}

1. {Colors.BLUE}Load Agent Context{Colors.ENDC} (-a agent.json)
   - Reads the agent's role (e.g., "admin", "user", "analyst")
   - Reads the agent's trustScore (0-100)
   - Validates these values for security
   
2. {Colors.BLUE}Load Policy{Colors.ENDC} (-p policy.json)
   - mask: Which fields to redact (e.g., ["ssn", "email"])
   - unmask_roles: Roles that can see everything (e.g., ["admin"])
   - conditions: Rules for when to show data (e.g., "trustScore >= 80")

3. {Colors.BLUE}Evaluate Conditions{Colors.ENDC}
   - Checks if the agent meets ANY condition in the policy
   - Uses the agent's role and trustScore in the evaluation
   - Example: "trustScore >= 80 && role == 'analyst'"

4. {Colors.BLUE}Display Results{Colors.ENDC}
   - Shows which fields WOULD BE masked/unmasked
   - Explains WHY (which condition passed/failed)
   - No actual data is processed

{Colors.BOLD}Example Output:{Colors.ENDC}
┌─ Context Summary ─┐
│ role: analyst     │
│ trustScore: 75    │
└───────────────────┘

┌─ Masking Analysis ──────────────────────────┐
│ Status: MASK                                │
│ Reason: All conditions failed               │
│ Fields to mask: ssn, email, phone          │
└─────────────────────────────────────────────┘

{Colors.GREEN}This is purely informational - no data is actually redacted!{Colors.ENDC}
""")

def main():
    """Run all tests"""
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("="*50)
    print("    Marvis Vault Security Test Suite")
    print("    Testing Bug Fixes & Security Features")
    print("="*50)
    print(f"{Colors.ENDC}")
    
    # First explain what simulate does
    explain_simulate_command()
    
    # Run all test categories
    test_results = []
    test_results.append(("Bug #7 - Malformed JSON", test_bug_7_malformed_json()))
    test_results.append(("Bug #8 - Missing trustScore", test_bug_8_missing_trustscore()))
    test_results.append(("Type Confusion", test_type_confusion()))
    test_results.append(("Injection Attacks", test_injection_attacks()))
    test_results.append(("Special Values", test_special_values()))
    test_results.append(("DoS Protection", test_dos_protection()))
    test_results.append(("Valid Scenarios", test_valid_scenarios()))
    
    # Summary
    print_header("Final Summary")
    total_passed = sum(1 for _, passed in test_results if passed)
    total_tests = len(test_results)
    
    print(f"\n{Colors.BOLD}Test Categories:{Colors.ENDC}")
    for category, passed in test_results:
        status = f"{Colors.GREEN}[PASS]{Colors.ENDC}" if passed else f"{Colors.RED}[FAIL]{Colors.ENDC}"
        print(f"  {status} {category}")
    
    print(f"\n{Colors.BOLD}Overall: {total_passed}/{total_tests} categories passed{Colors.ENDC}")
    
    if total_passed == total_tests:
        print(f"\n{Colors.GREEN}{Colors.BOLD}All security tests passed!{Colors.ENDC}")
        print(f"{Colors.GREEN}The CLI is secure and ready for production use.{Colors.ENDC}")
        return 0
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}Some tests failed!{Colors.ENDC}")
        print(f"{Colors.RED}Please review the security implementation.{Colors.ENDC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())