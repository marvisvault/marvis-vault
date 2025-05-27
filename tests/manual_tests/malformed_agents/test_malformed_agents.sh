#!/bin/bash
# Test malformed agent validation

echo "Testing Malformed Agent Validation (Issue #7)"
echo "============================================="

# Change to this test directory
cd "$(dirname "$0")"

# Create test data file
echo '{"email": "test@example.com", "ssn": "123-45-6789", "name": "Test User"}' > test_data.json

# Use a real policy from templates
POLICY_PATH="../../../vault/templates/pii-basic.json"

echo -e "\n1. Testing SIMULATE command validation:"
echo "--------------------------------------"

# Test 1: Empty file
echo "" > empty_agent.json
echo -e "\nTest: Empty agent file"
vault simulate --agent empty_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 2: Not a JSON object
echo '"just a string"' > string_agent.json
echo -e "\nTest: Non-object JSON (string)"
vault simulate --agent string_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 3: Missing role
echo '{"trustScore": 80}' > no_role_agent.json
echo -e "\nTest: Missing role field"
vault simulate --agent no_role_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 4: Empty role
echo '{"role": "", "trustScore": 80}' > empty_role_agent.json
echo -e "\nTest: Empty role"
vault simulate --agent empty_role_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 5: Non-string role
echo '{"role": 123, "trustScore": 80}' > numeric_role_agent.json
echo -e "\nTest: Non-string role (number)"
vault simulate --agent numeric_role_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 6: Missing trustScore (required for simulate)
echo '{"role": "user"}' > no_trust_agent.json
echo -e "\nTest: Missing trustScore"
vault simulate --agent no_trust_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 7: Out of range trustScore
echo '{"role": "user", "trustScore": 150}' > high_trust_agent.json
echo -e "\nTest: trustScore > 100"
vault simulate --agent high_trust_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

# Test 8: Invalid trustScore type
echo '{"role": "user", "trustScore": "high"}' > string_trust_agent.json
echo -e "\nTest: Non-numeric trustScore"
vault simulate --agent string_trust_agent.json --policy $POLICY_PATH 2>&1 | grep -E "Error:|Invalid"

echo -e "\n\n2. Testing REDACT command validation:"
echo "------------------------------------"

# Test with redact (trustScore optional)
echo '{"role": 123}' > bad_role_agent.json
echo -e "\nTest: Non-string role in redact"
vault redact -i test_data.json -p $POLICY_PATH -g bad_role_agent.json 2>&1 | grep -E "Error:|Invalid"

# Test valid agent for comparison
echo '{"role": "user"}' > valid_agent.json
echo -e "\nTest: Valid agent (should work)"
echo "Output should show redacted data:"
vault redact -i test_data.json -p $POLICY_PATH -g valid_agent.json 2>&1 | head -5

echo -e "\n\nTest complete. All malformed agents should show clear error messages."
echo "Clean up with: rm *.json"