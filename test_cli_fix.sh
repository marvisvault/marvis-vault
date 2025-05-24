#!/bin/bash
echo "Testing CLI redact with agent support..."
echo "========================================"

# Create test data
echo '{"name": "John Doe", "email": "john@example.com", "ssn": "123-45-6789"}' > test_data.json

# Create policy requiring trustScore
echo '{
  "mask": ["email", "ssn"],
  "unmask_roles": ["admin"],
  "conditions": ["trustScore > 80"]
}' > test_policy.json

# Create agent WITHOUT trustScore
echo '{"role": "user"}' > agent_no_trust.json

# Create agent WITH trustScore
echo '{"role": "user", "trustScore": 85}' > agent_with_trust.json

# Create admin agent
echo '{"role": "admin"}' > agent_admin.json

echo -e "\nTest 1: Without trustScore (should redact email and ssn)"
vault redact -i test_data.json -p test_policy.json -g agent_no_trust.json

echo -e "\n\nTest 2: With trustScore > 80 (should NOT redact)"
vault redact -i test_data.json -p test_policy.json -g agent_with_trust.json

echo -e "\n\nTest 3: Admin role without trustScore (should NOT redact)"
vault redact -i test_data.json -p test_policy.json -g agent_admin.json

echo -e "\n\nTest 4: No agent at all (should redact everything)"
vault redact -i test_data.json -p test_policy.json