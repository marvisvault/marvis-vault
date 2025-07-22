#!/bin/bash
# Marvis Vault Quick Start Script
# Run this to see Marvis Vault in action in 30 seconds

echo "Marvis Vault Quick Demo"
echo "========================="
echo ""

# Create a simple test
echo "1. Creating test data..."
echo '{"name":"John Doe","email":"john@example.com","ssn":"123-45-6789"}' > test_data.json

echo ""
echo "2. Creating agents with different trust levels..."
echo '{"role":"admin","trustScore":95}' > admin.json
echo '{"role":"user","trustScore":40}' > user.json

echo ""
echo "3. Testing who can see what..."
echo ""
echo "Admin simulation (high trust + unmask role):"
vault simulate -a admin.json -p vault/templates/pii-basic.json

echo ""
echo "User simulation (low trust):"
vault simulate -a user.json -p vault/templates/pii-basic.json

echo ""
echo "4. Testing security - SQL injection attempt:"
echo '{"role":"admin OR 1=1","trustScore":100}' > sql_injection.json
vault simulate -a sql_injection.json -p vault/templates/pii-basic.json 2>&1 | head -5

echo ""
echo "Demo complete! Marvis Vault:"
echo "   - Controls data access by role + trust score"
echo "   - Blocks injection attacks"
echo "   - Provides clear audit trail"
echo ""
echo "Run 'python demo.py' for interactive demo"
echo "See docs/01_index.md for full documentation"

# Cleanup
rm -f test_data.json admin.json user.json sql_injection.json