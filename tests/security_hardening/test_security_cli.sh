#!/bin/bash
# Test security hardening via CLI

echo "=== Security Hardening Test Suite ==="
echo "Testing various attack vectors that should now be blocked"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test function
test_agent() {
    local test_name="$1"
    local file="$2"
    local expected="$3"
    
    echo -n "Testing $test_name... "
    
    # Run simulate command and capture output
    if python3 -m vault.cli.main simulate -a "$file" -p vault/templates/pii-basic.json 2>&1 | grep -q "Error"; then
        result="BLOCKED"
    else
        result="ALLOWED"
    fi
    
    if [ "$result" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} ($result as expected)"
    else
        echo -e "${RED}FAIL${NC} (Got $result, expected $expected)"
    fi
}

echo "1. Testing Special Numeric Values:"
test_agent "Infinity value" "test_security_hardening/test_infinity_real.json" "BLOCKED"
test_agent "NaN value" "test_security_hardening/test_nan.json" "BLOCKED"  
test_agent "Negative Infinity" "test_security_hardening/test_negative_infinity.json" "BLOCKED"

echo
echo "2. Testing Type Confusion:"
test_agent "Boolean true as trustScore" "test_security_hardening/test_boolean_true.json" "BLOCKED"

echo
echo "3. Testing Unicode Attacks:"
test_agent "Cyrillic 'a' in admin" "test_security_hardening/test_unicode_admin.json" "BLOCKED"
test_agent "Zero-width space" "test_security_hardening/test_zero_width.json" "BLOCKED"

echo
echo "4. Testing Range Validation:"
test_agent "trustScore > 100" "test_security_hardening/test_out_of_range.json" "BLOCKED"

echo
echo "5. Testing Size Limits:"
# Generate large file
python3 test_security_hardening/test_large_file.py 2>/dev/null
test_agent "11MB file (exceeds limit)" "test_security_hardening/test_large.json" "BLOCKED"
rm -f test_security_hardening/test_large.json

echo
echo "6. Testing Valid Agent (should pass):"
echo '{"role": "analyst", "trustScore": 85}' > test_security_hardening/test_valid.json
test_agent "Valid agent" "test_security_hardening/test_valid.json" "ALLOWED"

echo
echo "=== Test Summary ==="
echo "Security hardening should block all attack vectors while allowing valid agents."