# Marvis Vault Development Resources

This directory contains all development, testing, and demonstration resources for Marvis Vault.

## Directory Structure

```
dev/
├── test-data/          # Comprehensive test data for API testing
│   ├── agents/         # Agent context test cases
│   ├── content/        # Sample content to be redacted
│   ├── policies/       # Redaction policies
│   ├── attacks/        # Security attack test vectors
│   └── test-config.json # Test suite configuration
├── scripts/            # Development and testing scripts
├── demos/              # Demo applications and examples
├── instructions/       # Development documentation
└── README.md           # This file
```

## Test Data

The `test-data/` directory contains production-ready test cases:

### Agents (`test-data/agents/`)
- **production-agents.json**: Real-world agent profiles with various trust levels
- **edge-case-agents.json**: Boundary conditions and edge cases
- **malicious-agents.json**: Security attack test cases

### Content (`test-data/content/`)
- **healthcare-records.json**: HIPAA-protected health information
- **financial-transactions.json**: PCI-DSS financial data
- **employee-records.json**: HR and employee sensitive data

### Policies (`test-data/policies/`)
- **healthcare-hipaa.json**: HIPAA-compliant redaction policy
- **financial-pci.json**: PCI-DSS compliant policy
- **hr-employee-data.json**: Employee data protection policy

### Attack Vectors (`test-data/attacks/`)
- **injection-payloads.json**: SQL, XSS, command injection tests
- **dos-payloads.json**: DoS attack patterns and large payloads

## Running API Tests

Use the comprehensive test runner:

```bash
# Run all test suites
python dev/scripts/api_test_runner.py

# Run specific suite
python dev/scripts/api_test_runner.py --suite security_validation

# Use custom test data location
python dev/scripts/api_test_runner.py --data-dir /path/to/test-data
```

## Test Configuration

The `test-config.json` file defines test suites:

```json
{
  "test_suites": {
    "basic_functionality": {
      "description": "Core functionality tests",
      "tests": [...]
    },
    "security_validation": {
      "description": "Security attack prevention",
      "tests": [...]
    }
  }
}
```

## Writing New Tests

1. Add test data to appropriate directories
2. Update `test-config.json` with new test cases
3. Run tests to validate

Example test case:
```json
{
  "name": "Healthcare Admin Access",
  "agent": "agents/production-agents.json#agents.admin_full_access",
  "content": "content/healthcare-records.json",
  "policy": "policies/healthcare-hipaa.json",
  "expected": {
    "all_fields": "visible"
  }
}
```

## Performance Benchmarks

Target performance metrics:
- Basic redaction: < 10ms
- Complex policy evaluation: < 50ms
- Large document processing: < 100ms
- Concurrent requests: > 1000 req/s

## Security Testing

The test suite includes comprehensive security validation:
- SQL injection prevention
- XSS attack prevention
- Command injection blocking
- Path traversal protection
- DoS attack mitigation
- Type confusion prevention
- Special value handling (Infinity, NaN, etc.)

## Development Workflow

1. Write test cases in JSON
2. Run API tests to validate
3. Check performance metrics
4. Review security test results
5. Examine audit logs for compliance