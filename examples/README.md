# Marvis Vault Examples

This directory contains simple examples to get started with Marvis Vault.

## Quick Start Examples

### Basic Usage

```bash
# View example agent and data
cat agent.json
cat data-pii.json

# Run basic redaction
vault redact -a agent.json -d data-pii.json -p ../policies/pii-basic.json

# Simulate policy evaluation
vault simulate -a agent.json -p ../policies/pii-basic.json
```

### Example Files

#### Agents (`agent-*.json`)
- **agent.json**: Default agent (admin with high trust)
- **agent-basic.json**: Basic user with medium trust
- **agent-admin.json**: Admin user with high trust  
- **agent-low-trust.json**: Low trust contractor

#### Data Files (`data-*.json`)
- **data-pii.json**: Example with PII fields (name, email, SSN)
- **data-medical.json**: Healthcare data example
- **data-pii-realistic.json**: More complex nested PII data

#### Test Agents (`agents/`)
- **malformed_agent.json**: For testing error handling
- **edge_case_agent.json**: Edge cases for testing

## Common Commands

1. **Simulate with GDPR policy:**
   ```bash
   vault simulate -a agent.json -p ../policies/gdpr-lite.json
   ```

2. **Simulate with healthcare policy:**
   ```bash
   vault simulate -a agent-admin.json -p ../policies/healthcare.json
   ```

3. **Redact financial data:**
   ```bash
   vault redact -a agent-basic.json -d data-pii.json -p ../policies/finance-trust.json
   ```

4. **Test error handling:**
   ```bash
   vault simulate -a agents/malformed_agent.json -p ../policies/pii-basic.json
   ```

## Policy Templates

Available in `../policies/`:
- **pii-basic.json**: Basic PII protection
- **healthcare.json**: HIPAA-compliant healthcare data
- **finance-trust.json**: Financial data with trust-based access
- **gdpr-lite.json**: GDPR-inspired data protection

## Advanced Testing

For comprehensive testing scenarios, see `dev/test-data/` which includes:
- Production-ready agent profiles with detailed metadata
- Complex nested data structures (healthcare records, financial transactions, employee data)
- Industry-specific policies with compliance metadata
- Security attack test vectors

## Next Steps

1. Try the basic examples above
2. Modify agent trust scores to see different redaction behavior
3. Create your own policies based on the templates
4. Run the comprehensive test suite in `dev/scripts/api_test_runner.py`