# Marvis Vault OSS - Quickstart Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/marvis-labs/marvis-vault-oss.git
cd marvis-vault-oss

# Create and activate virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install package in editable mode
pip install -e .
```

## Basic Usage

### Redacting Text

```bash
# Using a file
vault redact --input example.txt --policy policies/gdpr-lite.json

# Using stdin
cat example.txt | vault redact --policy policies/gdpr-lite.json

# Using stdout
vault redact --input example.txt --policy policies/gdpr-lite.json > redacted.txt
```

### Simulating Policies

```bash
# Simulate with agent and policy
vault simulate --agent agent.json --policy policies/policy.json

# View simulation results
vault simulate --agent agent.json --policy policies/policy.json --output results.json
```

### Audit Logging

```bash
# View audit log
vault audit --log vault.log

# Export to CSV
vault audit --log vault.log --format csv > audit.csv

# Export to JSON
vault audit --log vault.log --format json > audit.json
```

## Sample Files

### agent.json
```json
{
  "role": "admin",
  "trustScore": 90,
  "context": {
    "department": "security",
    "location": "US"
  }
}
```

### policy.json
```json
{
  "mask": ["email", "phone", "ssn"],
  "unmaskRoles": ["admin", "hr_manager"],
  "conditions": ["trustScore > 80 && role != 'auditor'"]
}
```

### Sample Input/Output

**Input:**
```
User Information:
Name: John Doe
Email: john.doe@example.com
Phone: +1-555-123-4567
SSN: 123-45-6789
```

**Output:**
```
User Information:
Name: John Doe
Email: [REDACTED]
Phone: [REDACTED]
SSN: [REDACTED]
```

## Using stdin/stdout Safely

1. **Input Safety**:
   - Always validate input files before processing
   - Use `--input -` for stdin
   - Consider file size limits for large inputs

2. **Output Safety**:
   - Redirect output to files when possible
   - Use `--output -` for stdout
   - Consider sensitive data in output

3. **Best Practices**:
   - Use file paths when possible
   - Validate policy files before use
   - Check file permissions
   - Monitor system resources

## Next Steps

- Read the [Policy Format Guide](policy-format.md)
- Learn about the [SDK Usage](sdk-usage.md)
- Check out the [Roadmap](roadmap.md) 