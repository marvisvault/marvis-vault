# Marvis Vault Examples

This directory contains example files for testing Marvis Vault.

## Quick Start

Test the simulate command:
```bash
vault simulate --agent agent.json --policy ../policies/gdpr-lite.json
```

## File Structure

### Agents (`agent-*.json`)
- `agent.json` - Default agent example (admin with high trust)
- `agent-basic.json` - Basic user with medium trust
- `agent-admin.json` - Admin user with high trust
- `agent-low-trust.json` - Low trust contractor

### Data Files (`data-*.json`)
- `data-pii.json` - Example with PII fields
- `data-medical.json` - Healthcare data example

### Test Agents (`agents/`)
- `agents/malformed_agent.json` - For testing error handling
- `agents/edge_case_agent.json` - Edge cases for testing

## Common Commands

1. Simulate with GDPR policy:
   ```bash
   vault simulate -a agent.json -p ../policies/gdpr-lite.json
   ```

2. Simulate with healthcare policy:
   ```bash
   vault simulate -a agent-admin.json -p ../policies/healthcare.json
   ```

3. Test error handling:
   ```bash
   vault simulate -a agents/malformed_agent.json -p ../policies/pii-basic.json
   ```
