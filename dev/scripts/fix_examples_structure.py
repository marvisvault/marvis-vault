#!/usr/bin/env python3
"""
Fix the examples directory structure to match documentation and user expectations.
"""

import os
import shutil
import json

def create_proper_structure():
    """Create the expected directory structure with proper examples."""
    
    # Create policies directory as referenced in README
    os.makedirs("policies", exist_ok=True)
    
    # Copy template policies to policies directory with user-friendly names
    policy_mappings = {
        "vault/templates/gdpr-lite.json": "policies/gdpr-lite.json",
        "vault/templates/pii-basic.json": "policies/pii-basic.json", 
        "vault/templates/healthcare.json": "policies/healthcare.json",
        "vault/templates/finance-trust.json": "policies/finance-trust.json"
    }
    
    for src, dst in policy_mappings.items():
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"Created {dst}")
    
    # Create a simple example policy as referenced in docs
    example_policy = {
        "mask": ["ssn", "email", "phone", "address"],
        "unmask_roles": ["admin", "auditor"],
        "conditions": [
            "trustScore >= 80",
            "role == 'manager' && trustScore >= 70"
        ]
    }
    
    with open("policies/example.json", "w") as f:
        json.dump(example_policy, f, indent=2)
    print("Created policies/example.json")
    
    # Create proper agent examples in the expected location
    # Fix the path issue - create examples/agent.json as docs suggest
    if os.path.exists("examples/agents/agent.json"):
        shutil.copy2("examples/agents/agent.json", "examples/agent.json")
        print("Created examples/agent.json (as referenced in README)")
    
    # Create a clear examples structure
    example_agents = {
        "examples/agent-basic.json": {
            "role": "user",
            "trustScore": 75
        },
        "examples/agent-admin.json": {
            "role": "admin",
            "trustScore": 90,
            "department": "IT"
        },
        "examples/agent-low-trust.json": {
            "role": "contractor",
            "trustScore": 40
        }
    }
    
    for path, content in example_agents.items():
        with open(path, "w") as f:
            json.dump(content, f, indent=2)
        print(f"Created {path}")
    
    # Create example data files
    example_data = {
        "examples/data-pii.json": {
            "name": "John Doe",
            "email": "john.doe@example.com",
            "ssn": "123-45-6789",
            "phone": "555-0123",
            "notes": "Customer since 2020"
        },
        "examples/data-medical.json": {
            "patient_id": "P12345",
            "diagnosis": "Type 2 Diabetes",
            "medication": "Metformin",
            "doctor": "Dr. Smith"
        }
    }
    
    for path, content in example_data.items():
        with open(path, "w") as f:
            json.dump(content, f, indent=2)
        print(f"Created {path}")
    
    # Create a README in examples directory
    examples_readme = """# Marvis Vault Examples

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
"""
    
    with open("examples/README.md", "w") as f:
        f.write(examples_readme)
    print("Created examples/README.md")
    
    print("\nStructure fixed! The examples now match the documentation.")
    print("\nYou can now run:")
    print("  vault simulate --agent examples/agent.json --policy policies/gdpr-lite.json")

if __name__ == "__main__":
    create_proper_structure()