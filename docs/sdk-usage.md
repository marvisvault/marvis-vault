# Marvis Vault OSS - SDK Usage Guide

## Installation

```bash
pip install marvis-vault
```

## Basic Usage

```python
from vault import redact, unmask, audit

# Or import specific functions
from vault.sdk.redact import redact
from vault.sdk.unmask import unmask
from vault.sdk.audit import audit
```

## Redacting Text

```python
# Sample policy
policy = {
    "mask": ["email", "phone", "ssn"],
    "unmaskRoles": ["admin"],
    "conditions": ["trustScore > 80 && role != 'auditor'"]
}

# Sample text
text = """
User Information:
Name: John Doe
Email: john.doe@example.com
Phone: +1-555-123-4567
SSN: 123-45-6789
"""

# Redact text
redacted = redact(text, policy)
print(redacted)
```

## Unmasking Text

```python
# Sample redacted text
redacted_text = """
User Information:
Name: John Doe
Email: [REDACTED]
Phone: [REDACTED]
SSN: [REDACTED]
"""

# Original values (optional)
original_values = {
    "email": "john.doe@example.com",
    "phone": "+1-555-123-4567",
    "ssn": "123-45-6789"
}

# Unmask with authorized role
unmasked = unmask(redacted_text, "admin", policy, original_values)
print(unmasked)

# Unmask with unauthorized role
unchanged = unmask(redacted_text, "user", policy, original_values)
print(unchanged)  # Returns redacted text unchanged
```

## Audit Logging

```python
# Sample audit event
event = {
    "action": "redact",
    "field": "email",
    "agent": {
        "role": "admin",
        "trustScore": 90
    },
    "result": "masked"
}

# Log audit event
audit(event)
```

## Simulating Agents and Policies

```python
from vault.engine.policy_engine import evaluate

# Sample agent
agent = {
    "role": "admin",
    "trustScore": 90,
    "context": {
        "department": "security",
        "location": "US"
    }
}

# Sample policy
policy = {
    "mask": ["email", "phone"],
    "unmaskRoles": ["admin"],
    "conditions": ["trustScore > 80 && role != 'auditor'"]
}

# Evaluate policy
result = evaluate(policy, agent)
print(result)  # {"status": True, "reason": "Conditions met"}
```

## Using in Agent Loops

```python
from vault import redact, audit

def process_text(text: str, agent: dict, policy: dict) -> str:
    # Redact text
    redacted = redact(text, policy)
    
    # Log audit event
    audit({
        "action": "redact",
        "field": "email",  # or detect fields
        "agent": agent,
        "result": "masked"
    })
    
    return redacted

# Example usage
texts = [...]  # List of texts to process
agent = {...}  # Agent configuration
policy = {...}  # Policy configuration

for text in texts:
    processed = process_text(text, agent, policy)
    # Use processed text...
```

## Using in Preprocessing Pipeline

```python
from typing import List, Dict, Any
from vault import redact, unmask

class TextProcessor:
    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy
    
    def preprocess(self, texts: List[str]) -> List[str]:
        return [redact(text, self.policy) for text in texts]
    
    def postprocess(self, texts: List[str], role: str) -> List[str]:
        return [unmask(text, role, self.policy) for text in texts]

# Example usage
processor = TextProcessor(policy)
preprocessed = processor.preprocess(texts)
# ... process preprocessed texts ...
postprocessed = processor.postprocess(preprocessed, "admin")
```

## Best Practices

1. **Error Handling**:
   ```python
   try:
       redacted = redact(text, policy)
   except Exception as e:
       # Handle error
       print(f"Error redacting text: {e}")
   ```

2. **Policy Validation**:
   ```python
   from vault.engine.policy_parser import validate_policy
   
   if validate_policy(policy):
       redacted = redact(text, policy)
   else:
       print("Invalid policy")
   ```

3. **Performance**:
   - Cache policies when possible
   - Batch process texts
   - Use async for I/O operations

## Next Steps

- Try the [Quickstart Guide](quickstart.md)
- Learn about [Policy Format](policy-format.md)
- Check out the [Roadmap](roadmap.md) 