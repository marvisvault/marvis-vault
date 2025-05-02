# Marvis Vault OSS - Policy Format Guide

## Policy Structure

A Vault policy is a JSON or YAML file that defines:
- Which fields to mask
- Who can unmask them
- Under what conditions

### Required Fields

```json
{
  "mask": ["field1", "field2"],
  "unmaskRoles": ["role1", "role2"],
  "conditions": ["condition1", "condition2"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mask` | `string[]` | List of field names to mask |
| `unmaskRoles` | `string[]` | Roles allowed to unmask fields |
| `conditions` | `string[]` | Conditions for unmasking |

## File Formats

Vault supports both JSON and YAML formats:

### JSON Example
```json
{
  "mask": ["email", "phone"],
  "unmaskRoles": ["admin"],
  "conditions": ["trustScore > 80 && role != 'auditor'"]
}
```

### YAML Example
```yaml
mask:
  - email
  - phone
unmaskRoles:
  - admin
conditions:
  - trustScore > 80 && role != 'auditor'
```

## Condition Syntax

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `>` | Greater than | `trustScore > 80` |
| `<` | Less than | `trustScore < 50` |
| `==` | Equal to | `role == 'admin'` |
| `!=` | Not equal to | `role != 'auditor'` |
| `&&` | Logical AND | `trustScore > 80 && role == 'admin'` |
| `||` | Logical OR | `trustScore > 90 || role == 'superadmin'` |

### Context Fields

| Field | Type | Description |
|-------|------|-------------|
| `trustScore` | `number` | Agent's trust score (0-100) |
| `role` | `string` | Agent's role |
| `department` | `string` | Agent's department |
| `location` | `string` | Agent's location |

### Examples

1. **Basic Trust Score Check**:
   ```json
   "conditions": ["trustScore > 80"]
   ```

2. **Role-Based Access**:
   ```json
   "conditions": ["role == 'admin'"]
   ```

3. **Combined Conditions**:
   ```json
   "conditions": [
     "trustScore > 80 && role != 'auditor'",
     "department == 'security' || role == 'superadmin'"
   ]
   ```

## Policy Versioning

1. **Version Control**:
   - Store policies in version control
   - Use semantic versioning
   - Document changes in commit messages

2. **Policy Templates**:
   - Create reusable templates
   - Use variables for customization
   - Document template parameters

3. **Best Practices**:
   - Keep policies simple and focused
   - Use descriptive field names
   - Document special cases
   - Test policies thoroughly

## Policy Reusability

1. **Template Structure**:
   ```json
   {
     "mask": ["${fields}"],
     "unmaskRoles": ["${roles}"],
     "conditions": ["${conditions}"]
   }
   ```

2. **Inheritance**:
   - Base policies for common rules
   - Specialized policies for specific cases
   - Override mechanism for customization

3. **Validation**:
   - Use `vault lint` to check policies
   - Validate against schema
   - Test with `vault simulate`

## Next Steps

- Try the [Quickstart Guide](quickstart.md)
- Learn about [SDK Usage](sdk-usage.md)
- Check out the [Roadmap](roadmap.md) 