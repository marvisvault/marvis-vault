# Tutorial: marvis-vault-oss

**Marvis Vault** is a programmable compliance infrastructure for AI systems that provides secure handling of sensitive data. It allows developers to **define policies** that govern which fields should be masked, which roles can unmask them, and under what conditions access is granted. The system works by intercepting data, applying redaction rules based on policy evaluation, maintaining detailed audit logs of all access attempts, and providing controlled unmasking capabilities. This creates a *security layer* around sensitive information, enabling AI systems to comply with data protection requirements while maintaining functionality.


**Source Repository:** [Marvis Vault OSS CLI](https://github.com/abbybiswas/marvis-vault-oss)

```mermaid
flowchart TD
    CLI["CLI Interface"]
    Policy["Policy Engine"]
    Redactor["Redaction System"]
    Audit["Audit Logger"]
    Evaluator["Condition Evaluator"]
    Unmask["Unmask Mechanism"]
    Definition["Policy Definition (JSON)"]

    CLI -->|Run Redaction| Redactor
    CLI -->|Trigger Unmasking| Unmask
    CLI -->|Validate Policy File| Definition
    CLI -->|Display Logs| Audit

    Redactor -->|Masking Request| Policy
    Redactor -->|Log Mask Events| Audit

    Unmask -->|Authorization Check| Policy
    Unmask -->|Log Unmask Events| Audit

    Policy -->|Evaluate Conditions| Evaluator
    Policy -->|Load Rules| Definition

    Evaluator -->|Parse Conditions| Definition
```

## Chapters

1. [CLI Interface](01_cli_interface_.md)
2. [Policy Definition](02_policy_definition_.md)
3. [Policy Engine](03_policy_engine_.md)
4. [Condition Evaluator](04_condition_evaluator_.md)
5. [Redaction System](05_redaction_system_.md)
6. [Unmask Mechanism](06_unmask_mechanism_.md)
7. [Audit System](07_audit_system_.md)

#### ---> [Quick Start](quickstart.md)
---
