# Marvis Vault OSS CLI: Tutorial

> **Marvis Vault** is a programmable compliance infrastructure for AI systems that provides secure handling of sensitive data. 

It allows developers to **define policies** that govern which fields should be masked, which roles can unmask them, and under what conditions access is granted. 

The system works by intercepting data, applying redaction rules based on policy evaluation, maintaining detailed audit logs of all access attempts, and providing controlled unmasking capabilities. This creates a ***security layer*** around sensitive information, enabling AI systems to comply with data protection requirements while maintaining functionality.


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

0. [Local Setup](../SETUP.md)
1. [CLI Interface](02_cli_interface_.md)
2. [Policy Definition](03_policy_definition_.md)
3. [Policy Engine](04_policy_engine_.md)
4. [Condition Evaluator](05_condition_evaluator_.md)
5. [Redaction System](06_redaction_system_.md)
6. [Unmask Mechanism](07_unmask_mechanism_.md)
7. [Audit System](08_audit_system_.md)

#### [Quick Start](00_quickstart.md)

#### Want to contribute? [Start here](../CONTRIBUTING.md)
---
