# Tutorial: marvis-vault-oss

**Marvis Vault** is a programmable compliance infrastructure for AI systems that provides secure handling of sensitive data. It allows developers to **define policies** that govern which fields should be masked, which roles can unmask them, and under what conditions access is granted. The system works by intercepting data, applying redaction rules based on policy evaluation, maintaining detailed audit logs of all access attempts, and providing controlled unmasking capabilities. This creates a *security layer* around sensitive information, enabling AI systems to comply with data protection requirements while maintaining functionality.


**Source Repository:** [None](None)

```mermaid
flowchart TD
    A0["Policy Engine
"]
    A1["Redaction System
"]
    A2["CLI Interface
"]
    A3["Audit System
"]
    A4["Condition Evaluator
"]
    A5["Unmask Mechanism
"]
    A9["Policy Definition
"]
    A0 -- "Uses for condition evaluation" --> A4
    A0 -- "Consumes and enforces" --> A9
    A1 -- "Requests masking decisions" --> A0
    A1 -- "Logs masking operations" --> A3
    A2 -- "Provides redaction commands" --> A1
    A2 -- "Reads and displays logs" --> A3
    A5 -- "Checks authorization" --> A0
    A5 -- "Logs unmasking attempts" --> A3
    A2 -- "Validates policies" --> A9
    A2 -- "Provides unmasking interface" --> A5
    A4 -- "Processes conditions from" --> A9
```

## Chapters

1. [CLI Interface
](01_cli_interface_.md)
2. [Policy Definition
](02_policy_definition_.md)
3. [Policy Engine
](03_policy_engine_.md)
4. [Condition Evaluator
](04_condition_evaluator_.md)
5. [Redaction System
](05_redaction_system_.md)
6. [Unmask Mechanism
](06_unmask_mechanism_.md)
7. [Audit System
](07_audit_system_.md)


---
