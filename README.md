![MIT License](https://img.shields.io/badge/license-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

---

# Marvis Vault OSS

**Programmable compliance infrastructure for agentic AI.**  
Redact, simulate, and audit sensitive data — with policies, trustScore, and role-based logic.  

Built for teams using LLMs, agents, and AI-native workflows.

[ Read the Docs](./docs/01_index.md) &nbsp;&nbsp;&nbsp;&nbsp;[marvisvault.com](https://marvisvault.com) &nbsp;&nbsp;&nbsp;&nbsp;[Apply for Vault Plus](https://tally.so/r/3XNBgP)

---

## Core Features

- **Redaction Engine** — Mask sensitive fields using role + trustScore
- **Policy Language** — Declarative conditions with `&&`, `||`, and field logic
- **Simulation CLI** — See what would be masked before sending to the model
- **Audit Logging** — Structured JSONL logs for every mask/unmask decision
- **Python SDK** — Use Vault in agents, pipelines, or AI assistants
- **Policy Templates** — GDPR, PII, finance, healthcare — ready to drop in

---

## Install

```bash
git clone https://github.com/abbybiswas/marvis-vault-oss.git
cd marvis-vault-oss
pip install -e .
```
> See [Local Setup Guide](SETUP.md) for detailed environment setup instructions

## Quick Start

### CLI Usage

```bash
# Simulate policy evaluation
vault simulate --agent examples/agent.json --policy policies/pii-basic.json

# Redact sensitive data
vault redact --agent examples/agent.json --data examples/data-pii.json --policy policies/gdpr-lite.json

# View audit logs
vault audit --log logs/audit.log --format table
```

### Python SDK

```python
from vault.sdk import redact
from vault.engine.policy_parser import load_policy

# Load policy and agent context
policy = load_policy("policies/healthcare.json")
agent = {"role": "analyst", "trustScore": 75}

# Redact sensitive data
result = redact(
    content='{"name": "John Doe", "ssn": "123-45-6789"}',
    policy=policy,
    agent_context=agent
)

print(result.content)  # {"name": "John Doe", "ssn": "[REDACTED]"}
```

---

## Project Structure

```
marvis-vault-oss/
├── vault/                 # Core library code
│   ├── cli/              # CLI commands
│   ├── engine/           # Policy engine
│   ├── sdk/              # Python SDK
│   └── utils/            # Security utilities
├── examples/             # Simple examples to get started
├── policies/             # Pre-built policy templates
├── tests/                # Test suite
├── dev/                  # Development resources
│   ├── test-data/        # Comprehensive test data
│   ├── scripts/          # Testing & demo scripts
│   └── instructions/     # Development guides
└── docs/                 # Documentation
```

---

## Policy Templates

Ready-to-use templates in `policies/`:

- **pii-basic.json** — Basic PII protection (name, email, SSN)
- **healthcare.json** — HIPAA-compliant medical records
- **finance-trust.json** — Financial data with trust-based access
- **gdpr-lite.json** — GDPR-inspired data protection

---

## Advanced Testing

For production-grade testing:

```bash
# Run comprehensive API tests
python dev/scripts/api_test_runner.py

# Test security hardening
python -m pytest tests/security/ -v

# Performance benchmarks
python dev/scripts/benchmark.py
```

See `dev/test-data/` for:
- Production agent profiles
- Industry-specific test data (healthcare, financial, HR)
- Security attack vectors
- Complex nested structures

---

## OSS vs Vault Plus

| Feature                          | OSS | Vault Plus |
|----------------------------------|-----|------------|
| Policy engine (mask, simulate)   | [x] | [x]        |
| Full CLI + Python SDK            | [x] | [x]        |
| Hosted API (FastAPI)             | [ ] | [x]        |
| Secure role-based unmasking      | [ ] | [x]        |
| Interactive TUI playground       | [ ] | [x]        |
| Telemetry + usage analytics      | [ ] | [x]        |
| Policy Marketplace (Q3 2024)     | [ ] | [x]        |

**Vault Plus is free during early access** — [Apply here](https://tally.so/r/3XNBgP)

---

## Documentation

- [Quickstart Guide](docs/00_quickstart.md)
- [CLI Reference](docs/02_cli_interface_.md)
- [Policy Definition](docs/03_policy_definition_.md)
- [API Documentation](docs/01_index.md)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Security

This project includes security hardening against:
- SQL/NoSQL injection
- XSS attacks
- Command injection
- Path traversal
- DoS attacks
- Type confusion
- Special value attacks (Infinity, NaN)

See [SECURITY.md](SECURITY.md) for details.

---

## License

MIT License - see [LICENSE.md](LICENSE.md)

---

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/abbybiswas/marvis-vault-oss/issues)
- Documentation: [docs/](./docs/)
- Community: Coming soon

---

Built with love by the Marvis team