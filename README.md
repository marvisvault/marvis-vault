![MIT License](https://img.shields.io/badge/license-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

---

# 🛡️ Marvis Vault OSS

**Programmable compliance infrastructure for agentic AI.**  
Redact, simulate, and audit sensitive data — with policies, trustScore, and role-based logic.  

Built for teams using LLMs, agents, and AI-native workflows.

[🧭 Read the Docs](https://docs.marvisvault.com) &nbsp;&nbsp;&nbsp;&nbsp;[🌐 marvisvault.com](https://marvisvault.com) &nbsp;&nbsp;&nbsp;&nbsp;[🚀 Apply for Vault Plus](https://tally.so/r/3XNBgP)

---

## ⚙️ Core Features

- 🔒 **Redaction Engine** — Mask sensitive fields using role + trustScore
- 🧠 **Policy Language** — Declarative conditions with `&&`, `||`, and field logic
- 🧪 **Simulation CLI** — See what would be masked before sending to the model
- 📜 **Audit Logging** — Structured JSONL logs for every mask/unmask decision
- 🧰 **Python SDK** — Use Vault in agents, pipelines, or AI assistants
- 💼 **Policy Templates** — GDPR, PII, finance, healthcare — ready to drop in

---

## 📦 Install

```bash
git clone https://github.com/abbybiswas/marvis-vault-oss.git
cd marvis-vault-oss
pip install -e .
```
## 🖥️ CLI Usage

```bash
vault simulate --agent examples/agent.json --policy policies/gdpr-lite.json
```
## 📤 Output Example

```txt
🔒 Fields to redact: email, phone  
🧠 Role: auditor | trustScore: 70  
❌ Condition failed: trustScore > 80  
```

---

## 💻 Other Commands

```bash
vault redact --input input.txt --policy policies/finance.json
vault audit --log vault.log --format csv
vault lint --policy policies/healthcare.yaml
```

---

## 🧱 OSS vs Vault Plus

| Feature                          | OSS ✅ | Vault Plus 🔒 |
|----------------------------------|--------|----------------|
| Policy engine (mask, simulate)   | ✅     | ✅  
| Full CLI + Python SDK            | ✅     | ✅  
| Hosted API (FastAPI)             | ❌     | ✅  
| Secure role-based unmasking      | ❌     | ✅  
| Interactive TUI playground       | ❌     | ✅  
| Telemetry + usage analytics      | ❌     | ✅  
| Policy Marketplace (Q3 2024)     | ❌     | ✅  

📬 **Vault Plus is free during early access** — [Apply here](https://tally.so/r/3XNBgP)

---

## 📚 Docs

- [Quickstart](https://docs.marvisvault.com/quickstart)
- [Policy Format](https://docs.marvisvault.com/policy-format)
- [SDK Usage](https://docs.marvisvault.com/sdk-usage)
- [Roadmap](https://docs.marvisvault.com/roadmap)

---

## 🧠 Built For

- AI startups building agent copilots  
- Compliance-conscious LLM apps  
- Enterprises evaluating secure AI stacks  
- Open-source hackers securing pipelines  

---

## 🔬 Tech Stack

- Language: Python 3.10+  
- CLI: [Typer](https://typer.tiangolo.com/)  
- Policy Logic: Pydantic + safe condition parser (no `eval`)  
- Output: Rich terminal formatting, structured JSONL logs  
- Tests: `pytest`, `mypy`, `black`, `isort`  

---

## 🧩 Contributing

Pull requests welcome!  
Check out the [roadmap](https://docs.marvisvault.com/roadmap) and open issues — or suggest your own.

---

## 🧠 About

**Marvis Vault** is built by [@abhigyanbiswas](https://www.linkedin.com/in/abhigyanbiswas/) to bring programmable trust to the age of agentic AI.

Built in public. OSS first.  
Try it → [marvisvault.com](https://marvisvault.com)
