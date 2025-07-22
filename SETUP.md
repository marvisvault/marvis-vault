# Marvis Vault OSS — Local Dev Setup

This guide will help you set up Marvis Vault locally in **developer mode** so you can run, test, and extend the CLI.

---

## Requirements

- **Python 3.11.9** (recommended for compatibility)  
  https://www.python.org/downloads/release/python-3119/
- **Git**
- Optional: **GitHub Desktop** (recommended for Windows)
- OS: Windows, macOS, or Linux

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/marvislabs/marvis-vault-oss.git
cd marvis-vault-oss
```

---

### 2. Create and activate a virtual environment

#### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

#### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3. Install the project in dev mode

```bash
pip install -e ".[dev]"
```

> If using Norton or another antivirus:  
> You may need to whitelist the repo folder or allow `pip.exe` if installation is blocked by Data Protector or SONAR.

---

## Usage

Once installed, you can run the CLI directly:

```bash
vault --help
```

Example command:

```bash
vault redact examples/agents/agent.json \
  --policy templates/pii-basic.json \
  --output redacted.json
```

Also supported:

```bash
vault simulate ...
vault audit ...
vault lint ...
```

---

## Developer Tools

| Task           | Command                |
|----------------|------------------------|
| Run tests      | `pytest tests/ -v`     |
| Auto-format    | `black .`              |
| Type check     | `mypy vault/`          |
| Lint code      | `pylint vault/`        |

---

## Updating Dependencies

```bash
pip install -r requirements.txt --upgrade
```

---

## Troubleshooting

### `pip install -e` fails with `.egg-info` error

This is usually caused by antivirus interference (e.g., Norton Data Protector).

**Fix:**

- Use a clean local directory like `C:\marvis-dev\`
- Or exclude the repo folder or `pip.exe` from antivirus

---

### `python` not recognized

**Fix:**

- Ensure Python is added to your system `PATH`
- Reinstall Python from https://www.python.org/ with the "Add to PATH" box checked

---

## Next Steps

- [ ] Read [Quick Start](./docs/00_quickstart.md) to get started
- [ ] Use the `vault` CLI
- [ ] Understand the Vault CLI using our [Tutorial Guide](./docs/01_index.md)
- [ ] Create or customize redaction/audit policies
- [ ] Extend the CLI with new commands
- [ ] Contribute improvements or file issues

---

Built with love by the Marvis Labs team
