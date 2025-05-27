# Marvis Vault OSS - Local Development Setup

## Quick Start (5 Minutes)

### Prerequisites
- **Python 3.11.9** (recommended for compatibility)
- **Git** 
- **Terminal/Command Prompt**

### Installation Commands

```bash
# 1. Clone the repository
git clone https://github.com/marvislabs/marvis-vault-oss.git
cd marvis-vault-oss

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.venv\Scripts\Activate.ps1

# 4. Install in development mode
pip install -e ".[dev]"

# 5. Verify installation
vault --help
```

### Test Your Installation

```bash
# Test basic functionality
vault simulate --agent examples/agents/agent.json --policy vault/templates/pii-basic.json

# Expected output should show policy evaluation results
```

## Detailed Setup Instructions

### Step 1: Environment Preparation

#### Python Version Check
```bash
python --version
# Should output: Python 3.11.9 (or 3.10+)
```

If you don't have Python 3.11.9:
- Download from: https://www.python.org/downloads/release/python-3119/
- **Windows users**: Check "Add to PATH" during installation

#### Git Check
```bash
git --version
# Should output git version info
```

### Step 2: Repository Setup

```bash
# Clone with proper remote URL
git clone https://github.com/marvislabs/marvis-vault-oss.git
cd marvis-vault-oss

# Verify you're in the right directory
ls -la
# Should see: README.md, vault/, tests/, examples/, etc.
```

### Step 3: Virtual Environment

#### Why Use Virtual Environment?
- Isolates project dependencies
- Prevents conflicts with other Python projects
- Makes dependency management easier

#### Create and Activate
```bash
# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (Windows Command Prompt)
.venv\Scripts\activate.bat

# Verify activation (should show .venv in prompt)
which python  # Linux/macOS
where python   # Windows
```

### Step 4: Install Dependencies

```bash
# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Alternative if above fails:
pip install -e .
pip install -r requirements.txt
```

#### What This Installs
- **Core dependencies**: typer, rich, pydantic, pyyaml
- **Development tools**: pytest, coverage tools
- **Marvis Vault**: Installs as editable package

### Step 5: Verification

```bash
# Check vault command is available
vault --version

# Test CLI commands
vault --help

# Test with example data
vault lint --policy vault/templates/pii-basic.json

# Run test suite
pytest tests/ -v
```

## Common Issues & Solutions

### Issue: `pip install -e .` fails with `.egg-info` error

**Cause**: Antivirus interference (especially Norton)

**Solution**:
```bash
# Try clean directory
mkdir C:\marvis-dev
cd C:\marvis-dev
git clone https://github.com/marvislabs/marvis-vault-oss.git
cd marvis-vault-oss
pip install -e .
```

Or exclude the repo folder from antivirus scanning.

### Issue: `python` command not recognized

**Solutions**:
```bash
# Try python3 instead
python3 --version
python3 -m venv .venv

# On Windows, try py launcher
py --version
py -m venv .venv
```

**Permanent fix**: Add Python to system PATH during installation.

### Issue: Virtual environment not activating

**Linux/macOS**:
```bash
# Make sure you use 'source'
source .venv/bin/activate

# Not just:
.venv/bin/activate  # This won't work
```

**Windows**:
```powershell
# Use full path
.\.venv\Scripts\Activate.ps1

# Or navigate first
cd .venv\Scripts
.\Activate.ps1
cd ..\..
```

### Issue: Module not found errors

**Solution**: Ensure you're in the right directory and virtual environment is activated
```bash
# Check current directory
pwd
ls -la  # Should see vault/ directory

# Check virtual environment
which python  # Should point to .venv/bin/python

# Reinstall if needed
pip install -e .
```

## Development Workflow

### Daily Development Commands

```bash
# Start working (activate env)
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\Activate.ps1  # Windows

# Run tests
pytest tests/ -v

# Code formatting
black vault/

# Type checking
mypy vault/

# Lint code
pylint vault/

# End working (deactivate env)
deactivate
```

### Testing Your Changes

```bash
# Test specific functionality
vault redact --input examples/agents/agent.json --policy vault/templates/pii-basic.json --output test_output.json

# Validate the output
cat test_output.json

# Clean up
rm test_output.json
```

### Making Code Changes

1. **Edit files** in `vault/` directory
2. **Test changes**: `pytest tests/`
3. **Format code**: `black vault/`
4. **Check types**: `mypy vault/`
5. **Test CLI**: `vault --help`

Since you installed with `-e` (editable), changes take effect immediately!

## IDE Setup Recommendations

### VS Code
1. Install Python extension
2. Select Python interpreter: `Ctrl+Shift+P` → "Python: Select Interpreter" → Choose `.venv/bin/python`
3. Install recommended extensions:
   - Python
   - Pylance
   - Black Formatter

### PyCharm
1. Open project folder
2. Configure interpreter: Settings → Project → Python Interpreter → Add → Existing environment → `.venv/bin/python`

## Next Steps

Once setup is complete:

1. **Read Documentation**: Start with `docs/00_quickstart.md`
2. **Try Examples**: Experiment with files in `examples/`
3. **Run Tests**: `pytest tests/ -v`
4. **Explore Code**: Start with `vault/cli/main.py`
5. **Make Changes**: Try modifying a template in `vault/templates/`

## Getting Help

### Documentation
- [Quick Start](../docs/00_quickstart.md)
- [Tutorial Index](../docs/01_index.md)
- [Contributing Guide](../CONTRIBUTING.md)

### Common Commands Reference
```bash
# Policy validation
vault lint --policy <policy_file>

# Data redaction
vault redact --input <input_file> --policy <policy_file> --output <output_file>

# Policy simulation
vault simulate --agent <agent_file> --policy <policy_file>

# Audit log review
vault audit --log <log_file>

# Run all tests
pytest tests/ -v

# Format all code
black .

# Type check
mypy vault/
```

This setup should get you up and running with Marvis Vault OSS in under 10 minutes!