"""
Tests for the lint command.
"""

import pytest
from typer.testing import CliRunner
from vault.cli.main import app
from pathlib import Path

runner = CliRunner()

def test_valid_policy_no_warnings():
    """Test lint command with a valid policy that has no warnings."""
    result = runner.invoke(app, ["lint", "-p", "examples/agents/agent.json"])
    assert result.exit_code == 0
    assert "Policy is valid!" in result.stdout
    assert "Found 0 error(s) and 0 warning(s)" in result.stdout

def test_valid_policy_with_warnings():
    """Test lint command with a valid policy that has warnings."""
    result = runner.invoke(app, ["lint", "-p", "templates/pii-basic.json"])
    assert result.exit_code == 0
    assert "Found 0 error(s)" in result.stdout
    assert "warning(s)" in result.stdout  # Number of warnings may vary
    assert "Warning" in result.stdout

def test_valid_policy_strict_mode():
    """Test lint command with a valid policy that has warnings in strict mode."""
    result = runner.invoke(app, ["lint", "-p", "templates/pii-basic.json", "--strict"])
    assert result.exit_code == 1
    assert "Found 0 error(s)" in result.stdout
    assert "warning(s)" in result.stdout
    assert "Warning" in result.stdout

def test_malformed_policy():
    """Test lint command with a malformed policy file."""
    result = runner.invoke(app, ["lint", "-p", "examples/agents/malformed_policy.json"])
    assert result.exit_code == 1
    assert "Error" in result.stdout

def test_nonexistent_policy():
    """Test lint command with a nonexistent policy file."""
    result = runner.invoke(app, ["lint", "-p", "does_not_exist.json"])
    assert result.exit_code == 1
    assert "Error" in result.stdout 