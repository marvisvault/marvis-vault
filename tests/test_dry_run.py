import pytest
from pathlib import Path
import json
from unittest.mock import patch, mock_open
from vault.cli.dry_run import (
    read_input,
    format_masking_summary,
    format_masked_preview,
    dry_run
)

@pytest.fixture
def valid_policy(tmp_path):
    """Create a valid policy file."""
    policy = {
        "mask": ["ssn", "email", "phone"],
        "unmaskRoles": ["admin"],
        "conditions": [
            {"field": "trust_score", "operator": ">=", "value": 80}
        ]
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def small_input(tmp_path):
    """Create a small input file."""
    text = "User: john@example.com\nSSN: 123-45-6789\nPhone: 555-1234"
    path = tmp_path / "input.txt"
    path.write_text(text)
    return path

@pytest.fixture
def large_input(tmp_path):
    """Create a large input file (>100KB)."""
    # Create a large text by repeating a pattern
    text = "Line of text\n" * 10000
    path = tmp_path / "large.txt"
    path.write_text(text)
    return path

@pytest.fixture
def invalid_policy(tmp_path):
    """Create an invalid policy file."""
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json}")
    return path

def test_read_input_file(small_input):
    """Test reading input from a file."""
    text, is_file = read_input(small_input)
    assert is_file
    assert "john@example.com" in text

def test_read_input_stdin():
    """Test reading input from stdin."""
    with patch("sys.stdin.read", return_value="stdin input"):
        text, is_file = read_input(None)
        assert not is_file
        assert text == "stdin input"

def test_read_input_large_file(large_input, capsys):
    """Test reading a large input file."""
    text, is_file = read_input(large_input)
    assert is_file
    captured = capsys.readouterr()
    assert "Warning: Input file is large" in captured.out

def test_read_input_missing_file():
    """Test reading a missing input file."""
    with pytest.raises(Exception):
        read_input(Path("nonexistent.txt"))

def test_format_masking_summary():
    """Test formatting the masking summary."""
    fields = {"ssn", "email"}
    summary = format_masking_summary(fields)
    assert "Fields to be Masked" in summary
    assert "ssn" in summary
    assert "email" in summary
    assert "MASKED" in summary

def test_format_masking_summary_empty():
    """Test formatting an empty masking summary."""
    summary = format_masking_summary(set())
    assert "No fields would be masked" in summary

def test_format_masked_preview():
    """Test formatting the masked preview."""
    text = "Email: test@example.com\nSSN: 123-45-6789"
    fields = {"email", "ssn"}
    preview = format_masked_preview(text, fields)
    assert "[MASKED email]" in preview
    assert "[MASKED ssn]" in preview

def test_dry_run_valid(small_input, valid_policy, capsys):
    """Test dry-run with valid input and policy."""
    with patch("sys.argv", ["dry-run", "--input", str(small_input), "--policy", str(valid_policy)]):
        dry_run()
    captured = capsys.readouterr()
    assert "Original Input" in captured.out
    assert "Masking Summary" in captured.out
    assert "Fields to be Masked" in captured.out

def test_dry_run_preview(small_input, valid_policy, capsys):
    """Test dry-run with preview option."""
    with patch("sys.argv", ["dry-run", "--input", str(small_input), "--policy", str(valid_policy), "--preview"]):
        dry_run()
    captured = capsys.readouterr()
    assert "Masked Preview" in captured.out
    assert "[MASKED" in captured.out

def test_dry_run_missing_input(valid_policy, capsys):
    """Test dry-run with missing input file."""
    with patch("sys.argv", ["dry-run", "--input", "nonexistent.txt", "--policy", str(valid_policy)]):
        with pytest.raises(SystemExit):
            dry_run()
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_dry_run_missing_policy(small_input, capsys):
    """Test dry-run with missing policy file."""
    with patch("sys.argv", ["dry-run", "--input", str(small_input), "--policy", "nonexistent.json"]):
        with pytest.raises(SystemExit):
            dry_run()
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_dry_run_invalid_policy(small_input, invalid_policy, capsys):
    """Test dry-run with invalid policy file."""
    with patch("sys.argv", ["dry-run", "--input", str(small_input), "--policy", str(invalid_policy)]):
        with pytest.raises(SystemExit):
            dry_run()
    captured = capsys.readouterr()
    assert "Error" in captured.out

def test_dry_run_stdin(valid_policy, capsys):
    """Test dry-run with stdin input."""
    with patch("sys.stdin.read", return_value="stdin input"):
        with patch("sys.argv", ["dry-run", "--policy", str(valid_policy)]):
            dry_run()
    captured = capsys.readouterr()
    assert "Original Input" in captured.out
    assert "stdin input" in captured.out 