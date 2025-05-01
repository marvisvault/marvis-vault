import pytest
from pathlib import Path
import sys
from io import StringIO
from unittest.mock import patch
from vault.cli.redact import redact, read_input, write_output, redact_text
import json

@pytest.fixture
def valid_policy(tmp_path):
    """Create a valid policy file for testing."""
    policy = {
        "mask": "****",
        "unmask_roles": ["admin"],
        "conditions": [
            {
                "field": "trust_score",
                "operator": ">=",
                "value": 80
            }
        ]
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return path

@pytest.fixture
def input_file(tmp_path):
    """Create an input file for testing."""
    content = """trust_score: 75
role: admin
department: IT
email: user@example.com
phone: 123-456-7890
"""
    path = tmp_path / "input.txt"
    path.write_text(content)
    return path

def test_read_input_from_file(input_file):
    """Test reading input from a file."""
    content = read_input(input_file)
    assert "trust_score: 75" in content
    assert "role: admin" in content

def test_read_input_from_stdin():
    """Test reading input from stdin."""
    input_text = "trust_score: 75\nrole: admin"
    with patch("sys.stdin", StringIO(input_text)):
        content = read_input(None)
        assert "trust_score: 75" in content
        assert "role: admin" in content

def test_write_output_to_file(tmp_path):
    """Test writing output to a file."""
    output_path = tmp_path / "output.txt"
    content = "test content"
    
    # Test writing to new file
    write_output(content, output_path)
    assert output_path.read_text() == content
    
    # Test overwrite with force
    new_content = "new content"
    write_output(new_content, output_path, force=True)
    assert output_path.read_text() == new_content

def test_write_output_to_stdout(capsys):
    """Test writing output to stdout."""
    content = "test content"
    write_output(content, None)
    captured = capsys.readouterr()
    assert captured.out == content

def test_redact_text():
    """Test text redaction."""
    text = """trust_score: 75
role: admin
email: user@example.com
"""
    fields_to_mask = ["trust_score", "email"]
    redacted = redact_text(text, fields_to_mask)
    
    assert "trust_score: [REDACTED]" in redacted
    assert "email: [REDACTED]" in redacted
    assert "role: admin" in redacted  # Should not be redacted

def test_redact_command_file_to_file(tmp_path, input_file, valid_policy):
    """Test redact command with file input and output."""
    output_path = tmp_path / "output.txt"
    
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", str(valid_policy), "--output", str(output_path)]):
        redact()
    
    output = output_path.read_text()
    assert "trust_score: [REDACTED]" in output
    assert "role: admin" in output  # Should not be redacted

def test_redact_command_stdin_to_stdout(capsys, valid_policy):
    """Test redact command with stdin input and stdout output."""
    input_text = "trust_score: 75\nrole: admin"
    
    with patch("sys.stdin", StringIO(input_text)):
        with patch("sys.argv", ["redact", "--policy", str(valid_policy)]):
            redact()
    
    captured = capsys.readouterr()
    assert "trust_score: [REDACTED]" in captured.out
    assert "role: admin" in captured.out  # Should not be redacted

def test_redact_command_missing_policy(tmp_path, input_file):
    """Test redact command with missing policy file."""
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", "nonexistent.json"]):
        with pytest.raises(SystemExit):
            redact()

def test_redact_command_invalid_policy(tmp_path, input_file):
    """Test redact command with invalid policy file."""
    invalid_policy = tmp_path / "invalid.json"
    invalid_policy.write_text("{invalid json}")
    
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", str(invalid_policy)]):
        with pytest.raises(SystemExit):
            redact()

def test_redact_command_safe_overwrite(tmp_path, input_file, valid_policy):
    """Test redact command safe overwrite behavior."""
    output_path = tmp_path / "output.txt"
    output_path.write_text("existing content")
    
    # Test without force - should prompt
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", str(valid_policy), "--output", str(output_path)]):
        with patch("rich.prompt.Confirm.ask", return_value=False):
            with pytest.raises(SystemExit):
                redact()
    
    # Test with force - should overwrite
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", str(valid_policy), "--output", str(output_path), "--force"]):
        redact()
    
    output = output_path.read_text()
    assert "trust_score: [REDACTED]" in output

def test_redact_command_preserves_formatting(tmp_path, input_file, valid_policy):
    """Test redact command preserves formatting."""
    # Create input with specific formatting
    formatted_input = """trust_score: 75
role: admin
email: user@example.com
phone: 123-456-7890
"""
    input_file.write_text(formatted_input)
    
    output_path = tmp_path / "output.txt"
    with patch("sys.argv", ["redact", "--input", str(input_file), "--policy", str(valid_policy), "--output", str(output_path)]):
        redact()
    
    output = output_path.read_text()
    # Check that line breaks and indentation are preserved
    assert output.count("\n") == formatted_input.count("\n")
    assert "trust_score: [REDACTED]" in output
    assert "role: admin" in output
    assert "email: [REDACTED]" in output
    assert "phone: 123-456-7890" in output 