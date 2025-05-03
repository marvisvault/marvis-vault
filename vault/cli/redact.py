"""
Redact command for masking sensitive data.
"""

import sys
from pathlib import Path
from typing import Optional, TextIO
import typer
from rich.console import Console
from rich.prompt import Confirm
from ..engine.policy_engine import evaluate
import re

app = typer.Typer()
console = Console()

def read_input(input_path: Optional[Path]) -> str:
    """Read input from file or stdin."""
    if input_path:
        return input_path.read_text()
    return sys.stdin.read()

def write_output(content: str, output_path: Optional[Path], force: bool = False) -> None:
    """Write output to file or stdout."""
    if output_path:
        if output_path.exists() and not force:
            if not Confirm.ask(f"File {output_path} exists. Overwrite?"):
                console.print("[yellow]Operation cancelled[/yellow]")
                sys.exit(1)
        output_path.write_text(content)
    else:
        sys.stdout.write(content)

def redact_text(text: str, fields_to_mask: list[str]) -> str:
    """Apply redaction to text while preserving formatting."""
    # Split text into lines to preserve formatting
    lines = text.splitlines()
    redacted_lines = []
    
    for line in lines:
        # For each field to mask, replace its value with [REDACTED]
        redacted_line = line
        for field in fields_to_mask:
            # Simple pattern matching - can be enhanced based on requirements
            pattern = f"{field}[:=]\\s*[^\\s,;]+"
            redacted_line = re.sub(pattern, f"{field}: [REDACTED]", redacted_line)
        redacted_lines.append(redacted_line)
    
    return "\n".join(redacted_lines)

@app.command()
def redact(
    input: Optional[Path] = typer.Option(
        None,
        "--input",
        "-i",
        help="Input file path. If not provided, reads from stdin.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    policy: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Policy file path (JSON or YAML)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. If not provided, writes to stdout.",
        file_okay=True,
        dir_okay=False,
        writable=True,
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force overwrite of output file if it exists.",
    ),
) -> None:
    """
    Redact sensitive information from input text based on policy rules.
    
    The input can be read from a file or stdin, and the output can be written
    to a file or stdout. The policy file determines which fields should be redacted.
    """
    try:
        # Read input
        input_text = read_input(input)
        
        # Create context from input text
        context = {}
        for line in input_text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                context[key.strip()] = value.strip()
        
        # Evaluate policy
        result = evaluate(context, str(policy))
        
        # Apply redaction
        redacted_text = redact_text(input_text, result.fields)
        
        # Write output
        write_output(redacted_text, output, force)
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    app() 