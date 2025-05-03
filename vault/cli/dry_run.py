"""
Dry run command for testing policy evaluation.
"""

import sys
from pathlib import Path
from typing import Optional, Set
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from vault.engine.policy_parser import load_policy
from vault.engine.policy_engine import evaluate

app = typer.Typer()
console = Console()

def read_input(input_path: Optional[Path] = None) -> tuple[str, bool]:
    """Read input from file or stdin."""
    if input_path:
        if not input_path.exists():
            raise typer.BadParameter(f"Input file not found: {input_path}")
        
        # Check file size
        size_mb = input_path.stat().st_size / (1024 * 1024)
        if size_mb > 0.1:  # 100KB
            console.print(f"[yellow]Warning: Input file is large ({size_mb:.2f}MB)[/yellow]")
        
        return input_path.read_text(), True
    else:
        return sys.stdin.read(), False

def format_masking_summary(fields_to_mask: Set[str]) -> str:
    """Format the summary of fields to be masked."""
    if not fields_to_mask:
        return "No fields would be masked"
    
    table = Table(title="Fields to be Masked")
    table.add_column("Field", style="cyan")
    table.add_column("Status", style="bold")
    
    for field in sorted(fields_to_mask):
        table.add_row(field, "[red]MASKED[/red]")
    
    return str(table)

def format_masked_preview(text: str, fields_to_mask: Set[str]) -> str:
    """Format a preview of the masked text."""
    if not fields_to_mask:
        return text
    
    # Create a simple preview by replacing field values with [MASKED]
    preview = text
    for field in fields_to_mask:
        # This is a simple placeholder - in a real implementation,
        # you'd want to use proper field detection/regex
        preview = preview.replace(field, "[MASKED]")
    
    return preview

@app.command()
def dry_run(
    input: Optional[Path] = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to input file (if not provided, reads from stdin)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    policy: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to policy file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    preview: bool = typer.Option(
        False,
        "--preview",
        help="Show preview of masked output",
    ),
) -> None:
    """
    Perform a dry run of policy evaluation on input text.
    
    Shows which fields would be masked without actually modifying the input.
    """
    try:
        # Read input
        input_text, is_file = read_input(input)
        
        # Create context
        context = {
            "text": input_text,
            "role": "user",  # Default role
            "trustScore": 50  # Default trust score
        }
        
        # Evaluate policy
        result = evaluate(context, str(policy))
        fields_to_mask = set(result.fields) if not result.success else set()
        
        # Output results
        console.print("\n[bold]Policy Evaluation:[/bold]")
        console.print(Panel(
            f"[{'green' if result.success else 'red'}]{result.reason}[/{'green' if result.success else 'red'}]",
            title="Result"
        ))
        
        console.print("\n[bold]Original Input:[/bold]")
        console.print(Syntax(input_text, "text", theme="monokai"))
        
        console.print("\n[bold]Masking Summary:[/bold]")
        console.print(format_masking_summary(fields_to_mask))
        
        if preview:
            console.print("\n[bold]Masked Preview:[/bold]")
            console.print(Syntax(
                format_masked_preview(input_text, fields_to_mask),
                "text",
                theme="monokai"
            ))
        
    except Exception as e:
        console.print(Panel(
            f"[red]Error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 