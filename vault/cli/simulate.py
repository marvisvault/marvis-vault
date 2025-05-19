"""
Simulate command for testing policy evaluation.
"""

import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from ..engine.policy_engine import evaluate

app = typer.Typer()
console = Console()

def load_agent_context(agent_path: Path) -> dict:
    """Load agent context from JSON file."""
    try:
        context = json.loads(agent_path.read_text())
        
        # Validate required fields
        if "role" not in context:
            raise ValueError("Agent context must contain 'role' field")
        if "trustScore" not in context:
            raise ValueError("Agent context must contain 'trustScore' field")
            
        # Validate trustScore is numeric
        try:
            if context["trustScore"] is not None:
                float(context["trustScore"])
        except (TypeError, ValueError):
            raise ValueError(f"trustScore must be numeric, got {type(context['trustScore'])}")
            
        return context
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in agent file: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to load agent file: {str(e)}")

def format_masking_explanation(result) -> Table:
    """Format the masking explanation in a readable way."""
    if not result.fields:
        table = Table(title="Masking Analysis")
        table.add_column("Status", style="green")
        table.add_row("No fields would be masked - all conditions are met")
        return table
    
    table = Table(title="Masking Analysis")
    table.add_column("Field", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Reason", style="white")
    
    for field in result.fields:
        table.add_row(
            field,
            "[red]MASKED[/red]",
            result.reason
        )
    
    return table

@app.command()
def simulate(
    agent: Path = typer.Option(
        ...,
        "--agent",
        "-a",
        help="Path to agent context JSON file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    policy: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to policy file (JSON or YAML)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """
    Simulate policy evaluation against an agent context.
    
    This command loads an agent's context from a JSON file and evaluates it against
    a policy to determine which fields would be masked and why.
    """
    try:
        # Load agent context
        context = load_agent_context(agent)
        
        # Evaluate policy
        result = evaluate(context, str(policy))
        
        # Display results
        console.print("\n[bold]Policy Evaluation Results[/bold]")
        console.print(Panel(
            f"[{'green' if result.success else 'red'}]{result.reason}[/{'green' if result.success else 'red'}]",
            title="Result"
        ))
        
        # Display any skipped conditions
        if result.skipped_conditions:
            console.print("\n[bold yellow]Warnings[/bold yellow]")
            warning_table = Table(show_header=False, box=None)
            for warning in result.skipped_conditions:
                warning_table.add_row(Text("⚠", style="yellow"), Text(warning, style="yellow"))
            console.print(warning_table)
        
        # Display masking analysis
        console.print("\n[bold]Masking Analysis[/bold]")
        console.print(format_masking_explanation(result))
        
    except Exception as e:
        console.print(Panel(
            f"[red]Error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 