import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from ..engine.policy_engine import evaluate

app = typer.Typer()
console = Console()

def load_agent_context(agent_path: Path) -> dict:
    """Load agent context from JSON file."""
    try:
        return json.loads(agent_path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in agent file: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to load agent file: {str(e)}")

def format_masking_explanation(result) -> str:
    """Format the masking explanation in a readable way."""
    if not result.fields_to_mask:
        return "[green]No fields would be masked[/green] - all conditions are met"
    
    table = Table(title="Masking Analysis")
    table.add_column("Field", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Reason", style="white")
    
    for field in result.fields_to_mask:
        # Find the relevant condition that caused masking
        condition_reason = "Unknown"
        for line in result.reason.split("\n"):
            if field in line and "failed" in line.lower():
                condition_reason = line
                break
        
        table.add_row(
            field,
            "[red]MASKED[/red]",
            condition_reason
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
        result = evaluate(context, policy)
        
        # Display results
        console.print("\n[bold]Policy Evaluation Results[/bold]")
        console.print(f"\nPolicy Status: {'[green]PASS[/green]' if result.status else '[red]FAIL[/red]'}")
        console.print(f"\nEvaluation Details:")
        console.print(result.reason)
        
        # Display masking analysis
        console.print("\n[bold]Masking Analysis[/bold]")
        console.print(format_masking_explanation(result))
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 