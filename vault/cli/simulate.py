"""
Simulate command for testing policy evaluation.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime
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

def format_masking_explanation(result, verbose: bool = False) -> Table:
    """Format the masking explanation in a readable way."""
   
    if not result.fields:
        table = Table(title="Masking Analysis")
        table.add_column("Field", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Reason", style="white")

        table.add_row(
            "—",
            "[green]CLEAR[/green]",
             "No fields would be masked — at least one condition passed"
        )

        # Always construct condition table in verbose mode  
        if verbose:
            condition_table = Table(title="Condition Evaluation Details")
            condition_table.add_column("Condition", style="cyan")
            condition_table.add_column("Status", style="yellow")
            condition_table.add_column("Explanation", style="white")

            if not result.condition_results:
                condition_table.add_row(
                    "—",
                    "[yellow]SKIPPED[/yellow]",
                    result.reason or "Condition evaluation was skipped"
                )
            else:
                for condition in result.condition_results:
                    condition_table.add_row(
                        condition.condition,
                        "[green]PASSED[/green]" if condition.success else "[red]FAILED[/red]",
                        condition.explanation
                    )

            return [table, condition_table]
        else:
            return table

   
    # Basic Masking Analysis Table
    table = Table(title="Masking Analysis")
    table.add_column("Field", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Reason", style="white")
    
    # Show fields that would be masked
    for field in result.fields:
        table.add_row(
            field,
            "[red]MASKED[/red]",
            "All conditions failed"
        )
    
    # In verbose mode, show condition evaluation details
    if verbose:
        condition_table = Table(title="Condition Evaluation Details")
        condition_table.add_column("Condition", style="cyan")
        condition_table.add_column("Status", style="yellow")
        condition_table.add_column("Explanation", style="white")
        
         # Fallback row for skipped condition evaluation
        if not result.condition_results:
            condition_table.add_row(
                "—",
                "[yellow]SKIPPED[/yellow]",
                result.reason or "Condition evaluation was skipped"
            )

        # Show passed conditions first
        for condition in result.condition_results:
            if condition.success:
                condition_table.add_row(
                    condition.condition,
                    "[green]PASSED[/green]",
                    condition.explanation
                )
        
        # Then show failed conditions
        for condition in result.condition_results:
            if not condition.success:
                condition_table.add_row(
                    condition.condition,
                    "[red]FAILED[/red]",
                    condition.explanation
                )
                
        return [table, condition_table]
        
    return table

def format_export_data(context: Dict[str, Any], result) -> Dict[str, Any]:
    """Format simulation results for export."""
    # Extract field names from conditions
    conditions = []
    for condition in result.condition_results:
        # Extract field name from condition string
        # This is a simple heuristic - we take the first identifier before any operator
        field = condition.condition.split()[0]
        conditions.append({
            "field": field,
            "result": "pass" if condition.success else "fail"
        })
    
    return {
        "roles": [context.get("role")],
        "fields_to_mask": result.fields,
        "conditions": conditions
    }

def get_default_export_path() -> Path:
    """Generate default export path with timestamp."""
    timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
    return Path("outputs") / f"simulate_{timestamp}.json"

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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed condition evaluation results",
    ),
    export: Optional[Path] = typer.Option(
        None,
        "--export",
        "-e",
        help="Export results to JSON file (default: outputs/simulate_<timestamp>.json)",
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
        tables = format_masking_explanation(result, verbose)
        if isinstance(tables, list):
            for table in tables:
                console.print(table)
                console.print()
        else:
            console.print(tables)
            
        # Export results if requested
        if export is not None:
            # If no path provided, use default
            export_path = export if export != Path() else get_default_export_path()
            
            # Ensure outputs directory exists
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Format and save export data
            export_data = format_export_data(context, result)
            export_path.write_text(json.dumps(export_data, indent=2))
            
            console.print(f"\n[green]Results exported to:[/green] {export_path}")
        
    except Exception as e:
        console.print(Panel(
            f"[red]Error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 