import json
from pathlib import Path
from typing import Dict, Any, Set, List, Tuple
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

app = typer.Typer()
console = Console()

def load_evaluation_result(file_path: Path) -> Dict[str, Any]:
    """Load a policy evaluation result from JSON file."""
    try:
        return json.loads(file_path.read_text())
    except json.JSONDecodeError as e:
        raise typer.BadParameter(f"Invalid JSON in {file_path}: {str(e)}")
    except Exception as e:
        raise typer.BadParameter(f"Failed to load {file_path}: {str(e)}")

def compare_roles(before: Dict[str, Any], after: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """Compare roles between two evaluation results."""
    before_roles = set(before.get("roles", []))
    after_roles = set(after.get("roles", []))
    return after_roles - before_roles, before_roles - after_roles

def compare_fields(before: Dict[str, Any], after: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """Compare masked fields between two evaluation results."""
    before_fields = set(before.get("fields_to_mask", []))
    after_fields = set(after.get("fields_to_mask", []))
    return after_fields - before_fields, before_fields - after_fields

def compare_conditions(before: Dict[str, Any], after: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Compare condition evaluations between two results."""
    changes = []
    before_conditions = {cond["field"]: cond["result"] for cond in before.get("conditions", [])}
    after_conditions = {cond["field"]: cond["result"] for cond in after.get("conditions", [])}
    
    # Check all fields that appear in either result
    all_fields = set(before_conditions.keys()) | set(after_conditions.keys())
    
    for field in all_fields:
        before_result = before_conditions.get(field)
        after_result = after_conditions.get(field)
        
        if before_result != after_result:
            if before_result is None:
                changes.append((field, "added", after_result))
            elif after_result is None:
                changes.append((field, "removed", before_result))
            else:
                changes.append((field, f"{before_result} → {after_result}", ""))
    
    return changes

def format_diff(
    added_roles: Set[str],
    removed_roles: Set[str],
    added_fields: Set[str],
    removed_fields: Set[str],
    condition_changes: List[Tuple[str, str, str]]
) -> None:
    """Format and display the diff results."""
    # Create a table for role changes
    if added_roles or removed_roles:
        role_table = Table(title="Role Changes")
        role_table.add_column("Change", style="bold")
        role_table.add_column("Role", style="cyan")
        
        for role in added_roles:
            role_table.add_row("[green]+[/green]", role)
        for role in removed_roles:
            role_table.add_row("[red]-[/red]", role)
        
        console.print(role_table)
    
    # Create a table for field changes
    if added_fields or removed_fields:
        field_table = Table(title="Field Changes")
        field_table.add_column("Change", style="bold")
        field_table.add_column("Field", style="cyan")
        
        for field in added_fields:
            field_table.add_row("[green]+[/green]", field)
        for field in removed_fields:
            field_table.add_row("[red]-[/red]", field)
        
        console.print(field_table)
    
    # Create a table for condition changes
    if condition_changes:
        condition_table = Table(title="Condition Changes")
        condition_table.add_column("Field", style="cyan")
        condition_table.add_column("Change", style="bold")
        condition_table.add_column("Details", style="white")
        
        for field, change, details in condition_changes:
            condition_table.add_row(field, change, details)
        
        console.print(condition_table)
    
    # Show summary
    total_changes = (
        len(added_roles) + len(removed_roles) +
        len(added_fields) + len(removed_fields) +
        len(condition_changes)
    )
    
    if total_changes == 0:
        console.print("[yellow]No changes found[/yellow]")
    else:
        console.print(Panel(
            f"Found {total_changes} change(s)",
            style="green" if total_changes > 0 else "yellow"
        ))

@app.command()
def diff(
    before: Path = typer.Option(
        ...,
        "--before",
        "-b",
        help="Path to before evaluation result file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    after: Path = typer.Option(
        ...,
        "--after",
        "-a",
        help="Path to after evaluation result file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """
    Compare two policy evaluation results.
    
    Shows differences in roles, masked fields, and condition evaluations
    between two policy evaluation results.
    """
    try:
        # Load evaluation results
        before_result = load_evaluation_result(before)
        after_result = load_evaluation_result(after)
        
        # Compare results
        added_roles, removed_roles = compare_roles(before_result, after_result)
        added_fields, removed_fields = compare_fields(before_result, after_result)
        condition_changes = compare_conditions(before_result, after_result)
        
        # Display results
        format_diff(
            added_roles,
            removed_roles,
            added_fields,
            removed_fields,
            condition_changes
        )
        
    except typer.BadParameter as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 