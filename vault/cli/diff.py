import json
from pathlib import Path
from typing import Dict, Any, Set, List, Tuple, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

app = typer.Typer()
console = Console()

def validate_evaluation_result(data: Dict[str, Any]) -> None:
    """Validate the structure of an evaluation result."""
    required_fields = {"roles", "fields_to_mask", "conditions"}
    missing_fields = required_fields - set(data.keys())
    if missing_fields:
        raise typer.BadParameter(f"Invalid evaluation result: missing fields {missing_fields}")
    
    if not isinstance(data.get("roles", []), list):
        raise typer.BadParameter("Invalid evaluation result: 'roles' must be a list")
    if not isinstance(data.get("fields_to_mask", []), list):
        raise typer.BadParameter("Invalid evaluation result: 'fields_to_mask' must be a list")
    if not isinstance(data.get("conditions", []), list):
        raise typer.BadParameter("Invalid evaluation result: 'conditions' must be a list")
    
    # Validate condition structure
    for i, condition in enumerate(data.get("conditions", [])):
        if not isinstance(condition, dict):
            raise typer.BadParameter(f"Invalid evaluation result: condition {i} must be a dictionary")
        if "result" not in condition:
            raise typer.BadParameter(f"Invalid evaluation result: condition {i} missing 'result'")
        if condition["result"] not in ["pass", "fail"]:
            raise typer.BadParameter(f"Invalid evaluation result: condition {i} result must be 'pass' or 'fail'")
        # Allow either field or condition string
        if "field" not in condition and "condition" not in condition:
            raise typer.BadParameter(f"Invalid evaluation result: condition {i} missing both 'field' and 'condition'")

def load_evaluation_result(file_path: Path) -> Dict[str, Any]:
    """Load a policy evaluation result from JSON file."""
    try:
        data = json.loads(file_path.read_text())
        validate_evaluation_result(data)
        return data
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

def get_condition_key(condition: Dict[str, Any]) -> str:
    """Get the key to use for condition comparison."""
    # Prefer full condition string if available
    return condition.get("condition", condition.get("field", "<unknown>"))

def format_condition_change(before_result: Optional[str], after_result: Optional[str]) -> Tuple[str, str]:
    """Format a condition change with color tags."""
    if before_result is None:
        return f"[green]added[/green]", f"now {after_result}"
    elif after_result is None:
        return f"[red]removed[/red]", f"was {before_result}"
    elif before_result == after_result:
        return "[yellow]unchanged[/yellow]", f"still {before_result}"
    else:
        # Format transition with colors
        before_color = "[green]" if before_result == "pass" else "[red]"
        after_color = "[green]" if after_result == "pass" else "[red]"
        return (
            f"{before_color}{before_result}[/] → {after_color}{after_result}[/]",
            "evaluation flipped"
        )

def compare_conditions(before: Dict[str, Any], after: Dict[str, Any], verbose: bool = False) -> List[Tuple[str, str, str]]:
    """Compare condition evaluations between two results."""
    changes = []
    
    # Skip comparison if either file has no conditions
    if not before.get("conditions") and not after.get("conditions"):
        return changes
        
    # Build condition maps using full condition strings as keys
    before_conditions = {
        get_condition_key(cond): cond["result"]
        for cond in before.get("conditions", [])
    }
    after_conditions = {
        get_condition_key(cond): cond["result"]
        for cond in after.get("conditions", [])
    }
    
    # Check all conditions that appear in either result
    all_conditions = set(before_conditions.keys()) | set(after_conditions.keys())
    
    for condition in sorted(all_conditions):
        before_result = before_conditions.get(condition)
        after_result = after_conditions.get(condition)
        
        # Skip unchanged conditions unless verbose mode
        if before_result == after_result and not verbose:
            continue
            
        change, details = format_condition_change(before_result, after_result)
        changes.append((condition, change, details))
    
    return changes

def format_diff(
    added_roles: Set[str],
    removed_roles: Set[str],
    added_fields: Set[str],
    removed_fields: Set[str],
    condition_changes: List[Tuple[str, str, str]],
    verbose: bool = False
) -> None:
    """Format and display the diff results."""
    # Create a table for role changes
    if added_roles or removed_roles:
        role_table = Table(title="Role Changes")
        role_table.add_column("Change", style="bold")
        role_table.add_column("Role", style="cyan")
        
        for role in sorted(added_roles):
            role_table.add_row("[green]+[/green]", role)
        for role in sorted(removed_roles):
            role_table.add_row("[red]-[/red]", role)
        
        console.print(role_table)
        console.print()
    
    # Create a table for field changes
    if added_fields or removed_fields:
        field_table = Table(title="Field Changes")
        field_table.add_column("Change", style="bold")
        field_table.add_column("Field", style="cyan")
        
        for field in sorted(added_fields):
            field_table.add_row("[green]+[/green]", field)
        for field in sorted(removed_fields):
            field_table.add_row("[red]-[/red]", field)
        
        console.print(field_table)
        console.print()
    
    # Create a table for condition changes
    if condition_changes:
        condition_table = Table(title="Condition Evaluation Changes")
        condition_table.add_column("Condition", style="cyan")
        condition_table.add_column("Change", style="bold")
        condition_table.add_column("Details", style="white")
        
        for condition, change, details in condition_changes:
            condition_table.add_row(condition, change, details)
        
        console.print(condition_table)
        console.print()
    
    # Show summary
    total_changes = (
        len(added_roles) + len(removed_roles) +
        len(added_fields) + len(removed_fields) +
        len([c for c in condition_changes if "unchanged" not in c[1]])
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show unchanged conditions and additional details",
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
        condition_changes = compare_conditions(before_result, after_result, verbose)
        
        # Display results
        format_diff(
            added_roles,
            removed_roles,
            added_fields,
            removed_fields,
            condition_changes,
            verbose
        )
        
    except typer.BadParameter as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 