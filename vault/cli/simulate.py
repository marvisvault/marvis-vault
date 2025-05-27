"""
Simulate command for testing policy evaluation.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
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
    """Load agent context from JSON file with comprehensive security validation."""
    try:
        # Import security validators
        from ..utils.security_validators import (
            validate_agent_context, 
            validate_content_size,
            validate_json_depth,
            SecurityValidationError
        )
        
        # Read and validate size
        content = agent_path.read_text()
        validate_content_size(content)
        
        if not content.strip():
            raise ValueError("Agent file is empty")
        
        # Parse JSON
        try:
            context = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in agent file: {str(e)}")
        
        # Validate JSON depth
        validate_json_depth(context)
        
        # Comprehensive security validation
        try:
            validated_context = validate_agent_context(context, source="agent")
            return validated_context
        except SecurityValidationError as e:
            raise ValueError(str(e))
            
    except ValueError:
        # Re-raise ValueError as-is to preserve specific validation messages
        raise
    except Exception as e:
        # For unexpected errors, provide a generic message
        raise ValueError("Failed to load agent file")

def get_context_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key fields for context summary."""
    return {
        "role": context.get("role"),
        "trustScore": context.get("trustScore"),
        "department": context.get("department")
    }

def format_masking_explanation(result, context: Dict[str, Any], verbose: bool = False) -> List[Table]:
    """Format the masking explanation in a readable way."""
    tables = []
    
    # Context Summary Table
    context_table = Table(title="Context Summary")
    context_table.add_column("Field", style="cyan")
    context_table.add_column("Value", style="white")
    
    context_summary = get_context_summary(context)
    for key, value in context_summary.items():
        if value is not None:
            context_table.add_row(key, str(value))
    tables.append(context_table)
    
    # Masking Analysis Table
    masking_table = Table(title="Masking Analysis")
    masking_table.add_column("Field", style="cyan")
    masking_table.add_column("Status", style="yellow")
    masking_table.add_column("Reason", style="white")
    
    if result.unmask_role_override:
        masking_table.add_row(
            "—",
            "[green]CLEAR[/green]",
            f"Unmasked for role '{context.get('role')}'"
        )
    elif not result.fields:
        masking_table.add_row(
            "—",
            "[green]CLEAR[/green]",
            "No fields would be masked — at least one condition passed"
        )
    else:
        for field in result.fields:
            masking_table.add_row(
                field,
                "[red]MASKED[/red]",
                "All conditions failed"
            )
    tables.append(masking_table)
    
    # Condition Evaluation Table (always shown, but with more detail in verbose mode)
    condition_table = Table(title="Condition Evaluation")
    condition_table.add_column("Condition", style="cyan")
    condition_table.add_column("Status", style="yellow")
    if verbose:
        condition_table.add_column("Explanation", style="white")
        condition_table.add_column("Fields Affected", style="white")
    
    if result.unmask_role_override:
        condition_table.add_row(
            "—",
            "[yellow]SKIPPED[/yellow]",
            "Role-based unmask override applied" if verbose else None,
            "—" if verbose else None
        )
    elif not result.condition_results:
        condition_table.add_row(
            "—",
            "[yellow]SKIPPED[/yellow]",
            result.reason or "Condition evaluation was skipped" if verbose else None,
            "—" if verbose else None
        )
    else:
        for condition in result.condition_results:
            status = "[green]PASSED[/green]" if condition.success else "[red]FAILED[/red]"
            if verbose:
                fields = ", ".join(condition.fields) if hasattr(condition, "fields") and condition.fields else "—"
                condition_table.add_row(
                    condition.condition,
                    status,
                    condition.explanation,
                    fields
                )
            else:
                condition_table.add_row(condition.condition, status)
    
    tables.append(condition_table)
    return tables

def format_export_data(context: Dict[str, Any], result, policy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Format simulation results for export."""
    conditions = []
    if not result.unmask_role_override:
        for condition in result.condition_results:
            conditions.append({
                "condition": condition.condition,
                "result": "pass" if condition.success else "fail",
                "explanation": condition.explanation,
                "fields_affected": condition.fields if hasattr(condition, "fields") else []
            })
    
    export_data = {
        "context_summary": get_context_summary(context),
        "roles": [context.get("role")],
        "fields_to_mask": result.fields,
        "conditions": conditions,
        "unmask_role_override": result.unmask_role_override,
        "reason": result.reason
    }
    
    # Add policy metadata if available
    if policy_path:
        try:
            policy_data = json.loads(policy_path.read_text())
            export_data["policy_name"] = policy_data.get("name")
            export_data["template_id"] = policy_data.get("template_id")
        except (json.JSONDecodeError, IOError):
            pass
            
    return export_data

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
                warning_table.add_row(Text("WARNING", style="yellow"), Text(warning, style="yellow"))
            console.print(warning_table)
        
        # Display masking analysis
        console.print("\n[bold]Analysis[/bold]")
        tables = format_masking_explanation(result, context, verbose)
        for table in tables:
            console.print(table)
            console.print()
            
        # Export results if requested
        if export is not None:
            # If no path provided, use default
            export_path = export if export != Path() else get_default_export_path()
            
            # Ensure outputs directory exists
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Format and save export data
            export_data = format_export_data(context, result, policy)
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