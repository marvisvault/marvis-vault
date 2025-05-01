import json
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from ..engine.policy_parser import parse_policy

app = typer.Typer()
console = Console()

# Required fields in policy
REQUIRED_FIELDS = {"mask", "unmask_roles", "conditions"}

def validate_required_fields(policy: Dict[str, Any]) -> List[str]:
    """Validate that all required fields exist."""
    errors = []
    missing_fields = REQUIRED_FIELDS - set(policy.keys())
    if missing_fields:
        errors.append(f"Missing required fields: {', '.join(missing_fields)}")
    return errors

def validate_field_types(policy: Dict[str, Any]) -> List[str]:
    """Validate that field types are correct."""
    errors = []
    
    # Check mask field
    if "mask" in policy and not isinstance(policy["mask"], str):
        errors.append("Field 'mask' must be a string")
    
    # Check unmask_roles field
    if "unmask_roles" in policy:
        if not isinstance(policy["unmask_roles"], list):
            errors.append("Field 'unmask_roles' must be a list")
        elif not all(isinstance(role, str) for role in policy["unmask_roles"]):
            errors.append("All elements in 'unmask_roles' must be strings")
    
    # Check conditions field
    if "conditions" in policy:
        if not isinstance(policy["conditions"], list):
            errors.append("Field 'conditions' must be a list")
        else:
            for i, condition in enumerate(policy["conditions"]):
                if not isinstance(condition, dict):
                    errors.append(f"Condition {i} must be a dictionary")
                else:
                    required = {"field", "operator", "value"}
                    missing = required - set(condition.keys())
                    if missing:
                        errors.append(f"Condition {i} missing required fields: {', '.join(missing)}")
    
    return errors

def validate_lists_not_empty(policy: Dict[str, Any]) -> List[str]:
    """Validate that lists are not empty."""
    errors = []
    if "unmask_roles" in policy and not policy["unmask_roles"]:
        errors.append("Field 'unmask_roles' cannot be empty")
    if "conditions" in policy and not policy["conditions"]:
        errors.append("Field 'conditions' cannot be empty")
    return errors

def check_unreachable_conditions(policy: Dict[str, Any]) -> List[str]:
    """Check for logically unreachable conditions."""
    warnings = []
    if "conditions" in policy:
        # Check for contradictory conditions on the same field
        field_conditions = {}
        for i, condition in enumerate(policy["conditions"]):
            field = condition.get("field")
            if field:
                if field not in field_conditions:
                    field_conditions[field] = []
                field_conditions[field].append((i, condition))
        
        for field, conditions in field_conditions.items():
            if len(conditions) > 1:
                # Check for contradictory conditions
                for i, (cond1_idx, cond1) in enumerate(conditions):
                    for cond2_idx, cond2 in conditions[i+1:]:
                        if (cond1["operator"] == "==" and cond2["operator"] == "==" and 
                            cond1["value"] != cond2["value"]):
                            warnings.append(
                                f"Conditions {cond1_idx} and {cond2_idx} on field '{field}' "
                                f"are contradictory (== {cond1['value']} and == {cond2['value']})"
                            )
    return warnings

def check_overbroad_unmask_roles(policy: Dict[str, Any]) -> List[str]:
    """Check for overbroad unmask_roles."""
    warnings = []
    if "unmask_roles" in policy and "*" in policy["unmask_roles"]:
        warnings.append("unmask_roles contains '*' which is overbroad")
    return warnings

def check_missing_context_fields(policy: Dict[str, Any]) -> List[str]:
    """Check for fields to mask that might be missing from context."""
    warnings = []
    if "conditions" in policy:
        fields_to_mask = {cond["field"] for cond in policy["conditions"]}
        # Add warning for each field that might need context
        for field in fields_to_mask:
            warnings.append(f"Field '{field}' might need to be present in context")
    return warnings

def format_validation_results(
    errors: List[str],
    warnings: List[str]
) -> None:
    """Format and display validation results."""
    if errors or warnings:
        # Create a table for errors
        if errors:
            error_table = Table(title="Errors", style="red")
            error_table.add_column("Error", style="red")
            for error in errors:
                error_table.add_row(error)
            console.print(error_table)
        
        # Create a table for warnings
        if warnings:
            warning_table = Table(title="Warnings", style="yellow")
            warning_table.add_column("Warning", style="yellow")
            for warning in warnings:
                warning_table.add_row(warning)
            console.print(warning_table)
        
        # Show summary
        console.print(Panel(
            f"Found {len(errors)} error(s) and {len(warnings)} warning(s)",
            style="red" if errors else "yellow"
        ))
    else:
        console.print("[green]Policy is valid![/green]")

@app.command()
def lint(
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
    Lint a policy file for potential issues.
    
    Validates the policy structure, checks for common issues, and provides
    warnings about potential problems.
    """
    try:
        # Parse policy
        policy_data = parse_policy(policy)
        
        # Run validations
        errors = []
        warnings = []
        
        errors.extend(validate_required_fields(policy_data))
        errors.extend(validate_field_types(policy_data))
        errors.extend(validate_lists_not_empty(policy_data))
        
        warnings.extend(check_unreachable_conditions(policy_data))
        warnings.extend(check_overbroad_unmask_roles(policy_data))
        warnings.extend(check_missing_context_fields(policy_data))
        
        # Display results
        format_validation_results(errors, warnings)
        
        # Exit with appropriate code
        if errors:
            raise typer.Exit(1)
        elif warnings:
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 