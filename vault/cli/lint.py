"""
Lint command for validating policy files.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from ..engine.policy_parser import parse_policy
from pydantic import BaseModel

app = typer.Typer()
console = Console()

# Required fields in policy
REQUIRED_FIELDS = {"mask", "unmask_roles", "conditions"}

class Policy(BaseModel):
    mask: List[str]
    unmask_roles: List[str]
    conditions: List[str]

def validate_required_fields(policy: Policy) -> List[str]:
    """Validate that all required fields exist."""
    errors = []
    missing_fields = REQUIRED_FIELDS - set(policy.model_dump().keys())
    if missing_fields:
        errors.append(f"Missing required fields: {', '.join(missing_fields)}")
    return errors

def validate_field_types(policy: Policy) -> List[str]:
    """Validate that field types are correct."""
    errors = []
    
    # Check mask field
    if not isinstance(policy.mask, list):
        errors.append("Field 'mask' must be a list")
    elif not all(isinstance(field, str) for field in policy.mask):
        errors.append("All elements in 'mask' must be strings")
    
    # Check unmask_roles field
    if not isinstance(policy.unmask_roles, list):
        errors.append("Field 'unmask_roles' must be a list")
    elif not all(isinstance(role, str) for role in policy.unmask_roles):
        errors.append("All elements in 'unmask_roles' must be strings")
    
    # Check conditions field
    if not isinstance(policy.conditions, list):
        errors.append("Field 'conditions' must be a list")
    elif not all(isinstance(condition, str) for condition in policy.conditions):
        errors.append("All elements in 'conditions' must be strings")
    
    return errors

def validate_lists_not_empty(policy: Policy) -> List[str]:
    """Validate that lists are not empty."""
    errors = []
    if not policy.unmask_roles:
        errors.append("Field 'unmask_roles' cannot be empty")
    if not policy.conditions:
        errors.append("Field 'conditions' cannot be empty")
    return errors

def check_unreachable_conditions(policy: Policy) -> List[str]:
    """Check for logically unreachable conditions."""
    warnings = []
    for i, condition in enumerate(policy.conditions):
        if "&&" in condition:
            warnings.append(f"Condition {i} uses AND (&&) which might make it harder to satisfy")
        if "||" in condition:
            warnings.append(f"Condition {i} uses OR (||) which might make it too permissive")
    return warnings

def check_overbroad_unmask_roles(policy: Policy) -> List[str]:
    """Check for overbroad unmask_roles."""
    warnings = []
    if "*" in policy.unmask_roles:
        warnings.append("unmask_roles contains '*' which is overbroad")
    return warnings

def check_missing_context_fields(policy: Policy) -> List[str]:
    """Check for fields to mask that might be missing from context."""
    warnings = []
    for i, condition in enumerate(policy.conditions):
        if "role" in condition:
            warnings.append("Condition uses 'role' field which must be present in context")
        if "trustScore" in condition:
            warnings.append("Condition uses 'trustScore' field which must be present in context")
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
        console.print(Panel(
            "[green]Policy is valid![/green]",
            title="Validation Result"
        ))

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
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat warnings as fatal errors (exit code 1)"
    )
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
        if errors or (strict and warnings):
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)

            
    except Exception as e:
        console.print(Panel(
            f"[red]Error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 