"""
Audit log export command.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any
import typer
from rich.console import Console
from rich.table import Table
from io import StringIO

app = typer.Typer()
console = Console()

# Required fields in audit log entries
REQUIRED_FIELDS = {"timestamp", "action", "field", "result"}

def read_audit_log(log_path: Path) -> List[Dict[str, Any]]:
    """Read and validate audit log entries from a JSONL file."""
    entries = []
    try:
        with open(log_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                    # Validate required fields
                    missing_fields = REQUIRED_FIELDS - set(entry.keys())
                    if missing_fields:
                        console.print(f"[yellow]Warning: Missing fields {missing_fields} in line {line_num}[/yellow]")
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    console.print(f"[yellow]Warning: Invalid JSON in line {line_num}[/yellow]")
                    continue
    except FileNotFoundError:
        raise typer.BadParameter(f"Audit log file not found: {log_path}")
    return entries

def format_csv(entries: List[Dict[str, Any]]) -> str:
    """Format audit log entries as CSV."""
    if not entries:
        return ""
    
    # Get all unique fields across entries
    fields = set()
    for entry in entries:
        fields.update(entry.keys())
    field_names = sorted(fields)
    
    # Write CSV
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=field_names)
    writer.writeheader()
    writer.writerows(entries)
    return output.getvalue()

def format_json(entries: List[Dict[str, Any]]) -> str:
    """Format audit log entries as JSON."""
    return json.dumps(entries, indent=2)

@app.command()
def audit(
    log: Path = typer.Option(
        "vault.log",
        "--log",
        "-l",
        help="Path to audit log file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    format: str = typer.Option(
        "csv",
        "--format",
        "-f",
        help="Output format (csv or json)",
    ),
) -> None:
    """
    Export audit log entries in the specified format.
    
    Reads a JSONL audit log file and converts it to either CSV or JSON format.
    Each log entry must contain timestamp, action, field, and result fields.
    """
    try:
        # Validate format
        if format not in ["csv", "json"]:
            raise typer.BadParameter("Format must be either 'csv' or 'json'")
        
        # Read and validate audit log
        entries = read_audit_log(log)
        
        if not entries:
            console.print("[yellow]No valid audit log entries found[/yellow]")
            raise typer.Exit(1)
        
        # Format output
        if format == "csv":
            output = format_csv(entries)
        else:  # format == "json"
            output = format_json(entries)
        
        # Write to stdout
        console.print(output)
        
    except typer.BadParameter as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 