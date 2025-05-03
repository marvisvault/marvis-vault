"""
Audit log export command.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
from io import StringIO

app = typer.Typer()
console = Console()

# Required fields in audit log entries
REQUIRED_FIELDS = {"timestamp", "action", "role"}

def validate_timestamp(timestamp: str) -> bool:
    """Validate timestamp format."""
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False

def read_audit_log(log_path: Path) -> List[Dict[str, Any]]:
    """Read and validate audit log entries from a JSONL file."""
    entries = []
    malformed_lines = 0
    
    if not log_path.exists():
        raise typer.BadParameter(f"Audit log file not found: {log_path}")
        
    if not log_path.is_file():
        raise typer.BadParameter(f"Path is not a file: {log_path}")
        
    if not log_path.stat().st_size:
        console.print(Panel(
            "[yellow]No entries found in audit log[/yellow]",
            title="Warning",
            border_style="yellow"
        ))
        return entries
        
    try:
        with open(log_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                try:
                    entry = json.loads(line)
                    
                    # Validate required fields
                    missing_fields = REQUIRED_FIELDS - set(entry.keys())
                    if missing_fields:
                        console.print(f"[yellow]Warning: Missing required fields {missing_fields} in line {line_num}[/yellow]")
                        malformed_lines += 1
                        continue
                        
                    # Validate timestamp format
                    if not validate_timestamp(entry["timestamp"]):
                        console.print(f"[yellow]Warning: Invalid timestamp format in line {line_num}[/yellow]")
                        malformed_lines += 1
                        continue
                        
                    entries.append(entry)
                except json.JSONDecodeError:
                    console.print(f"[yellow]Warning: Invalid JSON in line {line_num}[/yellow]")
                    malformed_lines += 1
                    continue
                    
    except Exception as e:
        raise typer.BadParameter(f"Error reading audit log: {str(e)}")
        
    if malformed_lines:
        console.print(Panel(
            f"[yellow]Warning: Skipped {malformed_lines} malformed lines[/yellow]",
            title="Warning",
            border_style="yellow"
        ))
        
    return entries

def format_table(entries: List[Dict[str, Any]], role_filter: Optional[str] = None) -> Table:
    """Format audit log entries as a rich table."""
    table = Table(title="Audit Log")
    
    # Add columns
    table.add_column("Timestamp", style="cyan")
    table.add_column("Action", style="green")
    table.add_column("Role", style="magenta")
    table.add_column("Input", style="white")
    table.add_column("Output", style="white")
    
    # Add rows
    for entry in entries:
        if role_filter and role_filter.lower() not in entry["role"].lower():
            continue
            
        table.add_row(
            entry["timestamp"],
            entry["action"],
            entry["role"],
            str(entry.get("input", "")),
            str(entry.get("output", ""))
        )
        
    return table

@app.command()
def audit(
    log: Path = typer.Option(
        "logs/audit_log.jsonl",
        "--log",
        "-l",
        help="Path to audit log file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    role: Optional[str] = typer.Option(
        None,
        "--role",
        "-r",
        help="Filter entries by role (case-insensitive partial match)",
    ),
) -> None:
    """
    Display audit log entries in a rich table format.
    
    Reads a JSONL audit log file and displays it in a formatted table.
    Each log entry must contain timestamp, action, and role fields.
    """
    try:
        # Read and validate audit log
        entries = read_audit_log(log)
        
        if not entries:
            console.print(Panel(
                "[yellow]No valid audit log entries found[/yellow]",
                title="Audit Log",
                border_style="yellow"
            ))
            raise typer.Exit(0)
        
        # Format and display table
        table = format_table(entries, role)
        console.print(table)
        
    except typer.BadParameter as e:
        console.print(Panel(
            f"[red]Error: {str(e)}[/red]",
            title="Error",
            border_style="red"
        ))
        raise typer.Exit(1)
    except Exception as e:
        console.print(Panel(
            f"[red]Error: {str(e)}[/red]",
            title="Error",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 