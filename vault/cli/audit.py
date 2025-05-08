"""
Audit command for viewing and exporting audit logs.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

app = typer.Typer()
console = Console()

def parse_date(date_str: str) -> datetime:
    """Parse date string in ISO format."""
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str}. Expected ISO format (YYYY-MM-DD)")

def read_audit_log(log_path: Path) -> list[dict]:
    """Read and parse audit log entries."""
    try:
        entries = []
        for line in log_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                console.print(f"[yellow]Warning: Skipping invalid log entry: {str(e)}[/yellow]")
        return entries
    except Exception as e:
        raise ValueError(f"Failed to read audit log: {str(e)}")

def filter_entries(entries: list[dict], start_date: Optional[datetime], end_date: Optional[datetime]) -> list[dict]:
    """Filter entries by date range."""
    if not start_date and not end_date:
        return entries
        
    filtered = []
    for entry in entries:
        try:
            entry_date = datetime.fromisoformat(entry.get("timestamp", ""))
            if start_date and entry_date < start_date:
                continue
            if end_date and entry_date > end_date:
                continue
            filtered.append(entry)
        except (ValueError, TypeError):
            console.print(f"[yellow]Warning: Skipping entry with invalid timestamp[/yellow]")
            continue
            
    return filtered

def format_entries(entries: list[dict]) -> Table:
    """Format entries as a rich table."""
    table = Table(title="Audit Log Entries")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Action", style="green")
    table.add_column("User", style="yellow")
    table.add_column("Details", style="white")
    
    for entry in entries:
        table.add_row(
            entry.get("timestamp", "N/A"),
            entry.get("action", "N/A"),
            entry.get("user", "N/A"),
            json.dumps(entry.get("details", {}), indent=2)
        )
    
    return table

def export_entries(entries: list[dict], output_path: Path, format: Literal["json", "csv"], force: bool = False) -> None:
    """Export entries to file in specified format."""
    if output_path.exists() and not force:
        if not Confirm.ask(f"File {output_path} exists. Overwrite?"):
            console.print("[yellow]Operation cancelled[/yellow]")
            raise typer.Exit(1)
            
    if format == "json":
        output_path.write_text(json.dumps(entries, indent=2))
    else:  # csv
        with output_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "action", "user", "details"])
            writer.writeheader()
            for entry in entries:
                row = {
                    "timestamp": entry.get("timestamp", ""),
                    "action": entry.get("action", ""),
                    "user": entry.get("user", ""),
                    "details": json.dumps(entry.get("details", {}))
                }
                writer.writerow(row)

@app.command()
def audit(
    log: Path = typer.Option(
        ...,
        "--log",
        "-l",
        help="Path to audit log file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    start_date: Optional[str] = typer.Option(
        None,
        "--start-date",
        "-s",
        help="Start date in ISO format (YYYY-MM-DD)",
    ),
    end_date: Optional[str] = typer.Option(
        None,
        "--end-date",
        "-e",
        help="End date in ISO format (YYYY-MM-DD)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. If not provided, displays in terminal.",
        file_okay=True,
        dir_okay=False,
        writable=True,
    ),
    format: Literal["json", "csv"] = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format (json or csv)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Force overwrite of output file if it exists.",
    ),
) -> None:
    """
    View and export audit log entries.
    
    This command reads audit log entries from a file and can filter them by date range.
    The entries can be displayed in the terminal or exported to a file in JSON or CSV format.
    
    The audit log file should contain one JSON object per line, with each object having:
    - timestamp: ISO format timestamp
    - action: The action performed
    - user: The user who performed the action
    - details: Additional details about the action
    """
    try:
        # Parse dates
        start = parse_date(start_date) if start_date else None
        end = parse_date(end_date) if end_date else None
        
        # Read and filter entries
        entries = read_audit_log(log)
        filtered_entries = filter_entries(entries, start, end)
        
        if not filtered_entries:
            console.print("[yellow]No entries found matching the criteria[/yellow]")
            return
            
        # Display or export
        if output:
            export_entries(filtered_entries, output, format, force)
        else:
            console.print(format_entries(filtered_entries))
            
    except ValueError as e:
        console.print(Panel(
            f"[red]Error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)
    except Exception as e:
        console.print(Panel(
            f"[red]Unexpected error:[/red] {str(e)}",
            title="[red]Error[/red]",
            border_style="red"
        ))
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 