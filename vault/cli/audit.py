"""
Audit log viewer command.
"""

import json
import csv
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union, TextIO
from datetime import datetime
from collections import defaultdict
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

app = typer.Typer()
console = Console()

# Required fields in audit log entries
REQUIRED_FIELDS = {"timestamp", "action", "role", "field"}

def validate_timestamp(timestamp: str) -> bool:
    """Validate timestamp format."""
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False

def read_audit_log(log_path: Path) -> List[Dict[str, Any]]:
    """Read and validate audit log entries from a JSONL or JSON file."""
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
            # Handle both JSONL and JSON formats
            if log_path.suffix == ".json":
                try:
                    data = json.load(f)
                    if isinstance(data, dict) and "detailed_log" in data:
                        lines = data["detailed_log"]
                    else:
                        lines = [data]
                except json.JSONDecodeError:
                    raise typer.BadParameter("Invalid JSON file format")
            else:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                if isinstance(line, str):
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        console.print(f"[yellow]Warning: Invalid JSON in line {line_num}[/yellow]")
                        malformed_lines += 1
                        continue
                else:
                    entry = line

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
                    
    except Exception as e:
        raise typer.BadParameter(f"Error reading audit log: {str(e)}")
        
    if malformed_lines:
        console.print(Panel(
            f"[yellow]Warning: Skipped {malformed_lines} malformed lines[/yellow]",
            title="Warning",
            border_style="yellow"
        ))
        
    return entries

def get_summary_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate summary statistics from audit log entries."""
    if not entries:
        return {
            "total_entries": 0,
            "unique_roles": set(),
            "unique_actions": set(),
            "unique_fields": set(),
            "timestamp_range": (None, None)
        }

    timestamps = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in entries]
    
    return {
        "total_entries": len(entries),
        "unique_roles": {e["role"] for e in entries},
        "unique_actions": {e["action"] for e in entries},
        "unique_fields": {e["field"] for e in entries},
        "timestamp_range": (min(timestamps), max(timestamps))
    }

def format_summary_panel(stats: Dict[str, Any]) -> Panel:
    """Format summary statistics as a rich panel."""
    if stats["total_entries"] == 0:
        return Panel(
            "[yellow]No valid audit log entries found[/yellow]",
            title="Audit Log Summary",
            border_style="yellow"
        )

    start_time = stats["timestamp_range"][0].strftime("%Y-%m-%d %H:%M:%S")
    end_time = stats["timestamp_range"][1].strftime("%Y-%m-%d %H:%M:%S")
    
    content = [
        f"Total Entries: {stats['total_entries']}",
        f"Unique Roles: {len(stats['unique_roles'])}",
        f"Unique Actions: {len(stats['unique_actions'])}",
        f"Unique Fields: {len(stats['unique_fields'])}",
        f"Time Range: {start_time} to {end_time}"
    ]
    
    return Panel(
        "\n".join(content),
        title="Audit Log Summary",
        border_style="green"
    )

def format_role_table(entries: List[Dict[str, Any]]) -> Table:
    """Format role statistics as a rich table."""
    table = Table(title="Role Summary")
    
    # Add columns
    table.add_column("Role", style="cyan")
    table.add_column("Entry Count", style="green")
    table.add_column("Fields Seen", style="magenta")
    table.add_column("Last Timestamp", style="yellow")
    
    # Calculate role statistics
    role_stats = defaultdict(lambda: {"count": 0, "fields": set(), "last_time": None})
    
    for entry in entries:
        role = entry["role"]
        role_stats[role]["count"] += 1
        role_stats[role]["fields"].add(entry["field"])
        timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        if not role_stats[role]["last_time"] or timestamp > role_stats[role]["last_time"]:
            role_stats[role]["last_time"] = timestamp
    
    # Add rows
    for role, stats in sorted(role_stats.items()):
        table.add_row(
            role,
            str(stats["count"]),
            ", ".join(sorted(stats["fields"])),
            stats["last_time"].strftime("%Y-%m-%d %H:%M:%S")
        )
    
    return table

def format_field_table(entries: List[Dict[str, Any]]) -> Table:
    """Format field statistics as a rich table."""
    table = Table(title="Field Summary")
    
    # Add columns
    table.add_column("Field", style="cyan")
    table.add_column("Entry Count", style="green")
    table.add_column("Roles Seen", style="magenta")
    
    # Calculate field statistics
    field_stats = defaultdict(lambda: {"count": 0, "roles": set()})
    
    for entry in entries:
        field = entry["field"]
        field_stats[field]["count"] += 1
        field_stats[field]["roles"].add(entry["role"])
    
    # Add rows
    for field, stats in sorted(field_stats.items()):
        table.add_row(
            field,
            str(stats["count"]),
            ", ".join(sorted(stats["roles"]))
        )
    
    return table

def format_full_table(entries: List[Dict[str, Any]]) -> Table:
    """Format all entries as a rich table."""
    table = Table(title="Full Audit Log")
    
    # Add columns
    table.add_column("Timestamp", style="cyan")
    table.add_column("Role", style="green")
    table.add_column("Action", style="magenta")
    table.add_column("Field", style="yellow")
    table.add_column("Input", style="white")
    table.add_column("Output", style="white")
    
    # Add rows
    for entry in entries:
        table.add_row(
            entry["timestamp"],
            entry["role"],
            entry["action"],
            entry["field"],
            str(entry.get("input", "")),
            str(entry.get("output", ""))
        )
    
    return table

def export_csv(entries: List[Dict[str, Any]], output: Union[str, Path, TextIO]) -> None:
    """Export entries to CSV format."""
    fieldnames = ["timestamp", "action", "role", "field", "input", "output"]
    
    if isinstance(output, (str, Path)):
        if str(output) == "-":
            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({k: entry.get(k, "") for k in fieldnames})
        else:
            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in entries:
                    writer.writerow({k: entry.get(k, "") for k in fieldnames})
    else:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow({k: entry.get(k, "") for k in fieldnames})

def export_json(entries: List[Dict[str, Any]], output: Union[str, Path, TextIO]) -> None:
    """Export entries to JSON format."""
    if isinstance(output, (str, Path)):
        if str(output) == "-":
            json.dump(entries, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            with open(output, "w") as f:
                json.dump(entries, f, indent=2)
    else:
        json.dump(entries, output, indent=2)

@app.command()
def audit(
    log: Path = typer.Option(
        "logs/audit_log.jsonl",
        "--log",
        "-l",
        help="Path to audit log file (JSONL or JSON)",
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
    all: bool = typer.Option(
        False,
        "--all",
        help="Show full audit log table",
    ),
    export: Optional[Path] = typer.Option(
        None,
        "--export",
        help="Export to CSV file (use - for stdout)",
    ),
    json_out: Optional[Path] = typer.Option(
        None,
        "--json-out",
        help="Export to JSON file (use - for stdout)",
    ),
) -> None:
    """
    Display audit log entries in a rich format.
    
    Reads a JSONL or JSON audit log file and displays summary statistics,
    role and field breakdowns, and optionally the full log.
    
    Can export to CSV or JSON format.
    """
    try:
        # Read and validate audit log
        entries = read_audit_log(log)
        
        # Filter by role if specified
        if role:
            entries = [e for e in entries if role.lower() in e["role"].lower()]
        
        # Export if requested
        if export:
            export_csv(entries, export)
            return
            
        if json_out:
            export_json(entries, json_out)
            return
        
        # Calculate and display summary
        stats = get_summary_stats(entries)
        console.print(format_summary_panel(stats))
        
        if entries:
            # Display role summary
            console.print("\n")
            console.print(format_role_table(entries))
            
            # Display field summary
            console.print("\n")
            console.print(format_field_table(entries))
            
            # Display full log if requested
            if all:
                console.print("\n")
                console.print(format_full_table(entries))
        
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