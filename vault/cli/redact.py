"""
Redact command for masking sensitive data.
"""

import sys
import json
from pathlib import Path
from typing import Optional, TextIO, Dict, Any
import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table
from rich.panel import Panel
from ..sdk.redact import redact as sdk_redact
from ..sdk.redact import validate_policy, RedactionResult
from datetime import datetime, timezone
app = typer.Typer()
console = Console()

def attach_stream_logger(result: RedactionResult, stream_log: Path):
    """Attach a JSONL stream writer to the result object."""
    stream_log.parent.mkdir(parents=True, exist_ok=True)
    log_file = stream_log.open("a", encoding="utf-8")
    print(f"[debug] Opened stream log: {stream_log.resolve()}")


    def stream_hook(field, reason, value=None, line_number=None, context=None):
        entry = {
            "timestamp": result.timestamp,
            "action": "redact", 
            "role": "user",
            "field": field,
            "reason": reason,
            "input": value,
            "output": f"{field}: [REDACTED]" if field != "system" else result.content,
            "line_number": line_number,
            "context": context
        }
        print(f"[debug] Writing stream entry: {entry}")
        log_file.write(json.dumps(entry) + "\n")
        log_file.flush()  # Ensure immediate write

    original_add = result.add_audit_entry

    def patched_add(*args, **kwargs):
        original_add(*args, **kwargs)
        stream_hook(*args, **kwargs)

    result.add_audit_entry = patched_add
    return log_file

def read_input(input_path: Optional[Path]) -> str:
    """Read input from file or stdin."""
    if input_path:
        return input_path.read_text()
    return sys.stdin.read()

def write_output(result: RedactionResult, output_path: Optional[Path], force: bool = False, pretty: bool = True) -> None:
    """Write output to file or stdout."""
    content = result.content
    if result.is_json and pretty:
        try:
            content = json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError:
            pass

    if output_path:
        if output_path.exists() and not force:
            if not Confirm.ask(f"File {output_path} exists. Overwrite?"):
                console.print("[yellow]Operation cancelled[/yellow]")
                sys.exit(1)
        output_path.write_text(content)
    else:
        sys.stdout.write(content)

def write_audit_log(result: RedactionResult, audit_path: Path, force: bool = False) -> None:
    """Write audit log to file with rich formatting."""
    if audit_path.exists() and not force:
        if not Confirm.ask(f"Audit log {audit_path} exists. Overwrite?"):
            console.print("[yellow]Audit logging cancelled[/yellow]")
            return

    try:
        # Create a summary table
        table = Table(title="Redaction Summary")
        table.add_column("Field", style="cyan")
        table.add_column("Occurrences", style="green")
        table.add_column("First Line", style="yellow")
        table.add_column("Last Line", style="yellow")

        # Group audit entries by field
        field_stats = {}
        # Initialize field_stats with all redacted fields (even if no line info)
        for field in result.redacted_fields:
            field_stats[field] = {
                "count": 0,
                "first_line": None,
                "last_line": None
            }

        # Now count from the audit_log
        for entry in result.audit_log:
            field = entry["field"]
            stats = field_stats[field]
            stats["count"] += 1
            if entry.get("line_number") is not None:
                if stats["first_line"] is None or entry["line_number"] < stats["first_line"]:
                    stats["first_line"] = entry["line_number"]
                if stats["last_line"] is None or entry["line_number"] > stats["last_line"]:
                    stats["last_line"] = entry["line_number"]


        # Add rows to table
        for field, stats in field_stats.items():
            table.add_row(
                field,
                str(stats["count"]),
                str(stats["first_line"]) if stats["first_line"] != float('inf') else "N/A",
                str(stats["last_line"]) if stats["last_line"] != 0 else "N/A"
            )

        # Write detailed audit log
        audit_data = {
            "summary": {
                "total_fields_redacted": len(result.redacted_fields),
                "total_occurrences": len(result.audit_log),
                "timestamp": result.timestamp,
                "format": "JSON" if result.is_json else "Text"
            },
            "field_statistics": field_stats,
            "detailed_log": result.audit_log,
            "line_mapping": result.line_mapping
        }

        # Write to file
        audit_path.write_text(json.dumps(audit_data, indent=2))

        # Print summary to console
        console.print("\n[bold]Redaction Summary:[/bold]")
        console.print(table)
        console.print(f"\nTotal fields redacted: {len(result.redacted_fields)}")
        console.print(f"Total occurrences: {len(result.audit_log)}")
        console.print(f"Format: {'JSON' if result.is_json else 'Text'}")
        console.print(f"Audit log written to: {audit_path}")

    except Exception as e:
        console.print(f"[yellow]Warning: Failed to write audit log: {str(e)}[/yellow]")

@app.command()
def redact(
    input: Optional[Path] = typer.Option(
        None,
        "--input",
        "-i",
        help="Input file path. If not provided, reads from stdin.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    policy: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Policy file path (JSON or YAML)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. If not provided, writes to stdout.",
        file_okay=True,
        dir_okay=False,
        writable=True,
    ),
    agent: Optional[Path] = typer.Option(
        None,
        "--agent",
        "-g",
        help="Agent context file path (JSON). Contains role, trustScore, etc.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    audit: Optional[Path] = typer.Option(
        None,
        "--audit",
        "-a",
        help="Audit log file path. If not provided, no audit log is written.",
        file_okay=True,
        dir_okay=False,
        writable=True,
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force overwrite of output files if they exist.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output in compact JSON format.",
    ),
    stream_log: Optional[Path] = typer.Option(
        None,
        "--stream-log",
        "-l",
        help="Write each audit event to a streaming JSONL log file.",
        file_okay=True,
        dir_okay=False,
        writable=True,
    ),
) -> None:
    """
    Redact sensitive information from input based on policy rules.
    
    The input can be JSON or plain text, read from a file or stdin.
    The output can be written to a file or stdout, with optional audit logging.
    The policy file determines which fields should be redacted and under what conditions.
    """
    try:
        # Read and parse policy
        try:
            policy_content = json.loads(policy.read_text())
        except json.JSONDecodeError:
            console.print("[red]Error: Policy file must be valid JSON[/red]")
            sys.exit(1)
        
        if not validate_policy(policy_content):
            console.print("[red]Error: Invalid policy structure[/red]")
            sys.exit(1)
        
        # Read and validate agent context if provided
        agent_context = None
        if agent:
            try:
                content = agent.read_text()
                if not content.strip():
                    raise ValueError("Agent file is empty")
                    
                agent_context = json.loads(content)
                
                # Validate it's a dictionary
                if not isinstance(agent_context, dict):
                    raise ValueError("Agent file must contain a JSON object (not array or string)")
                    
                # Validate required role field
                if "role" not in agent_context:
                    raise ValueError("Agent context must contain 'role' field")
                    
                # Validate role type and value
                if not isinstance(agent_context["role"], str):
                    raise ValueError(f"Agent 'role' must be a string, got {type(agent_context['role']).__name__}")
                if not agent_context["role"].strip():
                    raise ValueError("Agent 'role' cannot be empty")
                    
                # Validate trustScore if present (optional for redact)
                if "trustScore" in agent_context and agent_context["trustScore"] is not None:
                    # Reject boolean values explicitly
                    if isinstance(agent_context["trustScore"], bool):
                        raise ValueError("trustScore cannot be a boolean value")
                        
                    try:
                        score = float(agent_context["trustScore"])
                    except (TypeError, ValueError):
                        raise ValueError(f"trustScore must be numeric, got {type(agent_context['trustScore']).__name__}")
                    
                    if score < 0 or score > 100:
                        raise ValueError(f"trustScore must be between 0-100, got {score}")
                        
            except json.JSONDecodeError as e:
                console.print(f"[red]Error: Invalid JSON in agent file - {str(e)}[/red]")
                sys.exit(1)
            except ValueError as e:
                console.print(f"[red]Error: Invalid agent - {str(e)}[/red]")
                sys.exit(1)
            except Exception as e:
                console.print(f"[red]Error loading agent file: {str(e)}[/red]")
                sys.exit(1)
        
        # Read input
        input_content = read_input(input)
        log_file = None

        # Prepare RedactionResult and optionally attach streaming logger
        result = RedactionResult(input_content)
        if stream_log:
            log_file = attach_stream_logger(result, stream_log)

        # Apply redaction using pre-constructed result with agent context
        try:
            sdk_redact(input_content, policy_content, context=agent_context, result=result)
        except Exception as e:
            console.print(f"[red]Error during redaction: {str(e)}[/red]")
            sys.exit(1)
        
        # Write output
        write_output(result, output, force, not json_output)
        
        # Write audit log if requested
        if audit:
            write_audit_log(result, audit, force)
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)
    finally:
        if log_file:
            log_file.close()
if __name__ == "__main__":
    app() 