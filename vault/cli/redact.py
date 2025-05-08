"""
Redact command for masking sensitive data.
"""

import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from ..sdk.redact import validate_policy, redact_data

app = typer.Typer()
console = Console()

def load_agent_context(agent_path: Optional[Path]) -> dict:
    """Load agent context from JSON file if provided."""
    if not agent_path:
        return {}
        
    try:
        context = json.loads(agent_path.read_text())
        
        # Validate required fields
        if "role" not in context:
            raise ValueError("Agent context must contain 'role' field")
        if "trustScore" not in context:
            raise ValueError("Agent context must contain 'trustScore' field")
            
        # Validate trustScore is numeric
        try:
            if context["trustScore"] is not None:
                float(context["trustScore"])
        except (TypeError, ValueError):
            raise ValueError(f"trustScore must be numeric, got {type(context['trustScore'])}")
            
        return context
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in agent file: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to load agent file: {str(e)}")

def write_output(data: dict, output_path: Optional[Path], force: bool = False) -> None:
    """Write redacted data to file or stdout."""
    if output_path:
        if output_path.exists() and not force:
            if not Confirm.ask(f"File {output_path} exists. Overwrite?"):
                console.print("[yellow]Operation cancelled[/yellow]")
                raise typer.Exit(1)
        output_path.write_text(json.dumps(data, indent=2))
    else:
        console.print(json.dumps(data, indent=2))

@app.command()
def redact(
    data: Path = typer.Option(
        ...,
        "--data",
        "-d",
        help="Path to data file to redact",
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
    agent: Optional[Path] = typer.Option(
        None,
        "--agent",
        "-a",
        help="Path to agent context JSON file",
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
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force overwrite of output file if it exists.",
    ),
) -> None:
    """
    Redact sensitive data based on policy rules.
    
    This command takes a data file and applies redaction rules from a policy file.
    The policy file can be in JSON or YAML format and must contain valid redaction rules.
    
    If an agent context file is provided, it will be used to evaluate role-based
    redaction rules. The agent context must contain:
    - role: The role of the agent
    - trustScore: A numeric trust score
    
    The output can be written to a file or stdout in JSON format.
    """
    try:
        # Load data
        try:
            data_content = json.loads(data.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in data file: {str(e)}")
            
        # Load agent context if provided
        context = load_agent_context(agent)
        
        # Validate policy
        try:
            validate_policy(str(policy))
        except ValueError as e:
            raise ValueError(f"Invalid policy: {str(e)}")
            
        # Perform redaction
        try:
            redacted_data = redact_data(data_content, str(policy), context)
        except Exception as e:
            raise ValueError(f"Redaction failed: {str(e)}")
            
        # Write output
        write_output(redacted_data, output, force)
        
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