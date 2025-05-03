"""
Marvis Vault CLI - Programmable compliance infrastructure for agentic AI.
"""

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from .redact import redact
from .simulate import simulate
from .audit import audit
from .lint import lint
from .diff import diff
from .dry_run import dry_run

# Initialize Rich console for pretty output
console = Console()

# Create Typer app with proper configuration
app = typer.Typer(
    name="vault",
    help="Programmable compliance infrastructure for agentic AI",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register all commands
app.command(
    name="redact",
    help="Redact sensitive data from text using a policy",
)(redact)

app.command(
    name="simulate",
    help="Simulate policy evaluation on sample data",
)(simulate)

app.command(
    name="audit",
    help="View and export audit logs",
)(audit)

app.command(
    name="lint",
    help="Validate policy files",
)(lint)

app.command(
    name="diff",
    help="Compare two policy files",
)(diff)

app.command(
    name="dry-run",
    help="Test policy changes safely",
)(dry_run)

def version_callback(value: bool):
    """Print version and exit."""
    if value:
        from vault import __version__
        console.print(f"Marvis Vault v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    )
):
    """
    Marvis Vault - Programmable compliance infrastructure for agentic AI.
    
    Redact, simulate, and audit sensitive data with policies, trustScore, and role-based logic.
    """
    pass

def run():
    """Entry point for the CLI."""
    try:
        app()
    except Exception as e:
        console.print(
            Panel(
                f"[red]Error:[/red] {str(e)}",
                title="[bold red]Marvis Vault Error[/bold red]",
                border_style="red",
            )
        )
        sys.exit(1)

if __name__ == "__main__":
    run() 