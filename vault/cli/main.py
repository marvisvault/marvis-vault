import typer
from .redact import redact
from .simulate import simulate
from .audit import audit
from .lint import lint
from .diff import diff
from .dry_run import dry_run

app = typer.Typer(
    name="vault",
    help="Programmable compliance infrastructure for agentic AI",
    add_completion=False,
)

app.command(name="redact")(redact)
app.command(name="simulate")(simulate)
app.command(name="audit")(audit)
app.command(name="lint")(lint)
app.command(name="diff")(diff)
app.command(name="dry-run")(dry_run)

if __name__ == "__main__":
    app() 