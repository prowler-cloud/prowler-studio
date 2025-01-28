import typer

from cli.src.commands.build_rag import build_check_rag
from cli.src.commands.create_check import create_new_check

app = typer.Typer(help="Prowler Studio CLI")

app.command(name="create-check")(create_new_check)
app.command(name="build-check-rag")(build_check_rag)
