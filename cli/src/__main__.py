import typer

from cli.src.commands.build_rag import build_check_rag
from cli.src.commands.create_check import create_new_check
from cli.src.commands.update_compliance import update_compliance

app = typer.Typer(help="Prowler Studio CLI")

app.command(name="create-check")(create_new_check)
app.command(name="build-check-rag")(build_check_rag)
app.command(name="update-compliance")(update_compliance)