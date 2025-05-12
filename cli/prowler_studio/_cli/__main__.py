import sys

import typer

from .commands.build_rag import build_check_rag
from .commands.create_check import create_new_check
from .commands.create_fixer import create_new_fixer
from .commands.update_compliance import update_compliance

app = typer.Typer(help="Prowler Studio CLI")

app.command(name="create-check")(create_new_check)
app.command(name="build-check-rag")(build_check_rag)
app.command(name="update-compliance")(update_compliance)
app.command(name="create-fixer")(create_new_fixer)

if __name__ == "__main__":
    sys.exit(app())
