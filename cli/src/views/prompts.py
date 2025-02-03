import os
from pathlib import Path

from rich.prompt import Confirm, Prompt

from cli.src.views.output import display_error


def prompt_user_message() -> str:
    return Prompt.ask("\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤")


def confirm_save_check() -> bool:
    return Confirm.ask(
        "\n[bold]Do you want to save the generated check into a directory?[/bold] [y/n]"
    )


def ask_output_directory() -> Path:
    while True:
        path = Prompt.ask(
            "\n[bold]Enter the path to save the check or do not write anything to use the default path (./generated_checks/)[/bold]"
        )
        if path == "":
            return Path(os.path.join(os.getcwd(), "generated_checks"))
        elif os.path.exists(path) and os.path.isdir(path):
            return Path(path)
        else:
            display_error("\nInvalid output path. Please try again.")


def confirm_overwrite() -> bool:
    return Confirm.ask(
        "\n[bold]The selected path already contains a check. Do you want to overwrite it?[/bold] [y/n]"
    )
