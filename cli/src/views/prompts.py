import os

from rich.prompt import Confirm, Prompt

from cli.src.views.output import display_error


def prompt_user_message() -> str:
    return Prompt.ask("\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤")


def confirm_save_check() -> bool:
    return Confirm.ask(
        "\n[bold]Do you want to save this check in your local Prowler repository?[/bold] [y/n]"
    )


def ask_prowler_path() -> str:
    while True:
        path = Prompt.ask(
            "\n[bold]Enter the path to your local Prowler repository (or type 'skip' to cancel)[/bold]\n╰┈➤"
        )
        if path.lower() == "skip":
            return ""
        elif os.path.isdir(path):
            return path
        else:
            display_error("\n[bold red]Invalid path. Please try again.[/bold red]")


def confirm_overwrite(check_path: str) -> bool:
    return Confirm.ask(
        f"\n[bold]The check already exists in: {check_path}. Overwrite?[/bold] [y/n]"
    )
