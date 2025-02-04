from rich.prompt import Confirm, Prompt


def prompt_user_message() -> str:
    return Prompt.ask("\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤")


def confirm_save_check() -> bool:
    return Confirm.ask(
        "\n[bold]Do you want to save the generated check into a directory?[/bold] [y/n]"
    )


def confirm_overwrite() -> bool:
    return Confirm.ask(
        "\n[bold]The selected path already contains a check. Do you want to overwrite it?[/bold] [y/n]"
    )
