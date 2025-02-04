from rich.prompt import Confirm, Prompt


def prompt_user_message() -> str:
    return Prompt.ask("\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤")


def confirm_save_check(path: str) -> bool:
    return Confirm.ask(
        f"\n[bold]Do you want to save the generated check in {path}?[/bold] [y/n]"
    )


def confirm_overwrite() -> bool:
    return Confirm.ask(
        "\n[bold]The selected path already contains a check. Do you want to overwrite it?[/bold] [y/n]"
    )


def ask_execute_new_check() -> bool:
    return Confirm.ask(
        "\n[bold]Do you want to execute a new check?[/bold] (Prowler command must be in the PATH) [y/n]"
    )
