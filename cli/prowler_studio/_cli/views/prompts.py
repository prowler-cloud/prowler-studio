from rich.prompt import Confirm, Prompt


def prompt_user_message(
    message: str = "\n[bold]Message Prowler Studio :robot:[/bold]\n╰┈➤",
) -> str:
    return Prompt.ask(message)


def prompt_enter_compliance_path() -> str:
    return Prompt.ask("\n[bold]Enter the path to the compliance JSON file[/bold]\n╰┈➤")


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
