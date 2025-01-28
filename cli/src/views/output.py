from rich.markdown import Markdown

from cli.src.views.console import console


def display_markdown(content: str) -> None:
    console.print(Markdown(content))


def display_error(message: str) -> None:
    console.print(f"[bold red]{message}[/bold red]")


def display_success(message: str) -> None:
    console.print(f"[bold green]{message}[/bold green]")


def display_warning(message: str) -> None:
    console.print(f"[italic yellow]{message}[/italic yellow]")
