"""Main CLI for Prowler Studio."""

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from git import GitError, InvalidGitRepositoryError, Repo
from rich import print

from agents.implementation.agent import ChecKreatorAgent
from tools.git import prepare_repo_for_work
from tools.jira import parse_jira_url
from tools.prowler import ProwlerToolError, install_prowler_dependencies
from tools.skills import setup_prowler_skills

if TYPE_CHECKING:
    from agents.implementation.models import CheckImplementationResult

app = typer.Typer()

PROWLER_REPO_URL = "git@github.com:prowler-cloud/prowler.git"


@app.command()
def create_check(
    branch_name: Annotated[
        str,
        typer.Argument(
            help="Name of the branch to create for the check",
        ),
    ],
    ticket_file: Annotated[
        Path | None,
        typer.Option(
            "--ticket",
            "-t",
            help="Path to the markdown check ticket file",
        ),
    ] = None,
    jira_url: Annotated[
        str | None,
        typer.Option(
            "--jira-url",
            "-j",
            help="Jira ticket URL (e.g., https://mycompany.atlassian.net/browse/PROJ-123)",
        ),
    ] = None,
    working_dir: Annotated[
        Path,
        typer.Option(
            "--working-dir",
            "-w",
            help="Path to the working directory (default: ./working)",
        ),
    ] = Path("./working"),
) -> None:
    """
    Create a Prowler check from a markdown ticket or Jira URL.

    This will:
    1. Clone/prepare the Prowler repository
    2. Run the implementation agent to create the check
    3. Verify the check is loaded correctly

    You must provide either --ticket or --jira-url, not both.
    """
    # Validate input: must provide exactly one source
    if not ticket_file and not jira_url:
        print("[red]✗ Must provide either --ticket or --jira-url[/red]")
        raise typer.Exit(code=1)
    if ticket_file and jira_url:
        print("[red]✗ Cannot provide both --ticket and --jira-url[/red]")
        raise typer.Exit(code=1)

    # Validate file path if provided
    if ticket_file:
        ticket_file = ticket_file.resolve()
        if not ticket_file.exists():
            print(f"[red]✗ Ticket file not found: {ticket_file}[/red]")
            raise typer.Exit(code=1)
        if not ticket_file.is_file():
            print(f"[red]✗ Path is not a file: {ticket_file}[/red]")
            raise typer.Exit(code=1)

    # Validate Jira URL if provided
    jira_issue_key: str | None = None
    if jira_url:
        try:
            jira_info = parse_jira_url(jira_url)
            jira_issue_key = jira_info.issue_key
            print(f"[cyan]Jira ticket: {jira_issue_key}[/cyan]")
        except ValueError as e:
            print(f"[red]✗ {e}[/red]")
            raise typer.Exit(code=1) from e

    print("[bold cyan]=== Prowler Studio - Check Creation ===[/bold cyan]")

    # Setup working directory
    working_dir = working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=True)

    # Clone/prepare Prowler repository
    prowler_repo_path = working_dir / "prowler"

    if prowler_repo_path.exists():
        print(
            f"[yellow]⚠ Using existing Prowler repository at {prowler_repo_path}[/yellow]"
        )
        try:
            repo = Repo(prowler_repo_path)
        except InvalidGitRepositoryError as e:
            print("[red]✗ Directory exists but is not a valid git repository[/red]")
            raise typer.Exit(code=1) from e
    else:
        print("[bold]Cloning Prowler repository...[/bold]")
        try:
            repo = Repo.clone_from(url=PROWLER_REPO_URL, to_path=prowler_repo_path)
        except GitError as e:
            print(f"[red]✗ Git error: {e}[/red]")
            raise typer.Exit(code=1) from e

    # Prepare branch
    print("[bold]Preparing repository...[/bold]")
    prepare_repo_for_work(repo, branch_name)

    # Setup AI skills for Claude (non-blocking on failure)
    skills_result = setup_prowler_skills(prowler_directory=prowler_repo_path)
    if not skills_result.success:
        print(f"[yellow]⚠ Skills setup incomplete: {skills_result.message}[/yellow]")
        print("[yellow]  Continuing without full skills integration...[/yellow]")

    # Install Prowler dependencies
    try:
        install_prowler_dependencies(prowler_repo_path)
    except ProwlerToolError as e:
        print(f"[red]✗ Failed to install Prowler dependencies: {e}[/red]")
        raise typer.Exit(code=1) from e

    try:
        # Get ticket content from file or None if using Jira
        check_ticket_content: str | None = None
        if ticket_file:
            check_ticket_content = ticket_file.read_text()

        agent: ChecKreatorAgent = ChecKreatorAgent(
            working_dir=prowler_repo_path,
            check_ticket=check_ticket_content,
            jira_url=jira_url,
            prowler_repo=repo,
        )

        result: CheckImplementationResult = asyncio.run(agent.run())

        # Display results
        print("\n[bold cyan]=== Results ===[/bold cyan]")

        if result.success:
            print("[green]✓ Check implementation completed successfully![/green]")
            print(f"Check name: {result.check_name}")
            print(f"Verification attempts: {result.attempts}")
            print(f"Working directory: {working_dir}")
            print(f"Prowler repository: {prowler_repo_path}")
            print(f"Branch: {branch_name}")

            # Future agents would be called here in sequence:
            # agent2 = TestingAgent(working_dir=working_dir)
            # result2 = asyncio.run(agent2.run(check_name=check_name, ...))
            #
            # agent3 = PRCreationAgent(working_dir=working_dir)
            # result3 = asyncio.run(agent3.run(branch=branch_name, ...))

        else:
            print("[red]✗ Check implementation failed verification[/red]")
            if result.error:
                print(f"[red]Error: {result.error}[/red]")
            raise typer.Exit(code=1)

    except Exception as e:
        print(f"\n[red]✗ Error: {e}[/red]")
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        print(f"[red]✗ Unexpected error: {e}[/red]")
        raise typer.Exit(code=1) from e
