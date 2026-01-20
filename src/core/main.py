"""Main CLI for Prowler Studio."""

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from git import GitError, InvalidGitRepositoryError, Repo
from rich import print

from agents.implementation.agent import ChecKreatorAgent
from agents.pr_creation.agent import PRCreationAgent
from agents.review.agent import ReviewAgent
from agents.testing.agent import TestingAgent
from tools.git import generate_branch_name, prepare_repo_for_work, rename_branch
from tools.jira import parse_jira_url
from tools.prowler import ProwlerToolError, install_prowler_dependencies
from tools.skills import setup_prowler_skills

if TYPE_CHECKING:
    from agents.implementation.models import CheckImplementationResult
    from agents.pr_creation.models import PRCreationResult
    from agents.review.models import ReviewResult
    from agents.testing.models import TestingResult

app = typer.Typer()

PROWLER_REPO_URL = "git@github.com:prowler-cloud/prowler.git"


@app.command()
def create_check(
    branch_name: Annotated[
        str | None,
        typer.Option(
            "--branch",
            "-b",
            help="Branch name (default: feat/<ticket>-<check_name> or feat/<check_name>)",
        ),
    ] = None,
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

    # Determine branch name (use temp branch if not provided)
    temp_branch_name: str | None = None
    if branch_name is None:
        temp_branch_name = f"feat/new-check-{int(time.time())}"
        effective_branch = temp_branch_name
    else:
        effective_branch = branch_name

    # Prepare branch
    print("[bold]Preparing repository...[/bold]")
    prepare_repo_for_work(repo, effective_branch)

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

        # Stage 1: Check Implementation
        print("\n[bold cyan]=== Stage 1: Check Implementation ===[/bold cyan]")
        implementation_agent: ChecKreatorAgent = ChecKreatorAgent(
            working_dir=prowler_repo_path,
            check_ticket=check_ticket_content,
            jira_url=jira_url,
            prowler_repo=repo,
        )

        impl_result: CheckImplementationResult = asyncio.run(implementation_agent.run())

        if not impl_result.success:
            print("[red]✗ Check implementation failed verification[/red]")
            if impl_result.error:
                print(f"[red]Error: {impl_result.error}[/red]")
            raise typer.Exit(code=1)

        print("[green]✓ Check implementation completed[/green]")
        print(f"  Check name: {impl_result.check_name}")
        print(f"  Provider: {impl_result.check_provider}")

        # Rename branch if we used a temporary name
        final_branch_name: str
        if temp_branch_name is not None:
            ticket_key = jira_issue_key if jira_issue_key else None
            final_branch_name = generate_branch_name(impl_result.check_name, ticket_key)
            rename_branch(repo, temp_branch_name, final_branch_name)
            print(f"[green]✓ Branch renamed to: {final_branch_name}[/green]")
        else:
            # branch_name is guaranteed to be str when temp_branch_name is None
            assert branch_name is not None
            final_branch_name = branch_name

        # Stage 2: Testing
        print("\n[bold cyan]=== Stage 2: Testing ===[/bold cyan]")
        testing_agent: TestingAgent = TestingAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
            check_ticket=check_ticket_content,
        )

        test_result: TestingResult = asyncio.run(testing_agent.run())

        if not test_result.success:
            print("[red]✗ Testing failed[/red]")
            print(f"[red]Error: {test_result.message}[/red]")
            raise typer.Exit(code=1)

        print("[green]✓ Testing completed[/green]")
        print(f"  Test file: {test_result.test_file_path}")
        print(f"  Attempts: {test_result.attempts}")

        # Stage 3: Review
        print("\n[bold cyan]=== Stage 3: Code Review ===[/bold cyan]")
        review_agent: ReviewAgent = ReviewAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
        )

        review_result: ReviewResult = asyncio.run(review_agent.run())

        if not review_result.success:
            print("[red]✗ Review failed[/red]")
            raise typer.Exit(code=1)

        print("[green]✓ Review completed[/green]")

        # Stage 4: Re-test if review made changes
        if review_result.changes_made:
            print(
                "\n[bold cyan]=== Stage 4: Re-testing (review made changes) ===[/bold cyan]"
            )
            retest_result: TestingResult = asyncio.run(testing_agent.run())

            if not retest_result.success:
                print("[red]✗ Re-testing failed after review changes[/red]")
                print(f"[red]Error: {retest_result.message}[/red]")
                raise typer.Exit(code=1)

            print("[green]✓ Re-testing completed[/green]")

        # Stage 5: PR Creation
        print("\n[bold cyan]=== Stage 5: PR Creation ===[/bold cyan]")
        pr_agent: PRCreationAgent = PRCreationAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            branch_name=final_branch_name,
            prowler_repo=repo,
            jira_url=jira_url,
        )

        pr_result: PRCreationResult = asyncio.run(pr_agent.run())

        # Display final results
        print("\n[bold cyan]=== Final Results ===[/bold cyan]")

        if pr_result.success:
            print("[green]✓ Workflow completed successfully![/green]")
            print(f"  Check name: {impl_result.check_name}")
            print(f"  Provider: {impl_result.check_provider}")
            print(f"  Branch: {final_branch_name}")
            print(f"  PR: {pr_result.pr_url}")
            print(f"  Commit: {pr_result.commit_sha[:8]}")
        else:
            print("[yellow]⚠ Workflow completed but PR creation failed[/yellow]")
            print(f"  Check name: {impl_result.check_name}")
            print(f"  Provider: {impl_result.check_provider}")
            print(f"  Branch: {final_branch_name}")
            if pr_result.error:
                print(f"  PR Error: {pr_result.error}")
            print("\n[yellow]You can create the PR manually with:[/yellow]")
            print(f"  cd {prowler_repo_path}")
            print(f"  git push -u origin {final_branch_name}")
            print("  gh pr create")

    except typer.Exit:
        raise
    except Exception as e:
        print(f"\n[red]✗ Error: {e}[/red]")
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        print(f"[red]✗ Unexpected error: {e}[/red]")
        raise typer.Exit(code=1) from e
