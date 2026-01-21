"""Main CLI for Prowler Studio."""

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from git import GitError, InvalidGitRepositoryError, Repo
from rich import print

from agents.compliance_mapping.agent import ComplianceMappingAgent
from agents.implementation.agent import ChecKreatorAgent
from agents.pr_creation.agent import PRCreationAgent
from agents.review.agent import ReviewAgent
from agents.testing.agent import TestingAgent
from tools.git import generate_branch_name, prepare_repo_for_work, rename_branch
from tools.jira import parse_jira_url
from tools.jira_client import JiraClient, JiraClientError, JiraTicketContent
from tools.prowler import ProwlerToolError, install_prowler_dependencies
from tools.skills import setup_prowler_skills
from utils.logging import WorkflowLogger, log_stage, set_workflow_logger

if TYPE_CHECKING:
    from agents.compliance_mapping.models import ComplianceMappingResult
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

    # Validate and fetch Jira ticket if URL provided
    jira_issue_key: str | None = None
    jira_ticket_content: JiraTicketContent | None = None
    if jira_url:
        try:
            jira_info = parse_jira_url(jira_url)
            jira_issue_key = jira_info.issue_key
            print(f"[cyan]Jira ticket: {jira_issue_key}[/cyan]")

            # Fetch ticket content via REST API
            print("[bold]Fetching Jira ticket content...[/bold]")
            jira_client = JiraClient(site_url=jira_info.site_url)
            jira_ticket_content = jira_client.fetch_ticket(jira_issue_key)
            print(f"[green]✓ Fetched: {jira_ticket_content.summary}[/green]")
        except ValueError as e:
            print(f"[red]✗ {e}[/red]")
            raise typer.Exit(code=1) from e
        except JiraClientError as e:
            print(f"[red]✗ Failed to fetch Jira ticket: {e}[/red]")
            raise typer.Exit(code=1) from e

    print("[bold cyan]=== Prowler Studio - Check Creation ===[/bold cyan]")

    # Setup working directory
    working_dir = working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=True)

    # Initialize workflow logger
    workflow_logger = WorkflowLogger(
        base_dir=working_dir,
        jira_ticket=jira_issue_key,
    )
    set_workflow_logger(workflow_logger)
    print(f"[cyan]Log file: {workflow_logger.log_file}[/cyan]")

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
        # Get ticket content from file or Jira
        check_ticket_content: str | None = None
        if ticket_file:
            check_ticket_content = ticket_file.read_text()
        elif jira_ticket_content:
            check_ticket_content = jira_ticket_content.to_markdown()

        # Stage 1: Check Implementation
        log_stage("Check Implementation")
        print("\n[bold cyan]=== Stage 1: Check Implementation ===[/bold cyan]")
        implementation_agent: ChecKreatorAgent = ChecKreatorAgent(
            working_dir=prowler_repo_path,
            check_ticket=check_ticket_content,
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
        log_stage("Testing")
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

        # Stage 3: Compliance Mapping
        log_stage("Compliance Mapping")
        print("\n[bold cyan]=== Stage 3: Compliance Mapping ===[/bold cyan]")
        compliance_agent: ComplianceMappingAgent = ComplianceMappingAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
            check_ticket=check_ticket_content,
        )

        compliance_result: ComplianceMappingResult = asyncio.run(compliance_agent.run())

        if not compliance_result.success:
            print("[red]✗ Compliance mapping failed[/red]")
            if compliance_result.error:
                print(f"[red]Error: {compliance_result.error}[/red]")
            raise typer.Exit(code=1)

        print("[green]✓ Compliance mapping completed[/green]")
        if compliance_result.changes_made:
            print(f"  Files modified: {compliance_result.mappings_added}")

        # Stage 4: Review
        log_stage("Code Review")
        print("\n[bold cyan]=== Stage 4: Code Review ===[/bold cyan]")
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

        # Stage 5: Re-test if review made changes
        if review_result.changes_made:
            log_stage("Re-testing (review made changes)")
            print(
                "\n[bold cyan]=== Stage 5: Re-testing (review made changes) ===[/bold cyan]"
            )
            retest_result: TestingResult = asyncio.run(testing_agent.run())

            if not retest_result.success:
                print("[red]✗ Re-testing failed after review changes[/red]")
                print(f"[red]Error: {retest_result.message}[/red]")
                raise typer.Exit(code=1)

            print("[green]✓ Re-testing completed[/green]")

        # Stage 6: PR Creation
        log_stage("PR Creation")
        print("\n[bold cyan]=== Stage 6: PR Creation ===[/bold cyan]")
        pr_agent: PRCreationAgent = PRCreationAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            branch_name=final_branch_name,
            prowler_repo=repo,
            jira_url=jira_url,
            check_ticket=check_ticket_content,
        )

        pr_result: PRCreationResult = asyncio.run(pr_agent.run())

        # Display final results
        log_stage("Final Results")
        print("\n[bold cyan]=== Final Results ===[/bold cyan]")

        if pr_result.success:
            print("[green]✓ Workflow completed successfully![/green]")
            print(f"  Check name: {impl_result.check_name}")
            print(f"  Provider: {impl_result.check_provider}")
            print(f"  Branch: {final_branch_name}")
            print(f"  PR: {pr_result.pr_url}")
            print(f"  Commit: {pr_result.commit_sha[:8]}")
            workflow_logger.finalize(success=True)
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
            workflow_logger.finalize(success=False)

    except typer.Exit:
        workflow_logger.finalize(success=False)
        raise
    except Exception as e:
        print(f"\n[red]✗ Error: {e}[/red]")
        workflow_logger.finalize(success=False)
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        print(f"[red]✗ Unexpected error: {e}[/red]")
        raise typer.Exit(code=1) from e
