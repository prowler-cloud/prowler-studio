"""Main CLI for Prowler Studio."""

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from git import GitError, InvalidGitRepositoryError, Repo

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
from utils.logging import WorkflowLogger, console_error, set_workflow_logger

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
        console_error("Must provide either --ticket or --jira-url")
        raise typer.Exit(code=1)
    if ticket_file and jira_url:
        console_error("Cannot provide both --ticket and --jira-url")
        raise typer.Exit(code=1)

    # Validate file path if provided
    if ticket_file:
        ticket_file = ticket_file.resolve()
        if not ticket_file.exists():
            console_error(f"Ticket file not found: {ticket_file}")
            raise typer.Exit(code=1)
        if not ticket_file.is_file():
            console_error(f"Path is not a file: {ticket_file}")
            raise typer.Exit(code=1)

    # Parse Jira URL if provided (validation only, fetch after logger is initialized)
    jira_issue_key: str | None = None
    jira_ticket_content: JiraTicketContent | None = None
    jira_info = None
    if jira_url:
        try:
            jira_info = parse_jira_url(jira_url)
            jira_issue_key = jira_info.issue_key
        except ValueError as e:
            console_error(str(e))
            raise typer.Exit(code=1) from e

    # Setup working directory
    working_dir = working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=True)

    # Initialize workflow logger
    workflow_logger = WorkflowLogger(
        base_dir=working_dir,
        jira_ticket=jira_issue_key,
    )
    set_workflow_logger(workflow_logger)

    workflow_logger.stage("Prowler Studio - Check Creation")
    workflow_logger.info(f"[cyan]Log file: {workflow_logger.log_file}[/cyan]")

    # Fetch Jira ticket content (now that logger is available)
    if jira_info and jira_issue_key:
        try:
            workflow_logger.info(f"[cyan]Jira ticket: {jira_issue_key}[/cyan]")
            workflow_logger.info("[bold]Fetching Jira ticket content...[/bold]")
            jira_client = JiraClient(site_url=jira_info.site_url)
            jira_ticket_content = jira_client.fetch_ticket(jira_issue_key)
            workflow_logger.success(f"Fetched: {jira_ticket_content.summary}")
        except JiraClientError as e:
            workflow_logger.error(f"Failed to fetch Jira ticket: {e}")
            raise typer.Exit(code=1) from e

    # Clone/prepare Prowler repository
    prowler_repo_path = working_dir / "prowler"

    if prowler_repo_path.exists():
        workflow_logger.warning(
            f"Using existing Prowler repository at {prowler_repo_path}"
        )
        try:
            repo = Repo(prowler_repo_path)
        except InvalidGitRepositoryError as e:
            workflow_logger.error("Directory exists but is not a valid git repository")
            raise typer.Exit(code=1) from e
    else:
        workflow_logger.info("[bold]Cloning Prowler repository...[/bold]")
        try:
            repo = Repo.clone_from(url=PROWLER_REPO_URL, to_path=prowler_repo_path)
        except GitError as e:
            workflow_logger.error(f"Git error: {e}")
            raise typer.Exit(code=1) from e

    # Determine branch name (use temp branch if not provided)
    temp_branch_name: str | None = None
    if branch_name is None:
        temp_branch_name = f"feat/new-check-{int(time.time())}"
        effective_branch = temp_branch_name
    else:
        effective_branch = branch_name

    # Prepare branch
    workflow_logger.info("[bold]Preparing repository...[/bold]")
    prepare_repo_for_work(repo, effective_branch)

    # Setup AI skills for Claude (non-blocking on failure)
    skills_result = setup_prowler_skills(prowler_directory=prowler_repo_path)
    if not skills_result.success:
        workflow_logger.warning(f"Skills setup incomplete: {skills_result.message}")
        workflow_logger.print(
            "[yellow]  Continuing without full skills integration...[/yellow]"
        )

    # Install Prowler dependencies
    try:
        install_prowler_dependencies(prowler_repo_path)
    except ProwlerToolError as e:
        workflow_logger.error(f"Failed to install Prowler dependencies: {e}")
        raise typer.Exit(code=1) from e

    try:
        # Get ticket content from file or Jira
        check_ticket_content: str | None = None
        if ticket_file:
            check_ticket_content = ticket_file.read_text()
        elif jira_ticket_content:
            check_ticket_content = jira_ticket_content.to_markdown()

        # Stage 1: Check Implementation
        workflow_logger.stage("Stage 1: Check Implementation")
        implementation_agent: ChecKreatorAgent = ChecKreatorAgent(
            working_dir=prowler_repo_path,
            check_ticket=check_ticket_content,
            prowler_repo=repo,
        )

        impl_result: CheckImplementationResult = asyncio.run(implementation_agent.run())

        if not impl_result.success:
            workflow_logger.error("Check implementation failed verification")
            if impl_result.error:
                workflow_logger.error(f"Error: {impl_result.error}")
            raise typer.Exit(code=1)

        workflow_logger.success("Check implementation completed")
        workflow_logger.print(f"  Check name: {impl_result.check_name}")
        workflow_logger.print(f"  Provider: {impl_result.check_provider}")

        # Rename branch if we used a temporary name
        final_branch_name: str
        if temp_branch_name is not None:
            # User didn't provide --branch, rename temp branch to final name
            ticket_key = jira_issue_key if jira_issue_key else None
            final_branch_name = generate_branch_name(impl_result.check_name, ticket_key)
            rename_branch(repo, temp_branch_name, final_branch_name)
            workflow_logger.success(f"Branch renamed to: {final_branch_name}")
        else:
            # User provided explicit --branch name, use it as-is
            final_branch_name = branch_name  # type: ignore[assignment]

        # Stage 2: Testing
        workflow_logger.stage("Stage 2: Testing")
        testing_agent: TestingAgent = TestingAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
            check_ticket=check_ticket_content,
        )

        test_result: TestingResult = asyncio.run(testing_agent.run())

        if not test_result.success:
            workflow_logger.error("Testing failed")
            workflow_logger.error(f"Error: {test_result.message}")
            raise typer.Exit(code=1)

        workflow_logger.success("Testing completed")
        workflow_logger.print(f"  Test file: {test_result.test_file_path}")
        workflow_logger.print(f"  Attempts: {test_result.attempts}")

        # Stage 3: Compliance Mapping
        workflow_logger.stage("Stage 3: Compliance Mapping")
        compliance_agent: ComplianceMappingAgent = ComplianceMappingAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
            check_ticket=check_ticket_content,
        )

        compliance_result: ComplianceMappingResult = asyncio.run(compliance_agent.run())

        if not compliance_result.success:
            workflow_logger.error("Compliance mapping failed")
            if compliance_result.error:
                workflow_logger.error(f"Error: {compliance_result.error}")
            raise typer.Exit(code=1)

        workflow_logger.success("Compliance mapping completed")
        if compliance_result.changes_made:
            workflow_logger.print(
                f"  Files modified: {compliance_result.mappings_added}"
            )

        # Stage 4: Review
        workflow_logger.stage("Stage 4: Code Review")
        review_agent: ReviewAgent = ReviewAgent(
            working_dir=prowler_repo_path,
            check_name=impl_result.check_name,
            check_provider=impl_result.check_provider,
            prowler_repo=repo,
        )

        review_result: ReviewResult = asyncio.run(review_agent.run())

        if not review_result.success:
            workflow_logger.error("Review failed")
            raise typer.Exit(code=1)

        workflow_logger.success("Review completed")

        # Stage 5: Re-test if review made changes
        if review_result.changes_made:
            workflow_logger.stage("Stage 5: Re-testing (review made changes)")
            retest_result: TestingResult = asyncio.run(testing_agent.run())

            if not retest_result.success:
                workflow_logger.error("Re-testing failed after review changes")
                workflow_logger.error(f"Error: {retest_result.message}")
                raise typer.Exit(code=1)

            workflow_logger.success("Re-testing completed")

        # Stage 6: PR Creation
        workflow_logger.stage("Stage 6: PR Creation")
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
        workflow_logger.stage("Final Results")

        if pr_result.success:
            workflow_logger.success("Workflow completed successfully!")
            workflow_logger.print(f"  Check name: {impl_result.check_name}")
            workflow_logger.print(f"  Provider: {impl_result.check_provider}")
            workflow_logger.print(f"  Branch: {final_branch_name}")
            workflow_logger.print(f"  PR: {pr_result.pr_url}")
            workflow_logger.print(f"  Commit: {pr_result.commit_sha[:8]}")
            workflow_logger.finalize(success=True)
        else:
            workflow_logger.warning("Workflow completed but PR creation failed")
            workflow_logger.print(f"  Check name: {impl_result.check_name}")
            workflow_logger.print(f"  Provider: {impl_result.check_provider}")
            workflow_logger.print(f"  Branch: {final_branch_name}")
            if pr_result.error:
                workflow_logger.print(f"  PR Error: {pr_result.error}")
            workflow_logger.print(
                "\n[yellow]You can create the PR manually with:[/yellow]"
            )
            workflow_logger.print(f"  cd {prowler_repo_path}")
            workflow_logger.print(f"  git push -u origin {final_branch_name}")
            workflow_logger.print("  gh pr create")
            workflow_logger.finalize(success=False)

    except typer.Exit:
        workflow_logger.finalize(success=False)
        raise
    except Exception as e:
        workflow_logger.error(f"Error: {e}")
        workflow_logger.finalize(success=False)
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        console_error(f"Unexpected error: {e}")
        raise typer.Exit(code=1) from e
