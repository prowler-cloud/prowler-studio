"""PR creation agent for committing and creating pull requests."""

from __future__ import annotations

import contextlib
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from git import Repo

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

from agents.base import Agent
from agents.pr_creation.models import PRCreationResult
from utils.prompts import load_prompt


class PRCreationAgent(Agent):
    """Agent that commits changes and creates pull requests."""

    ALLOWED_TOOLS: ClassVar[list[str]] = [
        "Read",
        "Bash",
        "Glob",
        "Grep",
    ]
    GITHUB_PR_URL_PATTERN: ClassVar[str] = r"https://github\.com/[^/]+/[^/]+/pull/(\d+)"

    def __init__(
        self,
        working_dir: Path,
        check_name: str,
        check_provider: str,
        branch_name: str,
        prowler_repo: Repo,
        jira_url: str | None = None,
        check_ticket: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(working_dir, **kwargs)
        self.check_name: str = check_name
        self.check_provider: str = check_provider
        self.branch_name: str = branch_name
        self.prowler_repo: Repo = prowler_repo
        self.jira_url: str | None = jira_url
        self.check_ticket: str | None = check_ticket
        self._pr_url: str = ""
        self._pr_number: int = 0
        self._commit_sha: str = ""

    async def run(self, **inputs: Any) -> PRCreationResult:
        """
        Commit changes and create a pull request.

        Returns:
            PRCreationResult with PR information
        """
        logging.info("[bold cyan]Running PR creation agent...[/bold cyan]")

        # Load prompt and create options
        pr_prompt: str = self._load_pr_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        async with ClaudeSDKClient(options=options) as client:
            logging.info("[yellow]Creating commit and pull request...[/yellow]")
            await client.query(pr_prompt)
            response_text: str = await self._process_agent_messages(
                client, capture_text=True
            )

        # Extract PR information from response
        self._extract_pr_info(response_text)

        # Get commit SHA from repo (may fail if no commits yet)
        with contextlib.suppress(Exception):
            self._commit_sha = self.prowler_repo.head.commit.hexsha

        if self._pr_url:
            logging.info(f"[green]✓ PR created: {self._pr_url}[/green]")
            return PRCreationResult(
                success=True,
                check_name=self.check_name,
                commit_sha=self._commit_sha,
                pr_url=self._pr_url,
                pr_number=self._pr_number,
                message=f"PR #{self._pr_number} created successfully",
            )
        else:
            logging.error("Failed to create PR")
            return PRCreationResult(
                success=False,
                check_name=self.check_name,
                commit_sha=self._commit_sha,
                message="PR creation failed - check output for details",
                error="Could not extract PR URL from response",
            )

    def _load_pr_prompt(self) -> str:
        """Load the PR creation prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "pr_description.jinja"
        # Extract service from check name (first part before underscore)
        service: str = self.check_name.split("_")[0]
        return load_prompt(
            path=prompt_path,
            context={
                "check_name": self.check_name,
                "check_provider": self.check_provider,
                "branch_name": self.branch_name,
                "jira_url": self.jira_url,
                "check_ticket": self.check_ticket,
                "service": service,
            },
        )

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """Create Claude agent options with tools."""
        return ClaudeAgentOptions(
            allowed_tools=self.ALLOWED_TOOLS,
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    def _extract_pr_info(self, response_text: str) -> None:
        """Extract PR URL and number from response text."""
        match = re.search(self.GITHUB_PR_URL_PATTERN, response_text)
        if match:
            self._pr_url = match.group(0)
            self._pr_number = int(match.group(1))
