"""Review agent for code review of Prowler checks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from git import Repo

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)

from agents.base import Agent
from agents.review.models import ReviewResult
from utils.logging import log_agent_output
from utils.prompts import load_prompt


class ReviewAgent(Agent):
    """Agent that reviews Prowler check implementations."""

    ALLOWED_TOOLS: ClassVar[list[str]] = [
        "Read",
        "Write",
        "Edit",
        "Bash",
        "Glob",
        "Grep",
        "WebFetch",
    ]

    def __init__(
        self,
        working_dir: Path,
        check_name: str,
        check_provider: str,
        prowler_repo: Repo,
        **kwargs: Any,
    ) -> None:
        super().__init__(working_dir, **kwargs)
        self.check_name: str = check_name
        self.check_provider: str = check_provider
        self.prowler_repo: Repo = prowler_repo

    async def run(self, **inputs: Any) -> ReviewResult:
        """
        Review a Prowler check implementation.

        Returns:
            ReviewResult with review information
        """
        logging.info("[bold cyan]Running review agent...[/bold cyan]")

        # Load prompt and create options
        review_prompt: str = self._load_review_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        # Track if changes were made by checking git status before/after
        initial_dirty: bool = self.prowler_repo.is_dirty()
        initial_untracked: set[str] = set(self.prowler_repo.untracked_files)

        async with ClaudeSDKClient(options=options) as client:
            logging.info("[yellow]Reviewing check implementation...[/yellow]")
            await client.query(review_prompt)
            await self._process_agent_messages(client=client)

        # Check if changes were made
        final_dirty: bool = self.prowler_repo.is_dirty()
        final_untracked: set[str] = set(self.prowler_repo.untracked_files)

        changes_made: bool = (
            final_dirty != initial_dirty
            or final_untracked != initial_untracked
            or self._check_modified_files()
        )

        if changes_made:
            logging.warning("Review made changes - re-testing recommended")
        else:
            logging.info("[green]✓ Review complete - no changes needed[/green]")

        return ReviewResult(
            success=True,
            check_name=self.check_name,
            changes_made=changes_made,
            message="Review completed" + (" with changes" if changes_made else ""),
        )

    def _load_review_prompt(self) -> str:
        """Load the review prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "review_check.jinja"
        return load_prompt(
            path=prompt_path,
            context={
                "check_name": self.check_name,
                "check_provider": self.check_provider,
                "prowler_repo": str(self.working_dir),
            },
        )

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """Create Claude agent options with tools."""
        return ClaudeAgentOptions(
            allowed_tools=self.ALLOWED_TOOLS,
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    async def _process_agent_messages(self, client: ClaudeSDKClient) -> None:
        """Process and stream messages from the Claude agent."""
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        # Use builtin print for real-time streaming
                        print(block.text, end="", flush=True)
                        log_agent_output(block.text)
            elif isinstance(message, ResultMessage):
                print()  # Newline after streaming
                break

    def _check_modified_files(self) -> bool:
        """Check if there are any modified files related to the check."""
        try:
            diff = self.prowler_repo.git.diff("--name-only")
            if diff:
                modified_files: list[str] = diff.split("\n")
                # Check if any modified file is related to our check
                for file_path in modified_files:
                    if self.check_name in file_path:
                        return True
            return False
        except Exception:
            return False
