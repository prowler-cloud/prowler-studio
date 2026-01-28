"""Compliance mapping agent for suggesting and adding compliance framework mappings."""

from __future__ import annotations

import logging
import re
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
from agents.compliance_mapping.models import ComplianceMappingResult
from utils.logging import log_agent_output
from utils.prompts import load_prompt


class ComplianceMappingAgent(Agent):
    """Agent that analyzes checks and adds compliance framework mappings."""

    ALLOWED_TOOLS: ClassVar[list[str]] = [
        "Read",
        "Edit",
        "Glob",
        "Grep",
        "Bash",
    ]
    COMPLIANCE_FILE_PATTERN: ClassVar[str] = r"^prowler/compliance/{provider}/.*\.json$"

    def __init__(
        self,
        working_dir: Path,
        check_name: str,
        check_provider: str,
        prowler_repo: Repo,
        check_ticket: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(working_dir, **kwargs)
        self.check_name: str = check_name
        self.check_provider: str = check_provider
        self.prowler_repo: Repo = prowler_repo
        self.check_ticket: str | None = check_ticket
        self._files_modified: list[str] = []

    async def run(self, **inputs: Any) -> ComplianceMappingResult:
        """
        Analyze the check and add compliance framework mappings.

        Returns:
            ComplianceMappingResult with mapping information
        """
        logging.info("[bold cyan]Running compliance mapping agent...[/bold cyan]")

        # Load prompt and create options
        mapping_prompt: str = self._load_mapping_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        # Track files before running
        initial_modified: set[str] = self._get_modified_compliance_files()

        async with ClaudeSDKClient(options=options) as client:
            logging.info("[yellow]Analyzing compliance mappings...[/yellow]")
            await client.query(mapping_prompt)
            await self._process_agent_messages(client=client)

        # Check which files were modified
        final_modified: set[str] = self._get_modified_compliance_files()
        new_modifications: set[str] = final_modified - initial_modified
        self._files_modified = sorted(new_modifications)

        changes_made: bool = len(self._files_modified) > 0

        if changes_made:
            logging.info(
                f"[green]✓ Added compliance mappings to {len(self._files_modified)} file(s)[/green]"
            )
            for file_path in self._files_modified:
                logging.info(f"  - {file_path}")
        else:
            logging.warning("No compliance mappings were added")

        return ComplianceMappingResult(
            success=True,
            check_name=self.check_name,
            check_provider=self.check_provider,
            mappings_added=len(self._files_modified),
            files_modified=self._files_modified,
            changes_made=changes_made,
            message=f"Compliance mapping completed - {len(self._files_modified)} file(s) modified",
        )

    def _load_mapping_prompt(self) -> str:
        """Load the compliance mapping prompt template."""
        prompt_path: Path = (
            Path(__file__).parent / "prompts" / "analyze_compliance.jinja"
        )
        # Extract service from check name (first part before underscore)
        service: str = self.check_name.split("_")[0]
        return load_prompt(
            path=prompt_path,
            context={
                "check_name": self.check_name,
                "check_provider": self.check_provider,
                "service": service,
                "check_ticket": self.check_ticket,
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

    def _get_modified_compliance_files(self) -> set[str]:
        """Get the set of modified compliance JSON files."""
        try:
            diff = self.prowler_repo.git.diff("--name-only")
            if not diff:
                return set()

            modified_files: list[str] = diff.split("\n")
            compliance_files: set[str] = set()

            # Filter for compliance files for this provider
            compliance_pattern = re.compile(
                self.COMPLIANCE_FILE_PATTERN.format(provider=self.check_provider)
            )

            for file_path in modified_files:
                if compliance_pattern.match(file_path):
                    compliance_files.add(file_path)

            return compliance_files
        except Exception:
            return set()
