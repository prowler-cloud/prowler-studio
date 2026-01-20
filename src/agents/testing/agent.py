"""Testing agent for generating and running Prowler check tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from git import Repo

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)
from rich import print

from agents.base import Agent
from agents.testing.models import TestingResult
from tools.prowler import run_pytest
from utils.prompts import load_prompt


class TestingAgent(Agent):
    """Agent that generates and runs tests for Prowler checks."""

    MAX_TEST_FIX_ATTEMPTS: int = 5

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

    async def run(self, **inputs: Any) -> TestingResult:
        """
        Generate and run tests for a Prowler check.

        Returns:
            TestingResult with testing information
        """
        print("[bold cyan]Running testing agent...[/bold cyan]")

        # Extract service from check name
        service: str = self.check_name.split("_")[0]
        test_file_path: str = (
            f"tests/providers/{self.check_provider}/services/{service}/"
            f"{self.check_name}/{self.check_name}_test.py"
        )

        # Load prompt and create options
        generate_prompt: str = self._load_generate_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        changes_made: bool = False
        attempt: int = 0
        success: bool = False
        message: str = ""

        async with ClaudeSDKClient(options=options) as client:
            # Generate tests
            print("[yellow]Generating tests...[/yellow]")
            await client.query(generate_prompt)
            await self._process_agent_messages(client=client)
            changes_made = True

            # Run tests and fix loop
            prowler_directory: Path = Path(self.prowler_repo.working_dir)

            while attempt < self.MAX_TEST_FIX_ATTEMPTS and not success:
                attempt += 1
                print(
                    f"[yellow]Running tests (attempt {attempt}/{self.MAX_TEST_FIX_ATTEMPTS})...[/yellow]"
                )

                # Run check-specific tests
                check_test_result = run_pytest(
                    test_path=Path(test_file_path),
                    prowler_directory=prowler_directory,
                )

                if check_test_result.success:
                    # Also run service tests to ensure no regressions
                    service_test_path: str = (
                        f"tests/providers/{self.check_provider}/services/{service}/"
                    )
                    service_test_result = run_pytest(
                        test_path=Path(service_test_path),
                        prowler_directory=prowler_directory,
                    )

                    if service_test_result.success:
                        success = True
                        message = (
                            f"All tests passed for {self.check_name} "
                            f"and service {service}"
                        )
                        print(f"[green]✓ {message}[/green]")
                    else:
                        # Service tests failed, need to fix
                        print(
                            "[yellow]Service tests failed, attempting fix...[/yellow]"
                        )
                        fix_prompt: str = self._load_fix_prompt(
                            test_file_path=test_file_path,
                            error_output=service_test_result.error_output,
                            attempt=attempt,
                        )
                        await client.query(fix_prompt)
                        await self._process_agent_messages(client=client)
                else:
                    # Check tests failed, need to fix
                    print("[yellow]Check tests failed, attempting fix...[/yellow]")
                    fix_prompt = self._load_fix_prompt(
                        test_file_path=test_file_path,
                        error_output=check_test_result.error_output,
                        attempt=attempt,
                    )
                    await client.query(fix_prompt)
                    await self._process_agent_messages(client=client)

            if not success:
                message = f"Tests failed after {self.MAX_TEST_FIX_ATTEMPTS} attempts"
                print(f"[red]✗ {message}[/red]")

        return TestingResult(
            success=success,
            check_name=self.check_name,
            test_file_path=test_file_path,
            attempts=attempt,
            changes_made=changes_made,
            message=message,
        )

    def _load_generate_prompt(self) -> str:
        """Load the test generation prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "generate_tests.jinja"
        return load_prompt(
            path=prompt_path,
            context={
                "check_name": self.check_name,
                "check_provider": self.check_provider,
                "prowler_repo": str(self.working_dir),
                "check_ticket": self.check_ticket,
            },
        )

    def _load_fix_prompt(
        self, test_file_path: str, error_output: str, attempt: int
    ) -> str:
        """Load the test fix prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "fix_tests.jinja"
        return load_prompt(
            path=prompt_path,
            context={
                "check_name": self.check_name,
                "check_provider": self.check_provider,
                "test_file_path": test_file_path,
                "error_output": error_output,
                "attempt": attempt,
                "max_attempts": self.MAX_TEST_FIX_ATTEMPTS,
            },
        )

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """Create Claude agent options with tools."""
        allowed_tools: list[str] = [
            "Read",
            "Write",
            "Edit",
            "Bash",
            "Glob",
            "Grep",
        ]

        return ClaudeAgentOptions(
            allowed_tools=allowed_tools,
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    async def _process_agent_messages(self, client: ClaudeSDKClient) -> None:
        """Process and print messages from the Claude agent."""
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text, end="")
            elif isinstance(message, ResultMessage):
                print()
                break
