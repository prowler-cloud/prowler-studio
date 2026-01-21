"""Testing agent for generating and running Prowler check tests."""

from __future__ import annotations

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
from rich import print

from agents.base import Agent
from agents.testing.models import TestingResult
from tools.prowler import run_pytest
from utils.logging import log_agent_output
from utils.prompts import load_prompt


class TestingAgent(Agent):
    """Agent that generates and runs tests for Prowler checks."""

    MAX_TEST_FIX_ATTEMPTS: int = 5
    ALLOWED_TOOLS: ClassVar[list[str]] = [
        "Read",
        "Write",
        "Edit",
        "Bash",
        "Glob",
        "Grep",
    ]

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

        service: str = self.check_name.split("_")[0]
        test_file_path: str = self._build_test_file_path(service)
        options: ClaudeAgentOptions = self._create_claude_options()

        async with ClaudeSDKClient(options=options) as client:
            await self._generate_tests(client)
            success, attempt, message = await self._run_test_and_fix_loop(
                client=client,
                service=service,
                test_file_path=test_file_path,
            )

        return TestingResult(
            success=success,
            check_name=self.check_name,
            test_file_path=test_file_path,
            attempts=attempt,
            changes_made=True,
            message=message,
        )

    def _build_test_file_path(self, service: str) -> str:
        """Build the test file path for the check."""
        return (
            f"tests/providers/{self.check_provider}/services/{service}/"
            f"{self.check_name}/{self.check_name}_test.py"
        )

    async def _generate_tests(self, client: ClaudeSDKClient) -> None:
        """Generate tests using Claude agent."""
        print("[yellow]Generating tests...[/yellow]")
        generate_prompt: str = self._load_generate_prompt()
        await client.query(generate_prompt)
        await self._process_agent_messages(client=client)

    async def _run_test_and_fix_loop(
        self,
        client: ClaudeSDKClient,
        service: str,
        test_file_path: str,
    ) -> tuple[bool, int, str]:
        """Run tests and attempt fixes until success or max attempts reached."""
        prowler_directory: Path = Path(self.prowler_repo.working_dir)
        attempt: int = 0
        success: bool = False
        message: str = ""

        while attempt < self.MAX_TEST_FIX_ATTEMPTS and not success:
            attempt += 1
            print(
                f"[yellow]Running tests (attempt {attempt}/{self.MAX_TEST_FIX_ATTEMPTS})...[/yellow]"
            )

            success, message = await self._run_single_test_iteration(
                client=client,
                service=service,
                test_file_path=test_file_path,
                prowler_directory=prowler_directory,
                attempt=attempt,
            )

        if not success:
            message = f"Tests failed after {self.MAX_TEST_FIX_ATTEMPTS} attempts"
            print(f"[red]✗ {message}[/red]")

        return success, attempt, message

    async def _run_single_test_iteration(
        self,
        client: ClaudeSDKClient,
        service: str,
        test_file_path: str,
        prowler_directory: Path,
        attempt: int,
    ) -> tuple[bool, str]:
        """Run a single test iteration and fix if needed."""
        check_test_result = run_pytest(
            test_path=Path(test_file_path),
            prowler_directory=prowler_directory,
        )

        if not check_test_result.success:
            print("[yellow]Check tests failed, attempting fix...[/yellow]")
            await self._attempt_fix(
                client, test_file_path, check_test_result.error_output, attempt
            )
            return False, ""

        service_test_path: str = (
            f"tests/providers/{self.check_provider}/services/{service}/"
        )
        service_test_result = run_pytest(
            test_path=Path(service_test_path),
            prowler_directory=prowler_directory,
        )

        if service_test_result.success:
            message: str = (
                f"All tests passed for {self.check_name} and service {service}"
            )
            print(f"[green]✓ {message}[/green]")
            return True, message

        print("[yellow]Service tests failed, attempting fix...[/yellow]")
        await self._attempt_fix(
            client, test_file_path, service_test_result.error_output, attempt
        )
        return False, ""

    async def _attempt_fix(
        self,
        client: ClaudeSDKClient,
        test_file_path: str,
        error_output: str,
        attempt: int,
    ) -> None:
        """Attempt to fix failing tests."""
        fix_prompt: str = self._load_fix_prompt(
            test_file_path=test_file_path,
            error_output=error_output,
            attempt=attempt,
        )
        await client.query(fix_prompt)
        await self._process_agent_messages(client=client)

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
        return ClaudeAgentOptions(
            allowed_tools=self.ALLOWED_TOOLS,
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
                        log_agent_output(block.text)
            elif isinstance(message, ResultMessage):
                print()
                break
