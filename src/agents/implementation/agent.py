"""Implementation agent for creating Prowler checks."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from git import Repo

    from tools.models import CheckVerificationStatus

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    create_sdk_mcp_server,
)
from rich import print

from agents.base import Agent
from agents.implementation.models import (
    CheckDiscoveryResult,
    CheckImplementationResult,
    CheckVerificationResult,
)
from tools.prowler import mkcheck, verify_check_loaded
from utils.logging import log_agent_output
from utils.prompts import load_prompt


class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # MCP Server Configuration
    MCP_SERVER_NAME: ClassVar[str] = "utils"
    MCP_SERVER_VERSION: ClassVar[str] = "1.0.0"

    # Check Verification
    MAX_CHECK_VERIFICATION_ATTEMPTS: ClassVar[int] = 5

    # File name constants
    INIT_FILE: ClassVar[str] = "__init__.py"

    ALLOWED_TOOLS: ClassVar[list[str]] = [
        "Read",
        "Write",
        "Edit",
        "Bash",
        "Glob",
        "Grep",
        "mcp__utils__mkcheck",
    ]

    def __init__(
        self,
        working_dir: Path,
        check_ticket: str | None,
        prowler_repo: Repo,
        **kwargs: Any,
    ) -> None:
        super().__init__(working_dir, **kwargs)
        self.check_ticket: str | None = check_ticket
        self.prowler_repo: Repo = prowler_repo

    async def run(self) -> CheckImplementationResult:  # type: ignore[override]
        """
        Implement a Prowler check.

        Returns:
            CheckImplementationResult with implementation information
        """
        print("[bold cyan]Running implementation agent...[/bold cyan]")

        # Load prompt and create options
        implement_check_prompt: str = self._load_implementation_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        # Run Claude agent
        async with ClaudeSDKClient(options=options) as client:
            # Initial implementation
            await client.query(implement_check_prompt)
            await self._process_agent_messages(client=client)

            # Discover the newly created check
            discovery_result: CheckDiscoveryResult = self._discover_check_info()
            if not discovery_result.success:
                return CheckImplementationResult(
                    success=False,
                    error="No check folders found in repository changes",
                )

            # Verify and fix the check
            verification_result: CheckVerificationResult = (
                await self._verify_and_fix_check(
                    client=client,
                    check_name=discovery_result.check_name,
                    check_provider=discovery_result.check_provider,
                )
            )

        return CheckImplementationResult(
            success=verification_result.success,
            check_name=discovery_result.check_name,
            check_provider=discovery_result.check_provider,
            message=verification_result.message,
            attempts=verification_result.attempts,
        )

    def _load_implementation_prompt(self) -> str:
        """
        Load the check implementation prompt template.

        Returns:
            Rendered prompt string
        """
        prompt_path: Path = Path(__file__).parent / "prompts" / "implement_check.jinja"
        return load_prompt(
            path=prompt_path,
            context={
                "check_ticket": self.check_ticket,
            },
        )

    def _load_fix_prompt(self, check_name: str, verification_message: str) -> str:
        """
        Load the check fix prompt template.

        Args:
            check_name: Name of the check to fix
            verification_message: Error message from verification

        Returns:
            Rendered prompt string
        """
        fix_prompt_path: Path = Path(__file__).parent / "prompts" / "fix_check.jinja"
        return load_prompt(
            path=fix_prompt_path,
            context={
                "check_name": check_name,
                "verification_message": verification_message,
            },
        )

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """
        Create Claude agent options with tools and MCP servers.

        Returns:
            Configured ClaudeAgentOptions instance
        """
        tools_server: Any = create_sdk_mcp_server(
            name=self.MCP_SERVER_NAME,
            version=self.MCP_SERVER_VERSION,
            tools=[mkcheck],
        )

        mcp_servers: dict[str, Any] = {"utils": tools_server}

        return ClaudeAgentOptions(
            allowed_tools=self.ALLOWED_TOOLS,
            mcp_servers=mcp_servers,
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    async def _process_agent_messages(self, client: ClaudeSDKClient) -> None:
        """
        Process and print messages from the Claude agent.

        Args:
            client: Claude SDK client instance
        """
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text, end="")
                        log_agent_output(block.text)
            elif isinstance(message, ResultMessage):
                print()
                break

    def _discover_check_info(self) -> CheckDiscoveryResult:
        """
        Discover the newly created check from repository changes.

        Returns:
            CheckDiscoveryResult with discovery information
        """
        check_folders: list[Path] = self._get_new_check_folders()

        if not check_folders:
            print("[red]✗ Could not find check name in repository changes[/red]")
            return CheckDiscoveryResult(success=False)

        if len(check_folders) > 1:
            print(
                "[yellow]✗ Multiple check folders found in repository changes. Selecting the first one...[/yellow]"
            )

        check_path: Path = check_folders[0]
        check_name: str = check_path.name
        check_provider: str = check_path.parents[2].name

        print(f"[cyan]Found check: {check_name}[/cyan]")
        return CheckDiscoveryResult(
            success=True, check_name=check_name, check_provider=check_provider
        )

    async def _verify_and_fix_check(
        self, client: ClaudeSDKClient, check_name: str, check_provider: str
    ) -> CheckVerificationResult:
        """
        Verify the check implementation and fix issues in a loop.

        Args:
            client: Claude SDK client instance
            check_name: Name of the check
            check_provider: Provider of the check (e.g., 'aws', 'azure')

        Returns:
            CheckVerificationResult with verification information
        """
        max_attempts: int = self.MAX_CHECK_VERIFICATION_ATTEMPTS
        attempt: int = 0
        success: bool = False
        message: str = ""

        while attempt < max_attempts and not success:
            attempt += 1
            print(
                f"[yellow]Verifying check implementation (attempt {attempt}/{max_attempts})...[/yellow]"
            )

            verification_status: CheckVerificationStatus = verify_check_loaded(
                check_name=check_name,
                provider=check_provider,
                prowler_directory=Path(self.prowler_repo.working_dir),
            )

            success = verification_status.success
            message = verification_status.message

            print(message)

            if not success:
                fix_prompt: str = self._load_fix_prompt(
                    check_name=check_name, verification_message=message
                )

                print(
                    f"[yellow]Check verification failed. Requesting fixes (attempt {attempt}/{max_attempts})...[/yellow]"
                )

                await client.query(fix_prompt)
                await self._process_agent_messages(client=client)

        if not success:
            print(
                f"[red]✗ Failed to create a valid check after {max_attempts} attempts[/red]"
            )

        return CheckVerificationResult(
            success=success, message=message, attempts=attempt
        )

    def _get_new_check_folders(self) -> list[Path]:
        """
        Get list of new check folder paths from git untracked changes.

        Looks for untracked directories that contain both:
        - {check_name}.py
        - {check_name}.metadata.json

        Returns:
            List of Path objects pointing to check folders
        """
        # Get untracked files
        untracked: list[str] = self.prowler_repo.untracked_files

        # Group files by directory
        files_by_dir: dict[str, list[str]] = {}
        for file_path in untracked:
            dir_name: str = str(Path(file_path).parent)
            filename: str = Path(file_path).name
            if dir_name not in files_by_dir:
                files_by_dir[dir_name] = []
            files_by_dir[dir_name].append(filename)

        # Find directories with both .py and .metadata.json files
        check_folders: list[Path] = []
        for dir_name, filenames in files_by_dir.items():
            # Extract base names (without extensions)
            py_files: set[str] = {
                filename.replace(".py", "")
                for filename in filenames
                if filename.endswith(".py") and filename != self.INIT_FILE
            }
            json_files: set[str] = {
                filename.replace(".metadata.json", "")
                for filename in filenames
                if filename.endswith(".metadata.json")
            }

            # Find common base names (indicates a check folder)
            common_names: set[str] = py_files & json_files

            if common_names:
                check_folders.append(Path(dir_name))

        return check_folders
