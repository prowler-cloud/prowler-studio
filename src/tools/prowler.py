"""Prowler-specific tools."""

import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from claude_agent_sdk import tool
from rich import print

from core.exceptions import ToolError
from tools.models import CheckVerificationStatus


class ProwlerToolError(ToolError):
    """Exception for Prowler tool errors."""


# Constants
DEPENDENCY_INSTALL_TIMEOUT: int = 300  # 5 minutes
CHECK_VERIFICATION_TIMEOUT: int = 60  # 1 minute
DEFAULT_WORKING_DIR: Path = Path("./working/prowler")


@tool(
    name="mkcheck",
    description="Create a new check folder and files in the Prowler repository. This creates the directory structure and empty files for a new Prowler security check.",
    input_schema={
        "provider": str,
        "check_name": str,
    },
)
async def mkcheck(args: dict[str, Any]) -> dict[str, Any]:
    """
    Create a new check folder and files in the Prowler repository.

    This tool creates the necessary directory structure and empty files
    for a new Prowler check.

    Args:
        args: Dictionary containing:
            - provider: Cloud provider (e.g., 'gcp', 'aws', 'azure')
            - check_name: Name of the check (without service prefix)

    Returns:
        Dictionary with content and optional error status
    """
    try:
        # Extract parameters with explicit type hints
        provider: str = args["provider"]
        check_name: str = args["check_name"]
        prowler_directory: Path = DEFAULT_WORKING_DIR

        # Build check folder path
        check_folder: Path = (
            prowler_directory
            / "prowler"
            / "providers"
            / provider
            / "services"
            / check_name.split("_")[0]
            / f"{check_name}"
        )
        check_folder.mkdir(parents=True, exist_ok=True)

        # Create check files
        check_file: Path = check_folder / f"{check_name}.py"
        check_file.touch()

        check_metadata: Path = check_folder / f"{check_name}.metadata.json"
        check_metadata.touch()

        init_file: Path = check_folder / "__init__.py"
        init_file.touch()

        print(f"[green]✓ Created check structure at: {check_folder}[/green]")

        return {
            "content": [
                {
                    "type": "text",
                    "text": f"✓ Successfully created check structure for {check_name} at {check_folder}",
                }
            ]
        }

    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"✗ Failed to create check: {e}"}],
            "is_error": True,
        }


def install_prowler_dependencies(prowler_directory: Path) -> None:
    """
    Install Prowler dependencies using poetry.

    Args:
        prowler_directory: Path to the Prowler repository

    Raises:
        ProwlerToolError: If installation fails
    """
    try:
        print("[yellow]Installing Prowler dependencies...[/yellow]")
        install_result: subprocess.CompletedProcess[str] = subprocess.run(  # nosec B603 B607
            ["poetry", "install", "--with", "dev"],
            cwd=prowler_directory,
            capture_output=True,
            text=True,
            timeout=DEPENDENCY_INSTALL_TIMEOUT,
        )

        if install_result.returncode != 0:
            raise ProwlerToolError(
                f"Failed to install dependencies: {install_result.stderr}"
            )

        print("[green]✓ Prowler dependencies installed[/green]")

    except subprocess.TimeoutExpired as e:
        raise ProwlerToolError(
            f"Installation timed out after {DEPENDENCY_INSTALL_TIMEOUT} seconds"
        ) from e
    except Exception as e:
        raise ProwlerToolError(f"Installation error: {e}") from e


def verify_check_loaded(
    check_name: str,
    provider: str,
    prowler_directory: Path,
) -> CheckVerificationStatus:
    """
    Verify that a check has been loaded correctly in Prowler.

    This function runs prowler <provider> --list-checks and checks if the check name appears in the output.
    Note: Dependencies must be installed before calling this function.

    Args:
        check_name: Name of the check to verify
        provider: Cloud provider (e.g., 'aws', 'azure', 'gcp', 'kubernetes')
        prowler_directory: Path to the Prowler repository

    Returns:
        CheckVerificationStatus with verification results
    """
    try:
        # Run prowler <provider> --list-checks and capture output
        output: str = subprocess.check_output(  # nosec B603 B607
            ["poetry", "run", "prowler", provider, "--list-checks"],
            cwd=prowler_directory,
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout to capture everything
            text=True,
            timeout=CHECK_VERIFICATION_TIMEOUT,
        )

        # Check if the check name appears in the output
        if check_name in output:
            return CheckVerificationStatus(
                success=True,
                message=f"✓ Check '{check_name}' is successfully loaded in Prowler",
            )
        else:
            return CheckVerificationStatus(
                success=False,
                message=f"✗ Check '{check_name}' was NOT found in Prowler's check list. "
                "This means there may be an issue with the implementation.",
            )

    except subprocess.CalledProcessError as e:
        return CheckVerificationStatus(
            success=False,
            message=f"Failed to list checks (exit code {e.returncode}): {e.output}",
        )
    except subprocess.TimeoutExpired:
        return CheckVerificationStatus(
            success=False,
            message=f"Verification timed out after {CHECK_VERIFICATION_TIMEOUT} seconds",
        )
    except Exception as e:
        return CheckVerificationStatus(
            success=False, message=f"Verification error: {e}"
        )
