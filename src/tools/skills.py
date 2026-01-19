"""Skills setup tools for configuring AI assistant integration."""

import re
import subprocess  # nosec B404
from pathlib import Path

from rich import print

from core.exceptions import ToolError
from tools.models import SkillsSetupResult


class SkillsSetupError(ToolError):
    """Exception for skills setup errors."""


# Constants
SKILLS_SETUP_TIMEOUT: int = 60
SETUP_SCRIPT_PATH: str = "skills/setup.sh"
CLAUDE_FLAG: str = "--claude"


def setup_prowler_skills(prowler_directory: Path) -> SkillsSetupResult:
    """
    Set up AI skills for Claude in the Prowler repository.

    This runs the skills/setup.sh --claude script to configure symlinks
    that allow Claude to access Prowler's AI assistant skills.

    Non-blocking: returns failure result instead of raising on error.

    Args:
        prowler_directory: Path to the Prowler repository

    Returns:
        SkillsSetupResult with setup status and skills count
    """
    setup_script: Path = prowler_directory / SETUP_SCRIPT_PATH

    # Check if script exists
    if not setup_script.exists():
        return SkillsSetupResult(
            success=False,
            message=f"Setup script not found at {setup_script}",
            skills_count=0,
        )

    try:
        print("[yellow]Setting up Prowler AI skills...[/yellow]")

        # Run: bash skills/setup.sh --claude
        result: subprocess.CompletedProcess[str] = subprocess.run(  # nosec B603 B607
            ["bash", SETUP_SCRIPT_PATH, CLAUDE_FLAG],
            cwd=prowler_directory,
            capture_output=True,
            text=True,
            timeout=SKILLS_SETUP_TIMEOUT,
        )

        if result.returncode != 0:
            return SkillsSetupResult(
                success=False,
                message=f"Setup script failed: {result.stderr or result.stdout}",
                skills_count=0,
            )

        # Parse output for skills count
        # Expected format: "✅ Linked X skills"
        skills_count: int = 0
        output: str = result.stdout + result.stderr
        match = re.search(r"Linked\s+(\d+)\s+skills?", output, re.IGNORECASE)
        if match:
            skills_count = int(match.group(1))

        print(f"[green]✓ Prowler AI skills configured ({skills_count} skills)[/green]")

        return SkillsSetupResult(
            success=True,
            message=f"Successfully configured {skills_count} skills",
            skills_count=skills_count,
        )

    except subprocess.TimeoutExpired:
        return SkillsSetupResult(
            success=False,
            message=f"Setup timed out after {SKILLS_SETUP_TIMEOUT} seconds",
            skills_count=0,
        )
    except Exception as e:
        return SkillsSetupResult(
            success=False,
            message=f"Setup error: {e}",
            skills_count=0,
        )
