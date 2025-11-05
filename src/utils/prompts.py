"""Prompt loading utilities."""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from core.exceptions import ConfigurationError


def load_prompt(path: Path, context: dict[str, Any] | None = None) -> str:
    """
    Load and render a prompt template.

    Args:
        path: Path to the prompt template file
        context: Optional data passed to the template during rendering

    Returns:
        Rendered prompt content

    Raises:
        ConfigurationError: If the prompt file is not found or rendering fails
    """
    if not path.exists():
        raise ConfigurationError(f"Prompt file not found: {path}")

    try:
        # Create environment rooted at the prompt's parent directory
        # autoescape=False is safe here as we're generating prompts, not HTML
        env: Environment = Environment(
            loader=FileSystemLoader(path.parent),
            autoescape=False,  # nosec B701
            trim_blocks=True,
            lstrip_blocks=True,
        )

        template = env.get_template(path.name)
        return template.render(**(context or {}))

    except TemplateNotFound as e:
        raise ConfigurationError(f"Prompt template not found: {path}") from e
    except Exception as e:
        raise ConfigurationError(f"Failed to render prompt template {path}: {e}") from e
