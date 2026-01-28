"""Simple logging setup - console (with colors) + file output."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path  # noqa: TC003 (used at runtime for path operations)

from rich.logging import RichHandler

# Module-level file handler for agent output logging
_file_handler: logging.FileHandler | None = None


def setup_logging(base_dir: Path, ticket: str | None = None) -> Path:
    """
    Configure logging to output to both console (colored) and file.

    Args:
        base_dir: Base directory for the logs folder
        ticket: Optional ticket key for log filename

    Returns:
        Path to the log file
    """
    global _file_handler

    logs_dir = base_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"{timestamp}_{ticket}.log" if ticket else f"{timestamp}.log"
    log_file = logs_dir / filename

    # File handler (plain text)
    _file_handler = logging.FileHandler(log_file, encoding="utf-8")
    _file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
    )

    # Console handler (colored with Rich)
    console_handler = RichHandler(rich_tracebacks=True, markup=True)

    logging.basicConfig(
        level=logging.INFO,
        handlers=[_file_handler, console_handler],
        force=True,
    )

    logging.info("=" * 60)
    logging.info("WORKFLOW STARTED")
    logging.info(f"Log file: {log_file}")
    logging.info("=" * 60)

    return log_file


def log_agent_output(text: str) -> None:
    """
    Log agent output text to the log file only (not console).

    Args:
        text: Agent output text (may contain Rich markup)
    """
    if _file_handler is None:
        return

    clean_text = _strip_rich_markup(text)
    if clean_text.strip():
        for line in clean_text.splitlines():
            if line.strip():
                record = logging.LogRecord(
                    name="agent",
                    level=logging.DEBUG,
                    pathname="",
                    lineno=0,
                    msg=f"[AGENT] {line}",
                    args=(),
                    exc_info=None,
                )
                _file_handler.emit(record)


def _strip_rich_markup(text: str) -> str:
    """Strip Rich console markup from text."""
    return re.sub(r"\[/?[^\]]+\]", "", text)
