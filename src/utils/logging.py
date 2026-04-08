"""Simple logging setup - console (with colors) + file output."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path  # noqa: TC003 (used at runtime for path operations)
from typing import Any

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

    # Set format to just the message - Rich adds level/time, file handler has its own format
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[_file_handler, console_handler],
        force=True,
    )

    logging.info("=" * 60)
    logging.info("WORKFLOW STARTED")
    logging.info(f"Log file: {log_file}")
    logging.info("=" * 60)

    return log_file


def _emit_debug_log(msg: str) -> None:
    """Emit a DEBUG-level log record to file only."""
    if _file_handler is None:
        return
    record = logging.LogRecord(
        name="tool",
        level=logging.DEBUG,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    _file_handler.emit(record)


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
                _emit_debug_log(f"[AGENT] {line}")


def _strip_rich_markup(text: str) -> str:
    """Strip Rich console markup from text."""
    return re.sub(r"\[/?[^\]]+\]", "", text)


def log_tool_call(
    tool_name: str | None,
    tool_input: dict[str, Any] | None = None,
    tool_output: str | list[dict[str, Any]] | None = None,
    is_error: bool = False,
    tool_use_id: str | None = None,
) -> None:
    """
    Log tool call information to the log file only (not console).

    Args:
        tool_name: Name of the tool being called
        tool_input: Input parameters for the tool (for TOOL CALL)
        tool_output: Output from the tool (for TOOL RESULT)
        is_error: Whether the tool result was an error
        tool_use_id: Unique ID for correlating calls and results
    """
    if _file_handler is None:
        return

    id_suffix = f" (id={tool_use_id})" if tool_use_id else ""

    if tool_input is not None:
        # Log tool call with input
        _emit_debug_log(f"[TOOL CALL] {tool_name}{id_suffix}")

        # Log the input as formatted JSON
        try:
            input_json = json.dumps(tool_input, indent=2)
            for line in input_json.splitlines():
                _emit_debug_log(line)
        except (TypeError, ValueError):
            # Fallback if JSON serialization fails
            _emit_debug_log(str(tool_input))

    elif tool_output is not None:
        # Log tool result
        status = "ERROR" if is_error else "OK"
        _emit_debug_log(f"[TOOL RESULT] {tool_name} [{status}]")

        # Log the output (truncated if too long)
        output_str = _format_tool_output(tool_output)
        max_lines = 50
        lines = output_str.splitlines()
        if len(lines) > max_lines:
            lines = [
                *lines[:max_lines],
                f"... (truncated, {len(lines) - max_lines} more lines)",
            ]

        for line in lines:
            _emit_debug_log(line)


def _format_tool_output(output: str | list[dict[str, Any]]) -> str:
    """Format tool output for logging."""
    if isinstance(output, str):
        return output
    try:
        return json.dumps(output, indent=2)
    except (TypeError, ValueError):
        return str(output)
