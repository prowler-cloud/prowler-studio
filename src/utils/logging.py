"""Workflow logging utilities for debugging agent reasoning."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from pathlib import Path  # noqa: TC003 (needed at runtime for path operations)
from typing import ClassVar

from rich.console import Console

_console = Console()

# Global logger instance for easy access
_workflow_logger: WorkflowLogger | None = None


def get_workflow_logger() -> WorkflowLogger | None:
    """Get the global workflow logger instance."""
    return _workflow_logger


def set_workflow_logger(logger: WorkflowLogger | None) -> None:
    """Set the global workflow logger instance."""
    global _workflow_logger
    _workflow_logger = logger


def log_agent_output(text: str) -> None:
    """
    Log agent output to the workflow log file.

    Args:
        text: Agent output text
    """
    if _workflow_logger:
        _workflow_logger.log_agent_output(text)


def log_stage(stage_name: str) -> None:
    """
    Log a stage marker to the workflow log file.

    Args:
        stage_name: Name of the stage
    """
    if _workflow_logger:
        _workflow_logger.log_stage(stage_name)


def console_error(message: str) -> None:
    """
    Print an error message to console only (before logger is initialized).

    Args:
        message: Error message to display
    """
    _console.print(f"[red]✗ {message}[/red]")


class WorkflowLogger:
    """
    Logger for workflow runs with file output.

    Creates timestamped log files for debugging agent reasoning.
    Logs are written to the `logs/` directory.
    """

    DATE_FORMAT: ClassVar[str] = "%Y-%m-%d_%H%M%S"
    LOG_FORMAT: ClassVar[str] = "%(asctime)s | %(levelname)-8s | %(message)s"

    def __init__(
        self,
        base_dir: Path,
        jira_ticket: str | None = None,
    ) -> None:
        """
        Initialize the workflow logger.

        Args:
            base_dir: Base directory for the logs folder
            jira_ticket: Optional Jira ticket key for log filename
        """
        self.logs_dir: Path = base_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        self.jira_ticket: str | None = jira_ticket
        self.start_time: datetime = datetime.now()
        self.log_file: Path = self._generate_log_filename()
        self.logger: logging.Logger = self._setup_logger()

        # Log initial info
        self.logger.info("=" * 60)
        self.logger.info("WORKFLOW STARTED")
        self.logger.info(f"Start time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.jira_ticket:
            self.logger.info(f"Jira ticket: {self.jira_ticket}")
        self.logger.info("=" * 60)

    def _generate_log_filename(self) -> Path:
        """
        Generate the log filename with timestamp and optional ticket key.

        Returns:
            Path to the log file
        """
        timestamp: str = self.start_time.strftime(self.DATE_FORMAT)

        if self.jira_ticket:
            filename: str = f"{timestamp}_{self.jira_ticket}.log"
        else:
            filename = f"{timestamp}.log"

        return self.logs_dir / filename

    def _setup_logger(self) -> logging.Logger:
        """
        Set up the logger with file handler.

        Returns:
            Configured logger instance
        """
        logger: logging.Logger = logging.getLogger(f"workflow_{id(self)}")
        logger.setLevel(logging.DEBUG)

        # Remove any existing handlers
        logger.handlers.clear()

        # File handler
        file_handler: logging.FileHandler = logging.FileHandler(
            self.log_file, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)

        # Formatter
        formatter: logging.Formatter = logging.Formatter(
            self.LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

        return logger

    def _strip_rich_markup(self, text: str) -> str:
        """
        Strip Rich console markup from text.

        Args:
            text: Text with potential Rich markup

        Returns:
            Plain text without markup
        """
        # Remove Rich markup tags like [bold], [red], [/bold], etc.
        return re.sub(r"\[/?[^\]]+\]", "", text)

    def log_agent_output(self, text: str) -> None:
        """
        Log agent output text.

        Args:
            text: Agent output text (may contain Rich markup)
        """
        clean_text: str = self._strip_rich_markup(text)
        if clean_text.strip():
            for line in clean_text.splitlines():
                if line.strip():
                    self.logger.debug(f"[AGENT] {line}")

    def log_stage(self, stage_name: str) -> None:
        """
        Log a stage marker.

        Args:
            stage_name: Name of the stage
        """
        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info(f"STAGE: {stage_name}")
        self.logger.info("=" * 60)

    def log_info(self, message: str) -> None:
        """
        Log an info message.

        Args:
            message: Message to log
        """
        self.logger.info(message)

    def log_error(self, message: str) -> None:
        """
        Log an error message.

        Args:
            message: Error message to log
        """
        self.logger.error(message)

    def info(self, message: str) -> None:
        """
        Log an info message to both console (with Rich) and log file.

        Args:
            message: Message to log
        """
        _console.print(message)
        clean_message = self._strip_rich_markup(message)
        self.logger.info(clean_message)

    def success(self, message: str) -> None:
        """
        Log a success message to both console (with Rich) and log file.

        Args:
            message: Success message to log
        """
        _console.print(f"[green]✓ {message}[/green]")
        self.logger.info(f"SUCCESS: {message}")

    def error(self, message: str) -> None:
        """
        Log an error message to both console (with Rich) and log file.

        Args:
            message: Error message to log
        """
        _console.print(f"[red]✗ {message}[/red]")
        self.logger.error(message)

    def warning(self, message: str) -> None:
        """
        Log a warning message to both console (with Rich) and log file.

        Args:
            message: Warning message to log
        """
        _console.print(f"[yellow]⚠ {message}[/yellow]")
        self.logger.warning(message)

    def stage(self, stage_name: str) -> None:
        """
        Log a stage marker to both console (with Rich) and log file.

        Args:
            stage_name: Name of the stage
        """
        _console.print(f"\n[bold cyan]=== {stage_name} ===[/bold cyan]")
        self.log_stage(stage_name)

    def print(self, message: str) -> None:
        """
        Print a message to both console (with Rich markup) and log file.

        This is a general-purpose method for messages that need Rich formatting
        but don't fit info/success/error/warning categories.

        Args:
            message: Message to print (may contain Rich markup)
        """
        _console.print(message)
        clean_message = self._strip_rich_markup(message)
        if clean_message.strip():
            self.logger.info(clean_message)

    def finalize(self, success: bool) -> None:
        """
        Finalize the log with summary information.

        Args:
            success: Whether the workflow completed successfully
        """
        end_time: datetime = datetime.now()
        duration: timedelta = end_time - self.start_time

        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("WORKFLOW COMPLETE")
        self.logger.info(f"End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"Duration: {duration}")
        self.logger.info(f"Success: {success}")
        self.logger.info("=" * 60)

        # Close all handlers
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)
