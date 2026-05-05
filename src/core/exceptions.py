"""Core exceptions for Prowler Studio."""


class ProwlerStudioError(Exception):
    """Base exception for all Prowler Studio errors."""


class AgentError(ProwlerStudioError):
    """Base exception for agent-related errors."""


class ToolError(ProwlerStudioError):
    """Base exception for tool-related errors."""


class ConfigurationError(ProwlerStudioError):
    """Base exception for configuration-related errors."""
