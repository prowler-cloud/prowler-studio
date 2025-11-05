"""Base agent class for all agents."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class Agent(ABC):
    """
    Simple base class for agents.

    Each agent is just a self-contained unit that does one thing.
    No complex lifecycle, no status tracking - just execute the task.
    """

    def __init__(self, working_dir: Path, **kwargs: Any) -> None:
        """
        Initialize the agent.

        Args:
            working_dir: Working directory for the agent
            **kwargs: Agent-specific configuration
        """
        self.working_dir = working_dir
        self.config = kwargs

    @abstractmethod
    async def run(self, **inputs: Any) -> Any:
        """
        Run the agent.

        Args:
            **inputs: Input data for the agent

        Returns:
            Agent-specific result object

        Raises:
            AgentError: If agent execution fails
        """
