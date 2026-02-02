"""Base agent class for all agents."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from claude_agent_sdk import ClaudeSDKClient

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)

from utils.logging import log_agent_output, log_tool_call


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
        self._tool_names_by_id: dict[str, str] = {}

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

    async def _process_agent_messages(self, client: "ClaudeSDKClient") -> None:
        """
        Process and stream messages from the Claude agent.

        Handles TextBlock (prints + logs), ToolUseBlock (logs input at DEBUG),
        and ToolResultBlock (logs output at DEBUG).

        Args:
            client: Claude SDK client instance
        """
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text, end="", flush=True)
                        log_agent_output(block.text)
                    elif isinstance(block, ToolUseBlock):
                        self._tool_names_by_id[block.id] = block.name
                        log_tool_call(
                            tool_name=block.name,
                            tool_input=block.input,
                            tool_use_id=block.id,
                        )
                    elif isinstance(block, ToolResultBlock):
                        tool_name = self._tool_names_by_id.get(
                            block.tool_use_id, "Unknown"
                        )
                        log_tool_call(
                            tool_name=tool_name,
                            tool_output=block.content,
                            is_error=block.is_error or False,
                            tool_use_id=block.tool_use_id,
                        )
            elif isinstance(message, ResultMessage):
                print()
                break
