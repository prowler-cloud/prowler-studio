from typing import Optional

from llama_index.core.workflow import Event, StartEvent, StopEvent
from pydantic import Field

# TODO: Import or define any models needed for fixer metadata, etc.


class FixerCreationInput(StartEvent):
    """Event representing the input for the fixer creation process."""

    prowler_provider: str = Field(
        description="Prowler provider to which the fixer will be added"
    )
    check_id: str = Field(description="Check ID to which the fixer will be added")
    llm_provider: str = Field(description="Model provider to use for the LLM")
    llm_reference: str = Field(description="Model reference to use for the LLM")
    api_key: Optional[str] = Field(
        description="API key to use for the LLM", default=None
    )


class FixerBasicInformation(Event):
    """Event representing basic information after user input analysis for fixer creation."""

    check_description: str = Field(description="Description of the check")
    check_code: str = Field(description="Code of the check")
    check_id: str = Field(description="ID of the check")


class FixerCodeResult(Event):
    """Event representing the output of the fixer code generation step."""

    fixer_code: str = Field(description="Python code for the fixer")
    file_path: str = Field(description="Path to the fixer file in the repository")


class FixerCreationResult(StopEvent):
    """Event representing the result of the fixer creation process."""

    status_code: int = Field(
        description="Status code of the fixer creation process: 0 for success, 1 for failure, 2 for error"
    )
    user_answer: Optional[str] = Field(
        description="Unified and prettified answer to display to the user", default=None
    )
    fixer_code: Optional[str] = Field(
        description="Python code for the fixer", default=None
    )
    fixer_path: Optional[str] = Field(
        description="Path to the fixer file in the repository", default=None
    )
    error_message: Optional[str] = Field(
        description="Error message for the fixer creation exception", default=None
    )
