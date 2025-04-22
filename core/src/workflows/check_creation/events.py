from typing import Optional

from llama_index.core.workflow import Event, StartEvent, StopEvent
from pydantic import Field

from core.src.workflows.check_creation.utils.check_metadata_model import CheckMetadata


class CheckCreationInput(StartEvent):
    """Event representing the input for the check creation process."""

    user_query: str = Field(description="User query to create the check")
    llm_provider: str = Field(description="Model provider to use for the LLM")
    llm_reference: str = Field(description="Model reference to use for the LLM")
    api_key: Optional[str] = Field(
        description="API key to use for the LLM", default=None
    )


class CheckBasicInformation(Event):
    """Event representing basic information for cloud security assessments after user input analysis."""

    user_input_summary: str = Field(
        description="Summary of the user input analysis for the check"
    )
    prowler_provider: str = Field(
        description="Prowler provider to use for the check creation"
    )
    service: str = Field(
        description="Service of the provider to which the check is related"
    )


class CheckMetadataInformation(Event):
    """Event representing the information needed to generate check metadata for cloud security assessments after more in depth user input analysis."""

    user_input_summary: str = Field(
        description="Summary of the user input analysis for the check"
    )
    check_name: str = Field(description="Name of the check to create")
    prowler_provider: str = Field(
        description="Cloud provider to use for the check creation"
    )
    related_check_names: list = Field(
        description="List of related check names to the check being created"
    )


class CheckServiceInformation(Event):
    """Event representing the information needed to modify the service to be able to create a new check."""

    prowler_provider: str = Field(description="Provider of the check to create")
    check_name: str = Field(description="Name of the check to create")
    audit_steps: str = Field(description="Audit steps to identify the security issue")
    related_check_names: list = Field(
        description="List of related check names to the check being created"
    )


class CheckMetadataResult(Event):
    """Event representing the output of the check metadata generation step."""

    check_metadata: CheckMetadata = Field(description="Check metadata information")


class CheckServiceResult(Event):
    """Event representing the output of the check service modification step."""

    service_code: str = Field(description="Python code for the service")
    check_name: str = Field(description="Name of the check to create")
    prowler_provider: str = Field(
        description="Cloud provider to use for the check creation"
    )
    related_check_names: list = Field(
        description="List of related check names to the check being created"
    )
    audit_steps: str = Field(description="Audit steps to identify the security issue")


class CheckCodeResult(Event):
    """Event representing the output of the check code generation step."""

    check_code: str = Field(description="Python code for the check")
    modified_service_code: str = Field(
        description="Python Code from modified service, if not modified it will be an empty string"
    )


# Custom Stop Event
class CheckCreationResult(StopEvent):
    """Event representing the result of the check creation process."""

    status_code: int = Field(
        description="Status code of the check creation process: 0 for success, 1 for failure, 2 for error"
    )
    user_answer: Optional[str] = Field(
        description="Unified and prettified answer to display to the user",
        default=None,
    )
    check_metadata: Optional[CheckMetadata] = Field(
        description="Check metadata information",
        default=None,
    )
    check_code: Optional[str] = Field(
        description="Python code for the check",
        default=None,
    )
    check_path: Optional[str] = Field(
        description="Path to the check file in the repository",
        default=None,
    )
    generic_remediation: Optional[str] = Field(
        description="Generic remediation for the check",
        default=None,
    )
    service_code: Optional[str] = Field(
        description="Python code for the service, if not modified it will be None",
        default=None,
    )
    error_message: Optional[str] = Field(
        description="Error message for the check creation exception",
        default=None,
    )
