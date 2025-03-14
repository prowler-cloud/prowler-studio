from llama_index.core.workflow import Event
from pydantic import Field

from core.src.utils.llm_structured_outputs import CheckMetadata


class CheckBasicInformation(Event):
    """Event representing basic information for cloud security assessments after user input analysis."""

    prowler_provider: str = Field(
        description="Prowler provider to use for the check creation"
    )
    service: str = Field(
        description="Service of the provider to which the check is related"
    )


class CheckMetadataInformation(Event):
    """Event representing the information needed to generate check metadata for cloud security assessments after user input analysis."""

    check_name: str = Field(description="Name of the check to create")
    check_description: str = Field(description="Short description of the check")
    prowler_provider: str = Field(
        description="Cloud provider to use for the check creation"
    )
    related_check_names: list = Field(
        description="List of related check names to the check being created"
    )


class CheckTestInformation(Event):
    """Event representing information needed to create tests for the check."""

    check_name: str = Field(description="Name of the check to create")
    base_cases_and_steps: str = Field(
        description="Base cases and steps to identify the security issue"
    )


class CheckCodeInformation(Event):
    """Event representing check code information needed to create a new check."""

    check_name: str = Field(description="Name of the check to create")
    base_cases_and_steps: str = Field(
        description="Base cases and steps to identify the security issue"
    )
    related_check_names: list = Field(
        description="List of related check names to the check being created"
    )
    prowler_provider: str = Field(
        description="Cloud provider to use for the check creation"
    )


class CheckMetadataResult(Event):
    """Event representing the output of the check metadata generation step."""

    check_metadata: CheckMetadata = Field(description="Check metadata information")


class CheckTestsResult(Event):
    """Event representing the output of the check metadata generation step."""

    check_tests: str = Field(description="Python tests for the check")


class CheckCodeResult(Event):
    """Event representing the output of the check code generation step."""

    check_code: str = Field(description="Python code for the check")
