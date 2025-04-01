from llama_index.core.workflow import Event
from pydantic import Field

from core.src.workflows.check_creation.utils.check_metadata_model import CheckMetadata


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
