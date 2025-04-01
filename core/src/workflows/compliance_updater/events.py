from llama_index.core.workflow import Event
from pydantic import Field


class ComplianceBasicInformation(Event):
    """Event representing basic information for compliance security assessments after user input analysis."""

    prowler_provider: str = Field(
        description="Prowler provider to use for the check creation"
    )
    service: str = Field(
        description="Service of the provider to which the check is related"
    )
    compliance_data: dict = Field(description="Compliance data to update")


class ComplianceDataResult(Event):
    """Event representing the output of the compliance data update step."""

    original_compliance_data: dict = Field(description="Original compliance data")
    updated_compliance_data: list = Field(description="Updated compliance data")
