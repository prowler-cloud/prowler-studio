from llama_index.core.workflow import Event
from pydantic import Field


class ComplianceBasicInformation(Event):
    """Event representing basic information for compliance security assessments after user input analysis."""

    prowler_provider: str = Field(
        description="Prowler provider to use for the check creation"
    )
    compliance_data: dict = Field(description="Compliance data to update")
    max_check_number_per_requirement: int = Field(
        description="Maximum number of checks to create for each compliance requirement"
    )
    confidence_threshold: float = Field(
        description="Confidence threshold for the compliance data"
    )


class ComplianceDataResult(Event):
    """Event representing the output of the compliance data update step."""

    original_compliance_data: dict = Field(description="Original compliance data")
    updated_compliance_data: list = Field(description="Updated compliance data")
