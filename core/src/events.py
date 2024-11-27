from typing import Literal

from llama_index.core.workflow import Event
from pydantic import Field

from core.src.utils.llm_structured_outputs import CheckMetadata


class CheckBasicInformation(Event):
    """Event representing basic information for cloud security assessments after user input analysis."""

    prowler_provider: Literal["aws", "azure", "gcp", "kubernetes"] = Field(
        description="Prowler provider to use for the check creation"
    )
    service: str = Field(
        description="Service of the provider to which the check is related"
    )


class CheckMetadataInformation(Event):
    """Event representing check information for cloud security assessments after user input analysis.

    This event is used to create a new check metadata.
    """

    check_name: str = Field(description="Name of the check to create")
    check_description: str = Field(
        description="Description of the check to create from a cloud cybersecurity perspective"
    )
    prowler_provider: Literal["aws", "azure", "gcp", "kubernetes"] = Field(
        description="Cloud provider to use for the check creation"
    )


class CheckTestInformation(Event):
    """Event representing check information for cloud security assessments after user input analysis.

    This event is used to create a new check metadata.
    """

    check_name: str = Field(description="Name of the check to create")
    check_description: str = Field(
        description="Description of the check to create from a cloud cybersecurity perspective"
    )
    prowler_provider: Literal["aws", "azure", "gcp", "kubernetes"] = Field(
        description="Cloud provider to use for the check creation"
    )


class CheckMetadataResult(Event):
    """Event representing the output of the check metadata generation step."""

    check_metadata: CheckMetadata = Field(description="Check metadata information")


class CheckTestsResult(Event):
    """Event representing the output of the check metadata generation step."""

    check_tests: str = Field(description="Python tests for the check")
