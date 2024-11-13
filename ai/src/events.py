from llama_index.core.workflow import Event
from pydantic import Field


class CheckMetadataInformation(Event):
    """Event representing check information for cloud security assessments after user input analysis.

    This event is used to create a new check metadata.
    """

    check_name: str = Field(description="Name of the check to create")
    check_description: str = Field(
        description="Description of the check to create from a cloud cybersecurity perspective"
    )
    prowler_provider: str = Field(
        description="Cloud provider to use for the check creation"
    )
