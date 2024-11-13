from typing import Literal

from pydantic import BaseModel, Field


class CheckBasicInformation(BaseModel):
    """Avaiable provider and service information for Prowler checks."""

    prowler_provider: Literal["aws", "azure", "gcp", "kubernetes"] = Field(
        description="Prowler provider to use for the check creation"
    )
    service: str = Field(
        description="Service of the provider to which the check is related"
    )
    check_name: str = Field(description="Name of the check to create")
