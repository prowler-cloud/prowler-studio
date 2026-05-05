"""Pydantic models for ChecKreatorAgent results."""

from pydantic import BaseModel, Field


class CheckDiscoveryResult(BaseModel):
    """Result of discovering a check from repository changes."""

    success: bool = Field(description="Whether check discovery was successful")
    check_name: str = Field(default="", description="Name of the discovered check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )


class CheckVerificationResult(BaseModel):
    """Result of verifying and fixing a check implementation."""

    success: bool = Field(description="Whether verification succeeded")
    message: str = Field(description="Verification or error message")
    attempts: int = Field(description="Number of verification attempts made")


class CheckImplementationResult(BaseModel):
    """Result of implementing a Prowler check."""

    success: bool = Field(description="Whether implementation was successful")
    check_name: str = Field(default="", description="Name of the implemented check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )
    message: str = Field(default="", description="Result message")
    attempts: int = Field(default=0, description="Number of verification attempts")
    error: str | None = Field(default=None, description="Error message if failed")
