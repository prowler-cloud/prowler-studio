"""Pydantic models for tool return types."""

from pydantic import BaseModel, Field


class CheckVerificationStatus(BaseModel):
    """Result of verifying a check is loaded in Prowler."""

    success: bool = Field(description="Whether the check was successfully loaded")
    message: str = Field(description="Verification message or error details")


class MkcheckResult(BaseModel):
    """Result of creating a new check structure."""

    success: bool = Field(description="Whether check creation was successful")
    message: str = Field(description="Success or error message")
    check_folder: str = Field(
        default="", description="Path to the created check folder"
    )


class SkillsSetupResult(BaseModel):
    """Result of setting up AI skills in the Prowler repository."""

    success: bool = Field(description="Whether skills setup was successful")
    message: str = Field(description="Success or error message")
    skills_count: int = Field(default=0, description="Number of skills configured")


class TestRunResult(BaseModel):
    """Result of running pytest."""

    success: bool = Field(description="Whether all tests passed")
    error_output: str = Field(default="", description="Error output if tests failed")
