"""Pydantic models for TestingAgent results."""

from pydantic import BaseModel, Field


class TestingResult(BaseModel):
    """Result of testing a Prowler check."""

    success: bool = Field(description="Whether all tests passed")
    check_name: str = Field(default="", description="Name of the tested check")
    test_file_path: str = Field(default="", description="Path to the test file")
    attempts: int = Field(default=0, description="Number of test/fix attempts")
    changes_made: bool = Field(
        default=False, description="Whether changes were made to tests"
    )
    message: str = Field(default="", description="Result message")
    error: str | None = Field(default=None, description="Error message if failed")
