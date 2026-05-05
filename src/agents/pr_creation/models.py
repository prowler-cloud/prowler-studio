"""Pydantic models for PRCreationAgent results."""

from pydantic import BaseModel, Field


class PRCreationResult(BaseModel):
    """Result of creating a pull request."""

    success: bool = Field(description="Whether PR creation was successful")
    check_name: str = Field(default="", description="Name of the check in the PR")
    commit_sha: str = Field(default="", description="SHA of the commit")
    pr_url: str = Field(default="", description="URL of the created PR")
    pr_number: int = Field(default=0, description="Number of the created PR")
    message: str = Field(default="", description="Result message")
    error: str | None = Field(default=None, description="Error message if failed")
