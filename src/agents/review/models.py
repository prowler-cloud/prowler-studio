"""Pydantic models for ReviewAgent results."""

from typing import Literal

from pydantic import BaseModel, Field


class ReviewIssue(BaseModel):
    """A single issue found during code review."""

    severity: Literal["critical", "major", "minor"] = Field(
        description="Severity level of the issue"
    )
    category: str = Field(
        description="Issue category: agents_md, developer_guide, metadata, security"
    )
    file_path: str = Field(description="Path to the file with the issue")
    description: str = Field(description="Description of the issue")
    fixed: bool = Field(default=False, description="Whether the issue was auto-fixed")


class ReviewResult(BaseModel):
    """Result of reviewing a Prowler check."""

    success: bool = Field(description="Whether review passed (no critical issues)")
    check_name: str = Field(default="", description="Name of the reviewed check")
    issues_found: list[ReviewIssue] = Field(
        default_factory=list, description="List of issues found"
    )
    issues_fixed: int = Field(default=0, description="Number of issues auto-fixed")
    changes_made: bool = Field(
        default=False, description="Whether changes were made (triggers re-test)"
    )
    message: str = Field(default="", description="Result message")
