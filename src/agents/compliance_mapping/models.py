"""Pydantic models for ComplianceMappingAgent results."""

from typing import Literal

from pydantic import BaseModel, Field


class ComplianceMapping(BaseModel):
    """A suggested compliance framework mapping."""

    framework_id: str = Field(
        description="Compliance framework ID (e.g., 'cis_4.0_aws')"
    )
    framework_name: str = Field(
        description="Human-readable framework name (e.g., 'CIS Amazon Web Services Foundations Benchmark v4.0')"
    )
    requirement_id: str = Field(
        description="Requirement ID within the framework (e.g., '2.1.2')"
    )
    requirement_name: str = Field(description="Human-readable requirement name")
    confidence: Literal["high", "medium", "low"] = Field(
        description="Confidence level of the mapping suggestion"
    )
    reason: str = Field(description="Explanation of why this mapping is suggested")


class ComplianceMappingResult(BaseModel):
    """Result of compliance mapping analysis."""

    success: bool = Field(
        description="Whether the compliance mapping completed successfully"
    )
    check_name: str = Field(default="", description="Name of the check")
    check_provider: str = Field(default="", description="Provider of the check")
    suggested_mappings: list[ComplianceMapping] = Field(
        default_factory=list, description="List of suggested compliance mappings"
    )
    mappings_added: int = Field(
        default=0, description="Number of mappings added to compliance files"
    )
    files_modified: list[str] = Field(
        default_factory=list,
        description="List of compliance JSON files that were updated",
    )
    changes_made: bool = Field(
        default=False, description="Whether any compliance files were modified"
    )
    message: str = Field(default="", description="Result message")
    error: str | None = Field(default=None, description="Error message if failed")
