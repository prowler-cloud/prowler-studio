"""Simple Pydantic models for Prowler findings."""

from pydantic import BaseModel


class Finding(BaseModel):
    """A simplified Prowler security finding with only essential fields."""

    finding_id: str
    check_id: str
    severity: str
    problem: str  # status_extended - what's wrong
    remediation_cli: str  # CLI command to fix
    remediation_text: str  # Recommendation text
    remediation_url: str  # Recommendation URL

    class Config:
        """Pydantic config."""

        extra = "ignore"  # Ignore extra fields from JSON
