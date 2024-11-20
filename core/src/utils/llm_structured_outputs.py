from typing import List, Literal

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


class CodeModel(BaseModel):
    """Represents the remediation code using IaC like CloudFormation, Terraform or the native CLI."""

    NativeIaC: str = Field(description="Native IaC code")
    Terraform: str = Field(description="Terraform code")
    CLI: str = Field(description="CLI code")
    Other: str = Field(description="Other code")


class RecommendationModel(BaseModel):
    """Represents a recommendation."""

    Text: str = Field(description="The recommendation text")
    Url: str = Field(description="The recommendation URL")


class RemediationModel(BaseModel):
    """Represents a remediation action for a specific check."""

    Code: CodeModel = Field(
        description="The code associated with the remediation action"
    )
    Recommendation: RecommendationModel = Field(
        description="The recommendation for the remediation action"
    )


class CheckMetadata(BaseModel):
    """Metadata information of a Prowler check."""

    Provider: Literal["aws", "azure", "gcp", "kubernetes"] = Field(
        description="The provider of the check"
    )
    CheckID: str = Field(description="ID of the check")
    CheckTitle: str = Field(description="Title of the check")
    CheckType: List[str] = Field(description="For now this will be an empty str")
    ServiceName: str = Field(
        description="Name of the service that the check belongs to"
    )
    SubServiceName: str = Field(description="For now this will be an empty str")
    ResourceIdTemplate: str = Field(
        description="Template of the resource ID that the check will audit mainly"
    )
    Severity: Literal["critical", "high", "medium", "low"] = Field(
        description="Security severity of the check"
    )
    ResourceType: str = Field(description="For now this will be an empty str")
    Description: str = Field(description="Description of the check")
    Risk: str = Field(description="Security risk asociated with the check")
    RelatedUrl: str = Field(description="For now this will be an empty str")
    Remediation: RemediationModel = Field(
        description="The remediation action for the check"
    )
    Categories: List[str] = Field(description="For now this will be an empty List")
    DependsOn: List[str] = Field(description="For now this will be an empty List")
    RelatedTo: List[str] = Field(description="For now this will be an empty List")
    Notes: str = Field(description="Additional notes for the check")
