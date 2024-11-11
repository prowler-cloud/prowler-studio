from pydantic import BaseModel, field_validator


class ResultPromptAnalysis(BaseModel):
    """Model to represent the prompt analysis event."""

    security_logic: str
    provider: str
    service: str
    check_name: str

    @field_validator("provider")
    def validate_provider(cls, value):
        if value not in {"aws", "azure", "gcp", "kubernetes", "NONE"}:
            raise ValueError("Provider must be one of: aws, azure, gcp, kubernetes")
        return value
