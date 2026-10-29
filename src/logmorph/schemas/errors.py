"""Standardized API error schemas matching API Contract."""

from pydantic import BaseModel, ConfigDict, Field


class ErrorResponse(BaseModel):
    """Standardized API error response structure."""

    model_config = ConfigDict(extra="ignore")

    detail: str = Field(..., description="Human-readable error description")
    error_code: str = Field(..., description="Machine-readable error code")
    status_code: int = Field(..., description="HTTP status code")
