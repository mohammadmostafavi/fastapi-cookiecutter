from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """
    Schema for detailed error information.
    Used for validation errors or other detailed error information.
    """
    loc: Optional[List[str]] = Field(None, description="Location of the error")
    msg: str = Field(..., description="Error message")
    type: Optional[str] = Field(None, description="Error type")


class ErrorResponse(BaseModel):
    """
    Standard error response schema.
    All API error responses will follow this format.
    """
    error_code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Union[List[ErrorDetail], Dict[str, Any]]] = Field(
        None, description="Additional error details"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "error_code": "validation_error",
                "message": "Validation error",
                "details": [
                    {
                        "loc": ["body", "username"],
                        "msg": "field required",
                        "type": "value_error.missing"
                    }
                ]
            }
        }