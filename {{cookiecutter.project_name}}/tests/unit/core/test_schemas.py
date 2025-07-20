"""
Tests for Pydantic schemas in src.core.schemas.
"""

import pytest
import json
from pydantic import ValidationError

from src.core.schemas import ErrorDetail, ErrorResponse


@pytest.mark.unit
class TestErrorDetail:
    """Tests for the ErrorDetail schema."""
    
    def test_error_detail_required_fields(self):
        """Test that ErrorDetail requires the msg field."""
        # Create with required fields
        error_detail = ErrorDetail(msg="Error message")
        
        # Verify fields
        assert error_detail.msg == "Error message"
        assert error_detail.loc is None
        assert error_detail.type is None
    
    def test_error_detail_all_fields(self):
        """Test that ErrorDetail accepts all fields."""
        # Create with all fields
        error_detail = ErrorDetail(
            loc=["body", "username"],
            msg="Field required",
            type="value_error.missing"
        )
        
        # Verify fields
        assert error_detail.loc == ["body", "username"]
        assert error_detail.msg == "Field required"
        assert error_detail.type == "value_error.missing"
    
    def test_error_detail_missing_required(self):
        """Test that ErrorDetail raises ValidationError when msg is missing."""
        # Try to create without required fields
        with pytest.raises(ValidationError) as exc_info:
            ErrorDetail()
        
        # Verify the error
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("msg",)
        assert "field required" in errors[0]["msg"]
    
    def test_error_detail_serialization(self):
        """Test that ErrorDetail can be serialized to JSON."""
        # Create an instance
        error_detail = ErrorDetail(
            loc=["body", "username"],
            msg="Field required",
            type="value_error.missing"
        )
        
        # Serialize to JSON
        json_data = error_detail.model_dump_json()
        data = json.loads(json_data)
        
        # Verify serialized data
        assert data["loc"] == ["body", "username"]
        assert data["msg"] == "Field required"
        assert data["type"] == "value_error.missing"
    
    def test_error_detail_deserialization(self):
        """Test that ErrorDetail can be deserialized from JSON."""
        # Create JSON data
        json_data = {
            "loc": ["body", "username"],
            "msg": "Field required",
            "type": "value_error.missing"
        }
        
        # Deserialize from JSON
        error_detail = ErrorDetail.model_validate(json_data)
        
        # Verify deserialized instance
        assert error_detail.loc == ["body", "username"]
        assert error_detail.msg == "Field required"
        assert error_detail.type == "value_error.missing"


@pytest.mark.unit
class TestErrorResponse:
    """Tests for the ErrorResponse schema."""
    
    def test_error_response_required_fields(self):
        """Test that ErrorResponse requires error_code and message fields."""
        # Create with required fields
        error_response = ErrorResponse(
            error_code="validation_error",
            message="Validation error"
        )
        
        # Verify fields
        assert error_response.error_code == "validation_error"
        assert error_response.message == "Validation error"
        assert error_response.details is None
    
    def test_error_response_with_error_details(self):
        """Test that ErrorResponse accepts details as a list of ErrorDetail."""
        # Create error details
        error_details = [
            ErrorDetail(
                loc=["body", "username"],
                msg="Field required",
                type="value_error.missing"
            ),
            ErrorDetail(
                loc=["body", "password"],
                msg="Field required",
                type="value_error.missing"
            )
        ]
        
        # Create with error details
        error_response = ErrorResponse(
            error_code="validation_error",
            message="Validation error",
            details=error_details
        )
        
        # Verify fields
        assert error_response.error_code == "validation_error"
        assert error_response.message == "Validation error"
        assert len(error_response.details) == 2
        assert error_response.details[0].loc == ["body", "username"]
        assert error_response.details[1].loc == ["body", "password"]
    
    def test_error_response_with_dict_details(self):
        """Test that ErrorResponse accepts details as a dictionary."""
        # Create with dictionary details
        error_response = ErrorResponse(
            error_code="database_error",
            message="Database error",
            details={"error": "Connection timeout", "code": 1234}
        )
        
        # Verify fields
        assert error_response.error_code == "database_error"
        assert error_response.message == "Database error"
        assert error_response.details == {"error": "Connection timeout", "code": 1234}
    
    def test_error_response_missing_required(self):
        """Test that ErrorResponse raises ValidationError when required fields are missing."""
        # Try to create without required fields
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse()
        
        # Verify the error
        errors = exc_info.value.errors()
        assert len(errors) == 2
        field_names = [error["loc"][0] for error in errors]
        assert "error_code" in field_names
        assert "message" in field_names
    
    def test_error_response_serialization(self):
        """Test that ErrorResponse can be serialized to JSON."""
        # Create an instance
        error_response = ErrorResponse(
            error_code="validation_error",
            message="Validation error",
            details=[
                ErrorDetail(
                    loc=["body", "username"],
                    msg="Field required",
                    type="value_error.missing"
                )
            ]
        )
        
        # Serialize to JSON
        json_data = error_response.model_dump_json()
        data = json.loads(json_data)
        
        # Verify serialized data
        assert data["error_code"] == "validation_error"
        assert data["message"] == "Validation error"
        assert len(data["details"]) == 1
        assert data["details"][0]["loc"] == ["body", "username"]
        assert data["details"][0]["msg"] == "Field required"
        assert data["details"][0]["type"] == "value_error.missing"
    
    def test_error_response_deserialization(self):
        """Test that ErrorResponse can be deserialized from JSON."""
        # Create JSON data
        json_data = {
            "error_code": "validation_error",
            "message": "Validation error",
            "details": [
                {
                    "loc": ["body", "username"],
                    "msg": "Field required",
                    "type": "value_error.missing"
                }
            ]
        }
        
        # Deserialize from JSON
        error_response = ErrorResponse.model_validate(json_data)
        
        # Verify deserialized instance
        assert error_response.error_code == "validation_error"
        assert error_response.message == "Validation error"
        assert len(error_response.details) == 1
        assert error_response.details[0].loc == ["body", "username"]
        assert error_response.details[0].msg == "Field required"
        assert error_response.details[0].type == "value_error.missing"
    
    def test_error_response_example(self):
        """Test that the example in Config.schema_extra is valid."""
        # Get the example from Config.schema_extra
        example = ErrorResponse.model_config["schema_extra"]["example"]
        
        # Validate the example
        error_response = ErrorResponse.model_validate(example)
        
        # Verify the example is valid
        assert error_response.error_code == "validation_error"
        assert error_response.message == "Validation error"
        assert len(error_response.details) == 1
        assert error_response.details[0].loc == ["body", "username"]
        assert error_response.details[0].msg == "field required"
        assert error_response.details[0].type == "value_error.missing"