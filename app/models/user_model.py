from datetime import datetime

class User:
    def __init__(self, email, password, full_name, role="user", phone=None):
        self.email = email
        self.password = password
        self.full_name = full_name
        self.role = role
        self.phone = phone
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.is_active = True
        self.last_login = None
    
    def to_dict(self):
        return {
            "email": self.email,
            "password": self.password,
            "full_name": self.full_name,
            "role": self.role,
            "phone": self.phone,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
            "last_login": self.last_login
        }


# Request DTOs
class RegisterRequest:
    schema = {
        "type": "object",
        "required": ["email", "password", "full_name"],
        "properties": {
            "email": {"type": "string", "example": "user@example.com"},
            "password": {"type": "string", "example": "password123"},
            "full_name": {"type": "string", "example": "John Doe"},
            "role": {"type": "string", "example": "user"},
            "phone": {"type": "string", "example": "1234567890"}
        }
    }


class LoginRequest:
    schema = {
        "type": "object",
        "required": ["email", "password"],
        "properties": {
            "email": {"type": "string", "example": "user@example.com"},
            "password": {"type": "string", "example": "password123"}
        }
    }


class UpdateProfileRequest:
    schema = {
        "type": "object",
        "properties": {
            "full_name": {"type": "string", "example": "Jane Doe"},
            "phone": {"type": "string", "example": "9876543210"}
        }
    }


class ChangePasswordRequest:
    schema = {
        "type": "object",
        "required": ["old_password", "new_password"],
        "properties": {
            "old_password": {"type": "string", "example": "oldpass123"},
            "new_password": {"type": "string", "example": "newpass123"}
        }
    }


# Response DTOs
class SuccessResponse:
    schema = {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "example": True},
            "message": {"type": "string", "example": "Success"},
            "data": {"type": "object"}
        }
    }


class ErrorResponse:
    schema = {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "example": False},
            "error": {"type": "string", "example": "Error message"}
        }
    }