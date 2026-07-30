"""
User schemas for SentinelDNS.
"""

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Schema used when registering a new user."""

    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    """Schema returned to clients."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    username: str
    email: EmailStr
    is_active: bool