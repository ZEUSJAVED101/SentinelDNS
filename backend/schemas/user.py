"""
User schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from database.enums.user_role import UserRole


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool