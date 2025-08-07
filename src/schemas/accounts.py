from pydantic import BaseModel, EmailStr, constr, field_validator

from database.validators.accounts import validate_email, validate_password_strength


class UserRegistrationRequestBase(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)

    @field_validator("password")
    @classmethod
    def password_validator(cls, v: str) -> str:
        return validate_password_strength(v)


class UserRegistrationResponseBase(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestBase(BaseModel):
    email: EmailStr
    token: constr(min_length=64)


class UserPasswordResetRequestBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)


class UserPasswordResetCompletion(UserPasswordResetRequestBase):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def password_validator(cls, v: str) -> str:
        return validate_password_strength(v)

    class Config:
        from_attributes = True


class UserLoginRequestBase(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class RefreshTokenRequestBase(BaseModel):
    refresh_token: constr(min_length=64)
