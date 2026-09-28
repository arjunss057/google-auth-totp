from pydantic import BaseModel

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AuthenticatorAccountRequest(BaseModel):
    service_name: str
    account_name: str
    service_secret: str

class PasswordChangeAccount(BaseModel):
    account_id: int
    service_secret: str

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str
    accounts: list[PasswordChangeAccount]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
