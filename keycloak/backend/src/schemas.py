from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    id_token: str | None = None


class RefreshTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class ClientCredentialsResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class ProtectedResponse(BaseModel):
    message: str
    user: dict