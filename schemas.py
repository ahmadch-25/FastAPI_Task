from pydantic import BaseModel


class User(BaseModel):
    email: str
    password: str


class PostSchema(BaseModel):
    text: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str