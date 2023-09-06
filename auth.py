from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from schemas import User
import cachetools
import hashlib



class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str = None



def get_user(db, token: str):
    from main import cache
    if token in db:
        email = db[token]
        user_dict = cache[email]
        return User(email=user_dict['email'], password=user_dict['password'])
    else:
        return None


def authenticate_user(token: str ):
    from main import token_cache
    user = get_user(token_cache, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

