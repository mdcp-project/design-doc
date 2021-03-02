from pydantic import BaseModel

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class UserAuthenticate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    token: str
    token_type: str

class Session(BaseModel):
    id: int
    refreshToken: str
    refreshTokenExpirationDate: int
    userId: int

    class Config:
        orm_mode = True