from pydantic import BaseModel, EmailStr

class LoginUser(BaseModel):
    username: str
    password: str
    
class CreateUser(BaseModel):
    username: str
    email: EmailStr
    password: str
    
class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    
    class Config:
        orm_mode: True
        
class Token(BaseModel):
    token: str
    access_type: str
    
class TokenData(BaseModel):
    username: str