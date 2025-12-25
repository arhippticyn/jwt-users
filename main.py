from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
import jwt 
from datetime import datetime, timedelta, timezone
from typing import Annotated
from models import CreateUser, LoginUser, UserResponse, Token, TokenData
from pwdlib import PasswordHash
from db import get_db, Users


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f8f4caa6cf63b88e8d3e7"
ALGORITM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
hash_password = PasswordHash.recommended()

def hashed_password(password):
    return hash_password.hash(password)

def verify_password(plain_password, hashed_password):
    return hash_password.verify(plain_password, hashed_password)

@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='invalid creditials')
    
    payload = {
        'sub': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    
    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)
    
    return Token(token=access_token, access_type='bearer')

@app.post('/register', response_model=UserResponse, status_code=201)
async def register(user: CreateUser, db: Session = Depends(get_db)):
    exiting_user = db.query(Users).filter((Users.username == user.username) | (Users.email == user.email)).first()
    
    if exiting_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User with this username or email already exists')
    
    hash_password = hashed_password(user.password)
    
    new_user = Users(username=user.username, email=user.email, password=hash_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user