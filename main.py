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
password_hash = PasswordHash.recommended()

def hashed_password(password):
    return password_hash.hash(password)

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


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
    
    return {
    "access_token": access_token,
    "token_type": "bearer"
}

@app.post('/register', response_model=UserResponse, status_code=201)
async def register(user: CreateUser, db: Session = Depends(get_db)):
    exiting_user = db.query(Users).filter((Users.username == user.username) | (Users.email == user.email)).first()
    
    if exiting_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User with this username or email already exists')
    
    new_hash_password = hashed_password(user.password)
    
    new_user = Users(username=user.username, email=user.email, password=new_hash_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Users:
    creditials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},)
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITM])
        username: str | None = payload.get('sub')
        
        if username is None:
            raise creditials_exception
        
    
    except jwt.InvalidTokenError:
        raise creditials_exception
    
    user = db.query(Users).filter(Users.username == username).first()
    
    if user is None:
        raise creditials_exception
    
    return user

@app.get('/user', response_model=UserResponse)
def read_user(user: Users = Depends(get_current_user)):
    return user