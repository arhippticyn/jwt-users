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
import requests
import os
from dotenv import load_dotenv
load_dotenv()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")


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

# @app.get('/auth/google/login')
# async def google_login():
#     return {
#         'url': 'https://accounts.google.com/o/oauth2/v2/auth'
#         "?client_id=GOOGLE_CLIENT_ID"
#         "&redirect_uri=http://localhost:8000/auth/google/callback"
#         "&response_type=code"
#         "&scope=openid email profile"
#     }

# @app.get('/auth/google/callback')
# async def google_callback(code: str, db: Session = Depends(get_db)):
#     google_token = '... получаешь через requests ...'

#     hashed_google_password = hashed_password()

#     google_user = {
#         'id': 12312,
#         'username': 'Google test',
#         'email': 'test@gmail.com',
#         'password': None
#     }

#     user = db.query(Users).filter(Users.google_id == google_user['id']).first()

#     if not user: 
#         user = Users(username=google_user['username'], email=google_user['email'], password=google_user['password'], google_id=google_user['id'])
#         db.add(user)
#         db.commit()
#         db.refresh(user)

#     payload = {
#         'sub': user.username,
#         'exp': datetime.now(timezone.utc) + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
#     }

#     access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

#     return {'access_token': access_token, 'type': 'bearer'}

@app.get('/auth/github/login')
async def github_login():
    return {
        'url': (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={GITHUB_CLIENT_ID}"
            f"&redirect_uri=http://localhost:8000/auth/github/callback"
            f"&scope=user:email"
        )
    }

@app.get('/auth/github/callback')
async def github_callback(code: str, db: Session = Depends(get_db)):
    token_response = requests.post(
    "https://github.com/login/oauth/access_token",
    headers={"Accept": "application/json"},
    data={
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
    },
    )
    access_token = token_response.json().get("access_token")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Github error token')
    
        
    user_response = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )

    github_user = user_response.json()

    emails_response = requests.get(
    "https://api.github.com/user/emails",
    headers={"Authorization": f"Bearer {access_token}"},
     )
    emails = emails_response.json()

    primary_email = next(
        (e["email"] for e in emails if e["primary"] and e["verified"]),
        None
    )

    github_id = github_user['id']
    github_username = github_user['login']

    user = db.query(Users).filter(Users.github_id == github_id).first()

    if not user:
        user = Users(username=github_username, email=primary_email, password=None, github_id=github_id)
        db.add(user)
        db.commit()
        db.refresh(user)

    payload = {
        'sub': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

    return {'access_token': access_token, 'type': 'bearer'}

