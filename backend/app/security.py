import os
import uuid
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from . import storage

SECRET = os.getenv('SECRET_KEY', 'development-only-change-me')
AUTH = HTTPBearer()
ALGORITHM = 'HS256'

def password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user):
    data = {'sub': user['id'], 'email': user['email'], 'exp': datetime.now(timezone.utc) + timedelta(hours=12)}
    return jwt.encode(data, SECRET, algorithm=ALGORITHM)

def current_user(creds: HTTPAuthorizationCredentials = Depends(AUTH)):
    try:
        data = jwt.decode(creds.credentials, SECRET, algorithms=[ALGORITHM])
        email = data['email']
        user = storage.one_user(email)
        if not user or user['id'] != data['sub']:
            raise ValueError('Invalid account')
        return user
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail='Please sign in again')

def new_id():
    return str(uuid.uuid4())
