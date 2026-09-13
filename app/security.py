from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from .config import JWT_SECRET, ACCESS_TOKEN_MINUTES
from .database import get_db
from .models import User
pwd=CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto'); bearer=HTTPBearer()
def hash_password(p): return pwd.hash(p)
def verify_password(p,h): return pwd.verify(p,h)
def token_for(user): return jwt.encode({'sub':str(user.id),'exp':datetime.now(timezone.utc)+timedelta(minutes=ACCESS_TOKEN_MINUTES)},JWT_SECRET,algorithm='HS256')
def current_user(creds: HTTPAuthorizationCredentials=Depends(bearer), db: Session=Depends(get_db)):
    try: uid=int(jwt.decode(creds.credentials,JWT_SECRET,algorithms=['HS256'])['sub'])
    except Exception: raise HTTPException(401,'Invalid authentication token')
    u=db.get(User,uid)
    if not u: raise HTTPException(401,'Unknown user')
    return u
