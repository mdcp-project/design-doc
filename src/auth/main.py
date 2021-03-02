from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import secrets
import utils
import datetime

class Credentials(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    token: str

app = FastAPI()

@app.get('/')
def read_root():
    return {"Hello": "World"}

@app.post('/signup/credentials')
def signup(credentials: Credentials):
    pass

@app.get('/signin/credentials')
def signin(credentials: Credentials):
    pass

@app.get('/validate/token')
def validate(token: Token):
    pass

from sqlalchemy.orm import Session
import models, schemas

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(user=user.email)
    db_user.set_password(user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def check_email_password(db: Session, user: schemas.UserAuthenticate):
    db_user = get_user_by_email(db, email=user.email)
    if user is None:
        return False
    return db_user.check_password(user.password)

def create_tokens(email, session: models.Session, time=datetime.datetime.utcnow()):
    refresh_token = secrets.token_hex(64)
    access_token = utils.create_access_token({'email': email, 'session': session.id})
    return access_token, refresh_token

def create_session(db: Session, user: schemas.UserAuthenticate):
    if not check_email_password(db, user):
        return None
    
    db_user = get_user_by_email(db, user.email)
    session = models.Session(userId=db_user.id)

    db.add(session)
    db.commit()
    db.refresh(session)

    now = datetime.datetime.utcnow()
    access_token, refresh_token = create_tokens(db_user.email, session, now)
    session.refreshToken = refresh_token
    session.refreshTokenExpirationDate = now + 15
    db.add(session)
    db.commit()
    db.refresh(session)
    return access_token, refresh_token, session

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=5000)