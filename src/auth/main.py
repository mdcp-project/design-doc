from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import uvicorn
import secrets
import utils
import datetime
import jwt

from db import SessionLocal, engine
import models, schemas, utils, constants

from sqlalchemy.orm import Session

models.Base.metadata.create_all(bind=engine)

class Credentials(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    token: str

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get('/')
def read_root():
    return {"Hello": "World"}

@app.post('/signup')
def signup(credentials: Credentials, db: Session = Depends(get_db)):
    if get_user_by_email(db, credentials.email):
        raise HTTPException(402, detail="User with that email already exists")
    user = create_user(db, schemas.UserCreate(email=credentials.email, password=credentials.password))
    return {"result_code": 200, "user_id": user.id, "user_email": user.email}

@app.get('/signin')
def signin(credentials: Credentials, db: Session = Depends(get_db)):
    print(db, flush=True)
    at, rt, session = create_session(db, schemas.UserAuthenticate(email=credentials.email, password=credentials.password))
    if at is None:
        raise HTTPException(403, detail="Wrong email/password")
    return {"access_token": at, "refresh_token": rt, "result_code": 200}

@app.get('/validate')
def validate(token: Token, db: Session = Depends(get_db)):
    try:
        decoded_token = utils.decode_access_token(data=token.token)
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(403, detail="Token expired")
    except jwt.DecodeError as err:
        raise HTTPException(403, detail="Invalid token")

    session_id = decoded_token["session"]
    session = db.query(models.Session).get(session_id)
    if session is None:
        raise HTTPException(403, detail="Session not found")
    return {"result_code": 200, "is_valid": True}
    

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(email=user.email)
    db_user.set_password(user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def check_email_password(db: Session, user: schemas.UserAuthenticate):
    db_user = get_user_by_email(db, email=user.email)
    if db_user is None:
        return False
    return db_user.check_password(user.password)

def create_tokens(email, session: models.Session, time=datetime.datetime.utcnow()):
    refresh_token = secrets.token_hex(64)
    access_token = utils.create_access_token(data={'email': email, 'session': session.id})
    return access_token, refresh_token

def create_session(db: Session, user: schemas.UserAuthenticate):
    if not check_email_password(db, user):
        return None, None, None
    
    db_user = get_user_by_email(db, user.email)

    session = db.query(models.Session).filter(models.Session.userId == db_user.id).first()
    if session is None:
        session = models.Session(userId=db_user.id)
        db.add(session)
        db.commit()
        db.refresh(session)

    now = datetime.datetime.utcnow()
    access_token, refresh_token = create_tokens(db_user.email, session, now)
    session.refreshToken = refresh_token
    session.refreshTokenExpirationDate = now + datetime.timedelta(minutes = constants.TIMEDELTA)
    #db.add(session)
    db.commit()
    db.refresh(session)
    return access_token, refresh_token, session

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=5000)