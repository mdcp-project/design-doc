from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
import uvicorn
import secrets
import utils
import datetime
import jwt
import pika
import json

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
    send_email(user.email)
    return {"result_code": 200, "user_id": user.id, "user_email": user.email}

@app.get('/signin')
def signin(credentials: Credentials, db: Session = Depends(get_db)):
    at, rt, session = create_session(db, schemas.UserAuthenticate(email=credentials.email, password=credentials.password))
    if at is None:
        if rt is not None:
            raise HTTPException(403, detail=rt)
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

@app.post('/confirm')
def confirm(email: str = Query(...), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(403, detail="User with that email is not found")
    user.is_confirmed = True
    db.commit()
    return {"result_code": 200, "is_confirmed": True}
    

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(email=user.email)
    db_user.is_confirmed = False
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

    if not db_user.is_confirmed:
        return None, "User is not confirmed", None

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

def send_email(email: str):
    connection = pika.BlockingConnection(pika.ConnectionParameters(constants.RBMQ_ADDRESS))
    channel = connection.channel()
    channel.queue_declare("email")
    body = json.dumps({"email": email, "url": f"{constants.ENDPOINT}/confirm?email={email}"})
    channel.basic_publish("", routing_key="email", body=body)

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=5000)