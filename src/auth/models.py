from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from db import Base
from werkzeug.security import generate_password_hash, check_password_hash

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    password_hash = Column(String, unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<User {}: {}>'.format(self.id, self.email)
    
    def get_dict(self):
        return dict(id=self.id, email=self.email)

class Session(Base):
    __tablename__ = 'session'

    id = Column(Integer, primary_key=True)
    refreshToken = Column(Text)
    refreshTokenExpirationDate = Column(DateTime)
    userId = Column(Integer, ForeignKey('user.id'))

    def __repr__(self):
        return '<Session {}: {} at {}>'.format(self.userId, self.refreshToken, self.refreshTokenExpirationDate)
    
    def get_dict(self):
        return dict(
            refreshToken=self.refreshToken,
            refreshTokenExpirationDate=self.refreshTokenExpirationDate,
            userId=self.userId
        )