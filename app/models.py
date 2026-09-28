from sqlalchemy import Column, Integer, String, ForeignKey

from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)

class AuthenticatorAccount(Base):
    __tablename__ = "authenticator_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    service_name = Column(String, nullable=False)
    account_name = Column(String, nullable=False)
    service_secret = Column(String, nullable=False)
