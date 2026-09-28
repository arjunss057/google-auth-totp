from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv

from .database import Base, engine, get_db
from .models import User, AuthenticatorAccount
from .schemas import RegisterRequest, LoginRequest, AuthenticatorAccountRequest, PasswordChangeRequest, TokenResponse
from .auth import hash_password, verify_password, create_access_token, get_current_user

load_dotenv()
FRONT_END_ORIGIN = os.getenv("FRONT_END_ORIGIN")

app = FastAPI(
    title="Google Server",
    description="Authentication host and TOTP authenticator host"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_END_ORIGIN, ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {
        "service": "Google server",
        "status": "running"
    }

@app.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == request.username).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    user = User(
        username=request.username,
        password_hash=hash_password(request.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User created",
        "user_id": user.id
    }

@app.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == request.username).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token(user.id)
    return {
        "access_token": token,
        "token_type": "bearer"
    }

@app.get("/me")
def get_me(
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    return {
        "id": user.id,
        "username": user.username
    }

@app.get("/authenticator/accounts")
def list_authenticator_accounts(
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    accounts = db.query(AuthenticatorAccount).filter(AuthenticatorAccount.user_id == user_id).all()
    return [
        {
            "id": account.id,
            "service_name": account.service_name,
            "account_name": account.account_name,
            "service_secret": account.service_secret
        }
        for account in accounts
    ]

@app.post("/authenticator/accounts")
def add_authenticator_account(
    request: AuthenticatorAccountRequest,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    account = AuthenticatorAccount(
        user_id= user_id,
        service_name= request.service_name,
        account_name=request.account_name,
        service_secret=request.service_secret
    )

    db.add(account)
    db.commit()
    db.refresh(account)

    return {
        "id": account.id,
        "service_name": account.service_name,
        "account_name": account.account_name,
        "service_secret": account.service_secret
    }

@app.delete("/authenticator/accounts/{account_id}")
def delete_authenticator_account(
    account_id: int,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    account = db.query(AuthenticatorAccount).filter(AuthenticatorAccount.id == int(account_id), AuthenticatorAccount.user_id == user_id).first()

    if not account:
        raise HTTPException(
            status_code=404,
            detail="Authenticator account not found"
        )

    db.delete(account)
    db.commit()

    return {
        "message": "Authenticator account deleted"
    }

@app.post("/change-password")
def change_password(
    request: PasswordChangeRequest,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if not verify_password(request.old_password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Current password is incorrect"
        )

    accounts = db.query(AuthenticatorAccount).filter(AuthenticatorAccount.user_id == user_id).all()
    account_map = {account.id: account for account in accounts}
    supplied_ids = {item.account_id for item in request.accounts}
    existing_ids = set(account_map.keys())
    if supplied_ids != existing_ids:
        raise HTTPException(
            status_code=400,
            detail="Authenticator account list is incomplete or invalid"
        )
    try:
        user.password_hash = hash_password(request.new_password)
        for item in request.accounts:
            account = account_map[item.account_id]
            account.service_secret = item.service_secret
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Password change failed"
        )
    return {
        "message": "Password changed successfully"
    }
