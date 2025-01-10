import datetime
import hashlib
import sqlite3
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()


class User(BaseModel):
    name: str
    email: EmailStr
    password: str

    def hash_password(self):
        return hashlib.sha256(self.password.encode()).hexdigest()


class LoginUser(BaseModel):
    email: EmailStr
    password: str

    def hash_password(self):
        return hashlib.sha256(self.password.encode()).hexdigest()


class EchoData(BaseModel):
    message: str


def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()


init_db()


def add_user_to_db(user: User):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (user.name, user.email, user.hash_password())
    )
    conn.commit()
    conn.close()


def get_user_by_email(email: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=credentials_exception)
        user = get_user_by_email(email)
        if user is None:
            raise HTTPException(status_code=credentials_exception)
        return user
    except jwt.JWTError:
        raise HTTPException(status_code=credentials_exception)


@app.post("/register")
async def register(user: User):
    existing_user = get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    add_user_to_db(user)
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(user: LoginUser):
    # existing_user: 1 - name, 2 - email, 3 - password
    existing_user = get_user_by_email(user.email)
    if not existing_user:
        raise HTTPException(status_code=400, detail="User not found")

    stored_password = existing_user[3]
    if stored_password != user.hash_password():
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": existing_user[2]}, expires_delta=access_token_expires
    )

    return {"message": "Login successful", "user": {"name": existing_user[1], "email": existing_user[2]},
            "access_token": access_token,
            "token_type": "bearer"}


@app.post("/echo")
async def echo(data: EchoData, current_user: dict = Depends(get_current_user)):
    return {"echo": data.message}
