from pathlib import Path
import hmac
import hashlib
import time
import re
import json
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Form, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from sqlalchemy import Column, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = "super-secret-change-this"
DATABASE_URL = f"sqlite:///{BASE_DIR / 'shopkart.db'}"
PRODUCTS_FILE = BASE_DIR / "products.json"
COOKIE_NAME = "shopkart_session"
SESSION_MAX_AGE = 7 * 24 * 60 * 60

app = FastAPI()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SQLAlchemy setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    bio = Column(Text, default="")
    password_hash = Column(String(255), nullable=False)
    joined_at = Column(Integer, nullable=False)


class UserLog(Base):
    __tablename__ = "user_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), index=True)
    event = Column(String(50))
    timestamp = Column(Integer)
    client_ip = Column(String(50))
    details = Column(Text)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def normalize_username(username: str) -> str:
    return username.strip().lower()


def create_session_token(username: str) -> str:
    timestamp = str(int(time.time()))
    value = f"{username}|{timestamp}"
    signature = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}|{signature}"


def decode_session_token(token: str) -> Optional[str]:
    try:
        username, timestamp, signature = token.split("|")
        value = f"{username}|{timestamp}"
        expected = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if int(time.time()) - int(timestamp) > SESSION_MAX_AGE:
            return None
        return username
    except Exception:
        return None


def user_to_dict(user: User) -> Dict[str, Any]:
    return {
        "username": user.username,
        "name": user.name,
        "email": user.email,
        "bio": user.bio,
        "joined_at": user.joined_at,
    }


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == normalize_username(username)).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.strip().lower()).first()


def current_user(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    username = decode_session_token(token)
    if not username:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == normalize_username(username)).first()
        if not user:
            return None
        return user_to_dict(user)
    finally:
        db.close()


def render_template(request: Request, template_name: str, **context: Any):
    context["request"] = request
    context["user"] = current_user(request)
    return templates.TemplateResponse(template_name, context)


@app.on_event("startup")
async def startup() -> None:
    Base.metadata.create_all(bind=engine)
    # load products for in-memory search
    try:
        with open(PRODUCTS_FILE, "r", encoding="utf-8") as f:
            app.state.products = json.load(f)
    except Exception:
        app.state.products = []


@app.get("/")
async def root(request: Request):
    user = current_user(request)
    if user:
        return RedirectResponse(url="/deals", status_code=status.HTTP_303_SEE_OTHER)
    return render_template(request, "auth.html")


@app.get("/deals")
async def deals(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return render_template(request, "index.html", products=app.state.products)


@app.get("/api/search")
async def search(q: str = ""):
    query = q.strip().lower()
    if not query:
        return app.state.products

    return [
        product
        for product in app.state.products
        if query in product.get("title", "").lower()
        or query in product.get("keywords", "").lower()
    ]


@app.get("/login")
async def login_page(request: Request, message: str = ""):
    return render_template(request, "login.html", message=message)


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == normalize_username(username)).first()
        if not user or not verify_password(password, user.password_hash):
            return render_template(request, "login.html", message="Invalid username or password.")

        # log event
        log = UserLog(
            username=user.username,
            event="login",
            timestamp=int(time.time()),
            client_ip=(request.client.host if request.client else "unknown"),
            details=json.dumps({"success": True}),
        )
        db.add(log)
        db.commit()

        response = RedirectResponse(url="/deals", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            COOKIE_NAME,
            create_session_token(user.username),
            httponly=True,
            max_age=SESSION_MAX_AGE,
            samesite="lax",
        )
        return response
    finally:
        db.close()


@app.get("/signup")
async def signup_page(request: Request, message: str = ""):
    return render_template(request, "signup.html", message=message)


@app.post("/signup")
async def signup(
    request: Request,
    username: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    bio: str = Form(""),
):
    username = normalize_username(username)
    email = email.strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return render_template(request, "signup.html", message="Username may only contain letters, numbers, and underscores.")

    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            return render_template(request, "signup.html", message="That username is already taken.")
        if db.query(User).filter(User.email == email).first():
            return render_template(request, "signup.html", message="An account already exists with that email.")

        user_obj = User(
            username=username,
            name=name.strip() or username,
            email=email,
            bio=bio.strip(),
            password_hash=hash_password(password),
            joined_at=int(time.time()),
        )
        db.add(user_obj)
        db.commit()

        log = UserLog(
            username=username,
            event="signup",
            timestamp=int(time.time()),
            client_ip=(request.client.host if request.client else "unknown"),
            details=json.dumps({"email": email}),
        )
        db.add(log)
        db.commit()

        response = RedirectResponse(url="/deals", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            COOKIE_NAME,
            create_session_token(username),
            httponly=True,
            max_age=SESSION_MAX_AGE,
            samesite="lax",
        )
        return response
    finally:
        db.close()


@app.get("/profile")
async def profile_page(request: Request, message: str = ""):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return render_template(request, "profile.html", profile=user, message=message)


@app.post("/profile")
async def profile_update(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    bio: str = Form(""),
):
    current = current_user(request)
    if not current:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    email = email.strip().lower()
    db = SessionLocal()
    try:
        user_obj = db.query(User).filter(User.username == normalize_username(current["username"]) ).first()
        if not user_obj:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

        user_with_email = db.query(User).filter(User.email == email).first()
        if user_with_email and user_with_email.username != user_obj.username:
            return render_template(request, "profile.html", profile=current, message="This email is already used by another account.")

        user_obj.name = name.strip() or user_obj.username
        user_obj.email = email
        user_obj.bio = bio.strip()
        db.add(user_obj)
        db.commit()

        return RedirectResponse(url="/profile?message=Profile updated successfully.", status_code=status.HTTP_303_SEE_OTHER)
    finally:
        db.close()


@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response
