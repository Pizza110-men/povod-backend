"""«Повод» — весь backend в одном файле.

Запуск на Render:
  Build Command:  pip install -r requirements.txt
  Start Command:  uvicorn main:app --host 0.0.0.0 --port $PORT

Переменные окружения:
  POVOD_BOT_TOKEN  — токен бота от @BotFather (обязательно)
  POVOD_SECRET_KEY — длинная случайная строка (обязательно)
"""
import enum
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

import jwt  # PyJWT
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey, Integer, String, Text,
    UniqueConstraint, create_engine, select,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, joinedload, mapped_column,
    relationship, sessionmaker,
)

# ═══════════════════ НАСТРОЙКИ ═══════════════════
SECRET_KEY = os.getenv("POVOD_SECRET_KEY", "dev-secret-change-me")
BOT_TOKEN = os.getenv("POVOD_BOT_TOKEN", "")
DATABASE_URL = os.getenv("POVOD_DATABASE_URL", "sqlite:///./povod.db")
CHAT_TTL_HOURS = int(os.getenv("POVOD_CHAT_TTL_HOURS", "48"))
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
INIT_DATA_MAX_AGE = 60 * 60 * 24

# ═══════════════════ БАЗА ДАННЫХ ═══════════════════
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ResponseStatus(str, enum.Enum):
    pending = "pending"
    accepted = "accepted"
    declined = "declined"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(80))
    age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    city: Mapped[str] = mapped_column(String(80), index=True, default="")
    bio: Mapped[str] = mapped_column(String(300), default="")
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Povod(Base):
    __tablename__ = "povods"
    id: Mapped[int] = mapped_column(primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(40), index=True)
    place: Mapped[str] = mapped_column(String(160))
    city: Mapped[str] = mapped_column(String(80), index=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    note: Mapped[str] = mapped_column(String(300), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    author: Mapped[User] = relationship()


class ResponseModel(Base):
    __tablename__ = "responses"
    __table_args__ = (UniqueConstraint("povod_id", "user_id", name="uq_response"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    povod_id: Mapped[int] = mapped_column(ForeignKey("povods.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[ResponseStatus] = mapped_column(Enum(ResponseStatus), default=ResponseStatus.pending)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    povod: Mapped[Povod] = relationship()
    user: Mapped[User] = relationship()


class Match(Base):
    __tablename__ = "matches"
    id: Mapped[int] = mapped_column(primary_key=True)
    povod_id: Mapped[int] = mapped_column(ForeignKey("povods.id"))
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    responder_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    povod: Mapped[Povod] = relationship()


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    match_id: Mapped[int] = mapped_column(ForeignKey("matches.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    target_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    povod_id: Mapped[int | None] = mapped_column(ForeignKey("povods.id"), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ═══════════════════ СХЕМЫ ═══════════════════
class TelegramAuth(BaseModel):
    init_data: str = Field(min_length=10)


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    age: int | None
    city: str
    bio: str


class ProfileUpdate(BaseModel):
    age: int | None = Field(default=None, ge=18, le=100)  # только 18+
    city: str | None = Field(default=None, min_length=1, max_length=80)
    bio: str | None = Field(default=None, max_length=300)


class AuthResult(BaseModel):
    access_token: str
    token_type: str = "bearer"
    needs_onboarding: bool
    user: UserPublic


class PovodCreate(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    category: str = Field(max_length=40)
    place: str = Field(min_length=2, max_length=160)
    city: str = Field(default="", max_length=80)
    starts_at: datetime
    note: str = Field(default="", max_length=300)


class PovodPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    category: str
    place: str
    city: str
    starts_at: datetime
    note: str
    author: UserPublic


class ResponsePublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: str
    user: UserPublic


class MatchPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    povod: PovodPublic
    expires_at: datetime


class MessageCreate(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class MessagePublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    sender_id: int
    text: str
    created_at: datetime


class ReportCreate(BaseModel):
    target_user_id: int
    povod_id: int | None = None
    reason: str = Field(min_length=3, max_length=500)


# ═══════════════════ АУТЕНТИФИКАЦИЯ ЧЕРЕЗ TELEGRAM ═══════════════════
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/telegram")


def verify_telegram_init_data(init_data: str) -> dict:
    """Проверяем подпись данных, которые Telegram передал мини-аппу.
    Подделать её без токена бота невозможно."""
    if not BOT_TOKEN:
        raise HTTPException(500, "На сервере не задан POVOD_BOT_TOKEN")
    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = parsed.pop("hash", None)
    if not received_hash:
        raise HTTPException(401, "Некорректные данные Telegram (нет подписи)")
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, received_hash):
        raise HTTPException(401, "Подпись Telegram не совпадает")
    if time.time() - int(parsed.get("auth_date", "0")) > INIT_DATA_MAX_AGE:
        raise HTTPException(401, "Сессия устарела, переоткройте мини-апп")
    try:
        return json.loads(parsed["user"])
    except (KeyError, json.JSONDecodeError):
        raise HTTPException(401, "В данных Telegram нет пользователя")


def create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    cred_error = HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительный токен")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise cred_error
    user = db.get(User, user_id)
    if user is None or user.is_banned:
        raise cred_error
    return user


# ═══════════════════ ПРИЛОЖЕНИЕ ═══════════════════
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Повод API", version="0.2.0",
              description="Знакомства через конкретные приглашения.")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {"status": "ok"}


# ─────────── Вход и профиль ───────────
@app.post("/auth/telegram", response_model=AuthResult, tags=["auth"])
def telegram_login(data: TelegramAuth, db: Session = Depends(get_db)):
    tg_user = verify_telegram_init_data(data.init_data)
    user = db.scalar(select(User).where(User.telegram_id == tg_user["id"]))
    if user is None:
        user = User(telegram_id=tg_user["id"],
                    name=(tg_user.get("first_name") or "Без имени")[:80])
        db.add(user)
        db.commit()
        db.refresh(user)
    if user.is_banned:
        raise HTTPException(403, "Аккаунт заблокирован")
    return AuthResult(
        access_token=create_access_token(user.id),
        needs_onboarding=user.age is None or not user.city,
        user=user,
    )


@app.get("/auth/me", response_model=UserPublic, tags=["auth"])
def me(user: User = Depends(get_current_user)):
    return user


@app.patch("/auth/me", response_model=UserPublic, tags=["auth"])
def update_profile(data: ProfileUpdate, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    if data.age is not None:
        user.age = data.age
    if data.city is not None:
        user.city = data.city.strip()
    if data.bio is not None:
        user.bio = data.bio.strip()
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/report", status_code=201, tags=["auth"])
def report(data: ReportCreate, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    """Жалобы — обязательный механизм безопасности для дейтинга."""
    if data.target_user_id == user.id:
        raise HTTPException(400, "Нельзя пожаловаться на себя")
    db.add(Report(reporter_id=user.id, target_user_id=data.target_user_id,
                  povod_id=data.povod_id, reason=data.reason))
    db.commit()
    return {"status": "ok", "detail": "Жалоба отправлена на модерацию"}


# ─────────── Поводы ───────────
@app.post("/povods", response_model=PovodPublic, status_code=201, tags=["povods"])
def create_povod(data: PovodCreate, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    if user.age is None or not user.city:
        raise HTTPException(400, "Сначала заполните профиль: возраст и город")
    starts = data.starts_at if data.starts_at.tzinfo else data.starts_at.replace(tzinfo=timezone.utc)
    if starts <= utcnow():
        raise HTTPException(400, "Время встречи должно быть в будущем")
    payload = data.model_dump()
    payload["starts_at"] = starts
    if not payload["city"]:
        payload["city"] = user.city
    povod = Povod(author_id=user.id, **payload)
    db.add(povod)
    db.commit()
    db.refresh(povod)
    return povod


@app.get("/povods/feed", response_model=list[PovodPublic], tags=["povods"])
def feed(city: str | None = None, category: str | None = None, limit: int = 20,
         user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    responded = select(ResponseModel.povod_id).where(ResponseModel.user_id == user.id)
    q = (select(Povod).options(joinedload(Povod.author))
         .where(Povod.is_active.is_(True), Povod.starts_at > utcnow(),
                Povod.author_id != user.id, Povod.city == (city or user.city),
                Povod.id.not_in(responded))
         .order_by(Povod.starts_at).limit(min(limit, 50)))
    if category:
        q = q.where(Povod.category == category)
    return db.scalars(q).all()


@app.get("/povods/matches", response_model=list[MatchPublic], tags=["povods"])
def my_matches(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = (select(Match).options(joinedload(Match.povod).joinedload(Povod.author))
         .where(((Match.author_id == user.id) | (Match.responder_id == user.id)),
                Match.expires_at > utcnow())
         .order_by(Match.created_at.desc()))
    return db.scalars(q).all()


@app.post("/povods/{povod_id}/respond", status_code=201, tags=["povods"])
def respond(povod_id: int, user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    if user.age is None or not user.city:
        raise HTTPException(400, "Сначала заполните профиль: возраст и город")
    povod = db.get(Povod, povod_id)
    if not povod or not povod.is_active:
        raise HTTPException(404, "Повод не найден или уже неактивен")
    if povod.author_id == user.id:
        raise HTTPException(400, "Нельзя откликнуться на свой повод")
    dup = db.scalar(select(ResponseModel).where(
        ResponseModel.povod_id == povod_id, ResponseModel.user_id == user.id))
    if dup:
        raise HTTPException(409, "Вы уже откликнулись на этот повод")
    db.add(ResponseModel(povod_id=povod_id, user_id=user.id))
    db.commit()
    return {"status": "ok", "detail": "Отклик отправлен"}


@app.get("/povods/{povod_id}/responses", response_model=list[ResponsePublic], tags=["povods"])
def list_responses(povod_id: int, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    povod = db.get(Povod, povod_id)
    if not povod:
        raise HTTPException(404, "Повод не найден")
    if povod.author_id != user.id:
        raise HTTPException(403, "Отклики видит только автор повода")
    q = (select(ResponseModel).options(joinedload(ResponseModel.user))
         .where(ResponseModel.povod_id == povod_id,
                ResponseModel.status == ResponseStatus.pending))
    return db.scalars(q).all()


@app.post("/povods/responses/{response_id}/accept", response_model=MatchPublic, tags=["povods"])
def accept_response(response_id: int, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    resp = db.get(ResponseModel, response_id)
    if not resp:
        raise HTTPException(404, "Отклик не найден")
    povod = db.get(Povod, resp.povod_id)
    if povod.author_id != user.id:
        raise HTTPException(403, "Принять отклик может только автор повода")
    if resp.status != ResponseStatus.pending:
        raise HTTPException(409, "Отклик уже обработан")
    resp.status = ResponseStatus.accepted
    povod.is_active = False
    match = Match(povod_id=povod.id, author_id=user.id, responder_id=resp.user_id,
                  expires_at=utcnow() + timedelta(hours=CHAT_TTL_HOURS))
    db.add(match)
    for o in db.scalars(select(ResponseModel).where(
            ResponseModel.povod_id == povod.id,
            ResponseModel.status == ResponseStatus.pending,
            ResponseModel.id != resp.id)):
        o.status = ResponseStatus.declined
    db.commit()
    db.refresh(match)
    return match


# ─────────── Чат ───────────
def _get_match_for(user_id: int, match_id: int, db: Session) -> Match:
    match = db.get(Match, match_id)
    if not match or user_id not in (match.author_id, match.responder_id):
        raise HTTPException(404, "Чат не найден")
    if match.expires_at <= utcnow():
        raise HTTPException(410, "Чат истёк: 48 часов на согласование прошли")
    return match


@app.get("/matches/{match_id}/messages", response_model=list[MessagePublic], tags=["chat"])
def history(match_id: int, user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    _get_match_for(user.id, match_id, db)
    q = (select(Message).where(Message.match_id == match_id)
         .order_by(Message.created_at).limit(500))
    return db.scalars(q).all()


@app.post("/matches/{match_id}/messages", response_model=MessagePublic,
          status_code=201, tags=["chat"])
def send(match_id: int, data: MessageCreate, user: User = Depends(get_current_user),
         db: Session = Depends(get_db)):
    _get_match_for(user.id, match_id, db)
    msg = Message(match_id=match_id, sender_id=user.id, text=data.text)
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return msg


# WebSocket для реального времени (мини-апп также умеет опрашивать REST раз в 3 сек)
class ConnectionManager:
    def __init__(self):
        self.rooms: dict[int, list[WebSocket]] = {}

    async def connect(self, match_id: int, ws: WebSocket):
        await ws.accept()
        self.rooms.setdefault(match_id, []).append(ws)

    def disconnect(self, match_id: int, ws: WebSocket):
        room = self.rooms.get(match_id, [])
        if ws in room:
            room.remove(ws)

    async def broadcast(self, match_id: int, payload: dict):
        for ws in self.rooms.get(match_id, []):
            await ws.send_json(payload)


manager = ConnectionManager()


@app.websocket("/matches/{match_id}/ws")
async def chat_ws(ws: WebSocket, match_id: int, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        await ws.close(code=4401)
        return
    db = SessionLocal()
    try:
        match = db.get(Match, match_id)
        if (not match or user_id not in (match.author_id, match.responder_id)
                or match.expires_at <= utcnow()):
            await ws.close(code=4404)
            return
        await manager.connect(match_id, ws)
        try:
            while True:
                text = (await ws.receive_text()).strip()
                if not text or len(text) > 2000:
                    continue
                if match.expires_at <= utcnow():
                    await ws.send_json({"type": "expired"})
                    break
                msg = Message(match_id=match_id, sender_id=user_id, text=text)
                db.add(msg)
                db.commit()
                await manager.broadcast(match_id, {
                    "type": "message", "id": msg.id, "sender_id": user_id,
                    "text": text, "created_at": msg.created_at.isoformat(),
                })
        except WebSocketDisconnect:
            pass
        finally:
            manager.disconnect(match_id, ws)
    finally:
        db.close()
