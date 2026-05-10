"""
BizOS Backend — Phase 4
FastAPI + SQLite → قابل للترقية لـ PostgreSQL
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os

# ══════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════
SECRET_KEY  = os.getenv("SECRET_KEY", "bizos-secret-change-in-production-2024")
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7   # 7 days

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bizos.db")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ══════════════════════════════════════
#  DATABASE SETUP
# ══════════════════════════════════════
engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

# ── Models ──────────────────────────
class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, index=True)
    name          = Column(String, nullable=False)
    email         = Column(String, unique=True, index=True, nullable=False)
    hashed_pw     = Column(String, nullable=False)
    plan          = Column(String, default="free")       # free | basic | pro | premium
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)

    biz      = relationship("Business",    back_populates="owner",    uselist=False)
    posts    = relationship("ScheduledPost", back_populates="owner")
    trans    = relationship("Transaction",   back_populates="owner")
    perf     = relationship("PostPerformance", back_populates="owner")
    comps    = relationship("Competitor",    back_populates="owner")


class Business(Base):
    __tablename__  = "businesses"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id"), unique=True)
    name           = Column(String, default="")
    product        = Column(String, default="")
    market         = Column(String, default="مصر")
    audience       = Column(String, default="")
    style          = Column(String, default="modern")
    api_key_hint   = Column(String, default="")   # last 6 chars only — security
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="biz")


class ScheduledPost(Base):
    __tablename__ = "scheduled_posts"
    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"))
    platform      = Column(String)
    text          = Column(Text)
    hashtags      = Column(String, default="")
    img_url       = Column(String, default="")
    scheduled_at  = Column(DateTime)
    published     = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="posts")


class Transaction(Base):
    __tablename__ = "transactions"
    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"))
    type          = Column(String)          # sale | expense
    amount        = Column(Float)
    product       = Column(String, default="")
    category      = Column(String, default="")
    method        = Column(String, default="")
    note          = Column(String, default="")
    created_at    = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="trans")


class PostPerformance(Base):
    __tablename__ = "post_performance"
    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"))
    platform      = Column(String)
    post_type     = Column(String)
    reach         = Column(Integer, default=0)
    likes         = Column(Integer, default=0)
    comments      = Column(Integer, default=0)
    shares        = Column(Integer, default=0)
    engagement    = Column(Float, default=0.0)
    sales_from    = Column(Integer, default=0)
    post_time     = Column(String, default="")
    note          = Column(String, default="")
    created_at    = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="perf")


class Competitor(Base):
    __tablename__ = "competitors"
    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"))
    name          = Column(String)
    url           = Column(String, default="")
    followers     = Column(String, default="")
    analysis      = Column(Text, default="")
    created_at    = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="comps")


# Create all tables
Base.metadata.create_all(bind=engine)


# ══════════════════════════════════════
#  PYDANTIC SCHEMAS
# ══════════════════════════════════════
class UserRegister(BaseModel):
    name:     str
    email:    str
    password: str

class UserLogin(BaseModel):
    email:    str
    password: str

class Token(BaseModel):
    access_token: str
    token_type:   str
    user:         dict

class BizUpdate(BaseModel):
    name:     Optional[str] = None
    product:  Optional[str] = None
    market:   Optional[str] = None
    audience: Optional[str] = None
    style:    Optional[str] = None

class PostCreate(BaseModel):
    platform:     str
    text:         str
    hashtags:     Optional[str] = ""
    img_url:      Optional[str] = ""
    scheduled_at: Optional[str] = None     # ISO string

class TransCreate(BaseModel):
    type:     str       # sale | expense
    amount:   float
    product:  Optional[str] = ""
    category: Optional[str] = ""
    method:   Optional[str] = ""
    note:     Optional[str] = ""

class PerfCreate(BaseModel):
    platform:   str
    post_type:  str
    reach:      int
    likes:      int
    comments:   int
    shares:     int
    sales_from: Optional[int] = 0
    post_time:  Optional[str] = ""
    note:       Optional[str] = ""

class CompCreate(BaseModel):
    name:      str
    url:       Optional[str] = ""
    followers: Optional[str] = ""
    analysis:  Optional[str] = ""


# ══════════════════════════════════════
#  AUTH HELPERS
# ══════════════════════════════════════
pwd_ctx  = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2   = OAuth2PasswordBearer(tokenUrl="/auth/login-form")

def hash_pw(pw: str)      -> str:  return pwd_ctx.hash(pw)
def verify_pw(plain, hashed):       return pwd_ctx.verify(plain, hashed)

def create_token(data: dict) -> str:
    exp  = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:    yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    cred_err = HTTPException(status_code=401, detail="جلسة منتهية — سجّل دخولك مجدداً",
                             headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None: raise cred_err
    except JWTError: raise cred_err
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active: raise cred_err
    return user


# ══════════════════════════════════════
#  APP
# ══════════════════════════════════════
app = FastAPI(title="BizOS API", version="1.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ───────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "app": "BizOS API v1.0"}


# ══════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════
@app.post("/auth/register", response_model=Token)
def register(data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email.lower()).first():
        raise HTTPException(400, "الإيميل ده مسجّل بالفعل")
    user = User(name=data.name, email=data.email.lower(), hashed_pw=hash_pw(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    # Create empty business profile
    biz = Business(user_id=user.id)
    db.add(biz); db.commit()

    token = create_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user.id, "name": user.name, "email": user.email, "plan": user.plan}}


@app.post("/auth/login", response_model=Token)
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower()).first()
    if not user or not verify_pw(data.password, user.hashed_pw):
        raise HTTPException(401, "الإيميل أو الباسورد غلط")
    token = create_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user.id, "name": user.name, "email": user.email, "plan": user.plan}}


# OAuth2 form login (for /docs)
@app.post("/auth/login-form")
def login_form(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.lower()).first()
    if not user or not verify_pw(form.password, user.hashed_pw):
        raise HTTPException(401, "بيانات غلط")
    return {"access_token": create_token({"sub": str(user.id)}), "token_type": "bearer"}


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "name": user.name, "email": user.email,
            "plan": user.plan, "created_at": user.created_at}


# ══════════════════════════════════════
#  BUSINESS ROUTES
# ══════════════════════════════════════
@app.get("/biz")
def get_biz(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    biz = db.query(Business).filter(Business.user_id == user.id).first()
    if not biz: raise HTTPException(404, "مفيش بيانات بيزنس")
    return biz

@app.put("/biz")
def update_biz(data: BizUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    biz = db.query(Business).filter(Business.user_id == user.id).first()
    if not biz:
        biz = Business(user_id=user.id); db.add(biz)
    for field, val in data.dict(exclude_none=True).items():
        setattr(biz, field, val)
    biz.updated_at = datetime.utcnow()
    db.commit(); db.refresh(biz)
    return biz


# ══════════════════════════════════════
#  SCHEDULED POSTS
# ══════════════════════════════════════
@app.get("/posts")
def get_posts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ScheduledPost).filter(ScheduledPost.user_id == user.id)\
             .order_by(ScheduledPost.scheduled_at).all()

@app.post("/posts", status_code=201)
def create_post(data: PostCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sched = datetime.fromisoformat(data.scheduled_at) if data.scheduled_at else datetime.utcnow()
    post  = ScheduledPost(user_id=user.id, platform=data.platform, text=data.text,
                          hashtags=data.hashtags, img_url=data.img_url, scheduled_at=sched)
    db.add(post); db.commit(); db.refresh(post)
    return post

@app.delete("/posts/{post_id}")
def delete_post(post_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(ScheduledPost).filter(ScheduledPost.id == post_id, ScheduledPost.user_id == user.id).first()
    if not post: raise HTTPException(404, "مش لاقي المنشور")
    db.delete(post); db.commit()
    return {"ok": True}

@app.patch("/posts/{post_id}/publish")
def mark_published(post_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(ScheduledPost).filter(ScheduledPost.id == post_id, ScheduledPost.user_id == user.id).first()
    if not post: raise HTTPException(404, "مش لاقي المنشور")
    post.published = True; db.commit()
    return {"ok": True}


# ══════════════════════════════════════
#  TRANSACTIONS (Finance)
# ══════════════════════════════════════
@app.get("/finance")
def get_finance(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    trans = db.query(Transaction).filter(Transaction.user_id == user.id)\
              .order_by(Transaction.created_at.desc()).all()
    sales   = sum(t.amount for t in trans if t.type == "sale")
    expense = sum(t.amount for t in trans if t.type == "expense")
    orders  = sum(1 for t in trans if t.type == "sale")
    return {
        "transactions": trans,
        "summary": {
            "total_sales":   sales,
            "total_expense": expense,
            "net_profit":    sales - expense,
            "orders":        orders,
            "margin":        round(((sales - expense) / sales * 100), 1) if sales > 0 else 0,
            "avg_order":     round(sales / orders, 0) if orders > 0 else 0
        }
    }

@app.post("/finance", status_code=201)
def add_transaction(data: TransCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = Transaction(user_id=user.id, **data.dict())
    db.add(t); db.commit(); db.refresh(t)
    return t

@app.delete("/finance/{t_id}")
def delete_transaction(t_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Transaction).filter(Transaction.id == t_id, Transaction.user_id == user.id).first()
    if not t: raise HTTPException(404, "مش لاقيها")
    db.delete(t); db.commit()
    return {"ok": True}


# ══════════════════════════════════════
#  POST PERFORMANCE (Analytics)
# ══════════════════════════════════════
@app.get("/analytics/performance")
def get_performance(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    perf = db.query(PostPerformance).filter(PostPerformance.user_id == user.id)\
              .order_by(PostPerformance.created_at.desc()).all()
    if not perf:
        return {"records": [], "summary": {}}
    avg_reach = sum(p.reach for p in perf) / len(perf)
    avg_eng   = sum(p.engagement for p in perf) / len(perf)
    best      = max(perf, key=lambda p: p.engagement)
    # Best posting time
    time_eng = {}
    for p in perf:
        if p.post_time:
            h = p.post_time.split(":")[0]
            time_eng[h] = time_eng.get(h, [])
            time_eng[h].append(p.engagement)
    best_time = max(time_eng, key=lambda h: sum(time_eng[h])/len(time_eng[h])) if time_eng else None
    return {
        "records": perf,
        "summary": {
            "avg_reach":   round(avg_reach),
            "avg_eng":     round(avg_eng, 1),
            "total_posts": len(perf),
            "best_time":   f"{best_time}:00" if best_time else "—",
            "best_type":   best.post_type
        }
    }

@app.post("/analytics/performance", status_code=201)
def add_performance(data: PerfCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    eng = (data.likes + data.comments + data.shares) / data.reach * 100 if data.reach > 0 else 0
    p   = PostPerformance(user_id=user.id, engagement=round(eng, 2), **data.dict())
    db.add(p); db.commit(); db.refresh(p)
    return p


# ══════════════════════════════════════
#  COMPETITORS
# ══════════════════════════════════════
@app.get("/competitors")
def get_competitors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Competitor).filter(Competitor.user_id == user.id).all()

@app.post("/competitors", status_code=201)
def add_competitor(data: CompCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    c = Competitor(user_id=user.id, **data.dict())
    db.add(c); db.commit(); db.refresh(c)
    return c

@app.delete("/competitors/{c_id}")
def delete_competitor(c_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Competitor).filter(Competitor.id == c_id, Competitor.user_id == user.id).first()
    if not c: raise HTTPException(404, "مش لاقيه")
    db.delete(c); db.commit()
    return {"ok": True}


# ══════════════════════════════════════
#  DASHBOARD SUMMARY
# ══════════════════════════════════════
@app.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    trans = db.query(Transaction).filter(Transaction.user_id == user.id).all()
    posts = db.query(ScheduledPost).filter(ScheduledPost.user_id == user.id,
                                           ScheduledPost.published == False).all()
    perf  = db.query(PostPerformance).filter(PostPerformance.user_id == user.id).all()
    biz   = db.query(Business).filter(Business.user_id == user.id).first()

    sales   = sum(t.amount for t in trans if t.type == "sale")
    expense = sum(t.amount for t in trans if t.type == "expense")
    orders  = sum(1 for t in trans if t.type == "sale")
    avg_eng = sum(p.engagement for p in perf) / len(perf) if perf else 0

    return {
        "user":            {"name": user.name, "plan": user.plan},
        "biz":             biz,
        "finance":         {"sales": sales, "expense": expense, "profit": sales - expense, "orders": orders},
        "pending_posts":   len(posts),
        "avg_engagement":  round(avg_eng, 1),
        "competitors":     db.query(Competitor).filter(Competitor.user_id == user.id).count()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
