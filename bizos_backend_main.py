"""
BizOS Backend — v2 Clean
Works with Python 3.11+ and Pydantic v2
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional, List
import os

# ── Config ──────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", "bizos-dev-secret-change-in-production")
ALGORITHM   = "HS256"
TOKEN_EXP   = 60 * 24 * 7   # 7 days in minutes

DATABASE_URL     = os.getenv("DATABASE_URL", "sqlite:///./bizos.db")
ALLOWED_ORIGINS  = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ── Database ─────────────────────────────────────────
engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

# ── DB Models ────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(100), nullable=False)
    email      = Column(String(200), unique=True, index=True, nullable=False)
    hashed_pw  = Column(String(200), nullable=False)
    plan       = Column(String(20), default="free")
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    transactions = relationship("Transaction", back_populates="owner", cascade="all, delete")
    posts        = relationship("ScheduledPost", back_populates="owner", cascade="all, delete")
    performance  = relationship("PostPerformance", back_populates="owner", cascade="all, delete")
    competitors  = relationship("Competitor", back_populates="owner", cascade="all, delete")
    biz          = relationship("Business", back_populates="owner", uselist=False, cascade="all, delete")


class Business(Base):
    __tablename__ = "businesses"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), unique=True)
    name       = Column(String(200), default="")
    product    = Column(String(200), default="")
    market     = Column(String(100), default="مصر")
    audience   = Column(String(200), default="")
    style      = Column(String(100), default="modern")
    updated_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="biz")


class Transaction(Base):
    __tablename__ = "transactions"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    type       = Column(String(20))
    amount     = Column(Float)
    product    = Column(String(200), default="")
    category   = Column(String(100), default="")
    method     = Column(String(100), default="")
    note       = Column(String(500), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="transactions")


class ScheduledPost(Base):
    __tablename__ = "scheduled_posts"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"))
    platform     = Column(String(50))
    text         = Column(Text)
    hashtags     = Column(String(500), default="")
    img_url      = Column(String(500), default="")
    scheduled_at = Column(DateTime)
    published    = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="posts")


class PostPerformance(Base):
    __tablename__ = "post_performance"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    platform   = Column(String(50))
    post_type  = Column(String(50))
    reach      = Column(Integer, default=0)
    likes      = Column(Integer, default=0)
    comments   = Column(Integer, default=0)
    shares     = Column(Integer, default=0)
    engagement = Column(Float, default=0.0)
    sales_from = Column(Integer, default=0)
    post_time  = Column(String(10), default="")
    note       = Column(String(500), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="performance")


class Competitor(Base):
    __tablename__ = "competitors"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    name       = Column(String(200))
    url        = Column(String(500), default="")
    followers  = Column(String(100), default="")
    analysis   = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="competitors")


# Create tables
Base.metadata.create_all(bind=engine)


# ── Pydantic Schemas (v2 compatible) ─────────────────
class UserRegisterIn(BaseModel):
    name:     str
    email:    str
    password: str

class UserLoginIn(BaseModel):
    email:    str
    password: str

class BizUpdateIn(BaseModel):
    name:     Optional[str] = None
    product:  Optional[str] = None
    market:   Optional[str] = None
    audience: Optional[str] = None
    style:    Optional[str] = None

class PostCreateIn(BaseModel):
    platform:     str
    text:         str
    hashtags:     Optional[str] = ""
    img_url:      Optional[str] = ""
    scheduled_at: Optional[str] = None

class TransactionIn(BaseModel):
    type:     str
    amount:   float
    product:  Optional[str] = ""
    category: Optional[str] = ""
    method:   Optional[str] = ""
    note:     Optional[str] = ""

class PerformanceIn(BaseModel):
    platform:   str
    post_type:  str
    reach:      int
    likes:      int
    comments:   int
    shares:     int
    sales_from: Optional[int] = 0
    post_time:  Optional[str] = ""
    note:       Optional[str] = ""

class CompetitorIn(BaseModel):
    name:      str
    url:       Optional[str] = ""
    followers: Optional[str] = ""
    analysis:  Optional[str] = ""


# ── Auth helpers ─────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_pw(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_pw(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_token(user_id: int) -> str:
    exp  = datetime.utcnow() + timedelta(minutes=TOKEN_EXP)
    data = {"sub": str(user_id), "exp": exp}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    err = HTTPException(status_code=401, detail="جلسة منتهية — سجّل دخولك مجدداً")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        if not uid:
            raise err
    except JWTError:
        raise err
    user = db.query(User).filter(User.id == int(uid), User.is_active == True).first()
    if not user:
        raise err
    return user

def user_dict(u: User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "plan": u.plan,
            "created_at": str(u.created_at)}

def biz_dict(b: Business) -> dict:
    if not b:
        return {}
    return {"name": b.name, "product": b.product, "market": b.market,
            "audience": b.audience, "style": b.style}


# ── App ──────────────────────────────────────────────
app = FastAPI(title="BizOS API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ───────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "app": "BizOS API v2.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "time": str(datetime.utcnow())}


# ── Auth ─────────────────────────────────────────────
@app.post("/auth/register")
def register(data: UserRegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email.lower()).first():
        raise HTTPException(400, "الإيميل ده مسجّل بالفعل")
    user = User(name=data.name, email=data.email.lower(), hashed_pw=hash_pw(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    # Create business profile
    biz = Business(user_id=user.id)
    db.add(biz)
    db.commit()
    return {"access_token": create_token(user.id), "token_type": "bearer", "user": user_dict(user)}


@app.post("/auth/login")
def login(data: UserLoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower()).first()
    if not user or not verify_pw(data.password, user.hashed_pw):
        raise HTTPException(401, "الإيميل أو الباسورد غلط")
    return {"access_token": create_token(user.id), "token_type": "bearer", "user": user_dict(user)}


@app.post("/auth/login")
def login(data: UserLoginIn, db: Session = Depends(get_db)):
    biz = db.query(Business).filter(Business.user_id == user.id).first()
    if not biz:
        biz = Business(user_id=user.id)
        db.add(biz)
    for field, val in data.model_dump(exclude_none=True).items():
        setattr(biz, field, val)
    biz.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(biz)
    return biz_dict(biz)


# ── Finance ──────────────────────────────────────────
@app.get("/finance")
def get_finance(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    trans   = db.query(Transaction).filter(Transaction.user_id == user.id)\
                .order_by(Transaction.created_at.desc()).all()
    sales   = sum(t.amount for t in trans if t.type == "sale")
    expense = sum(t.amount for t in trans if t.type == "expense")
    orders  = sum(1 for t in trans if t.type == "sale")
    return {
        "transactions": [
            {"id": t.id, "type": t.type, "amount": t.amount, "product": t.product,
             "category": t.category, "method": t.method, "note": t.note,
             "date": str(t.created_at)} for t in trans
        ],
        "summary": {
            "total_sales":   sales,
            "total_expense": expense,
            "net_profit":    round(sales - expense, 2),
            "orders":        orders,
            "margin":        round(((sales - expense) / sales * 100), 1) if sales > 0 else 0,
            "avg_order":     round(sales / orders, 0) if orders > 0 else 0
        }
    }


@app.post("/finance", status_code=201)
def add_transaction(data: TransactionIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = Transaction(user_id=user.id, **data.model_dump())
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id, "type": t.type, "amount": t.amount, "created_at": str(t.created_at)}


@app.delete("/finance/{t_id}")
def delete_transaction(t_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t = db.query(Transaction).filter(Transaction.id == t_id, Transaction.user_id == user.id).first()
    if not t:
        raise HTTPException(404, "مش لاقيها")
    db.delete(t)
    db.commit()
    return {"ok": True}


# ── Posts ────────────────────────────────────────────
@app.get("/posts")
def get_posts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    posts = db.query(ScheduledPost).filter(ScheduledPost.user_id == user.id)\
               .order_by(ScheduledPost.scheduled_at).all()
    return [{"id": p.id, "platform": p.platform, "text": p.text,
             "hashtags": p.hashtags, "img_url": p.img_url,
             "scheduled_at": str(p.scheduled_at), "published": p.published} for p in posts]


@app.post("/posts", status_code=201)
def create_post(data: PostCreateIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sched = datetime.fromisoformat(data.scheduled_at) if data.scheduled_at else datetime.utcnow()
    post  = ScheduledPost(user_id=user.id, platform=data.platform, text=data.text,
                          hashtags=data.hashtags or "", img_url=data.img_url or "",
                          scheduled_at=sched)
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"id": post.id, "platform": post.platform, "scheduled_at": str(post.scheduled_at)}


@app.delete("/posts/{post_id}")
def delete_post(post_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(ScheduledPost).filter(ScheduledPost.id == post_id,
                                          ScheduledPost.user_id == user.id).first()
    if not post:
        raise HTTPException(404, "مش لاقي المنشور")
    db.delete(post)
    db.commit()
    return {"ok": True}


# ── Analytics ────────────────────────────────────────
@app.get("/analytics/performance")
def get_performance(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    records = db.query(PostPerformance).filter(PostPerformance.user_id == user.id)\
                .order_by(PostPerformance.created_at.desc()).all()
    if not records:
        return {"records": [], "summary": {}}
    avg_reach = sum(r.reach for r in records) / len(records)
    avg_eng   = sum(r.engagement for r in records) / len(records)
    best      = max(records, key=lambda r: r.engagement)
    return {
        "records": [
            {"id": r.id, "platform": r.platform, "post_type": r.post_type,
             "reach": r.reach, "likes": r.likes, "comments": r.comments,
             "engagement": r.engagement, "post_time": r.post_time,
             "date": str(r.created_at)} for r in records
        ],
        "summary": {
            "avg_reach":   round(avg_reach),
            "avg_eng":     round(avg_eng, 1),
            "total_posts": len(records),
            "best_type":   best.post_type
        }
    }


@app.post("/analytics/performance", status_code=201)
def add_performance(data: PerformanceIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    eng = ((data.likes + data.comments + data.shares) / data.reach * 100) if data.reach > 0 else 0
    d   = data.model_dump()
    d.pop("likes"); d.pop("comments"); d.pop("shares")
    p = PostPerformance(user_id=user.id, engagement=round(eng, 2),
                        likes=data.likes, comments=data.comments, shares=data.shares, **d)
    db.add(p)
    db.commit()
    db.refresh(p)
    return {"id": p.id, "engagement": p.engagement}


# ── Competitors ──────────────────────────────────────
@app.get("/competitors")
def get_competitors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    comps = db.query(Competitor).filter(Competitor.user_id == user.id).all()
    return [{"id": c.id, "name": c.name, "url": c.url, "followers": c.followers,
             "date": str(c.created_at)} for c in comps]


@app.post("/competitors", status_code=201)
def add_competitor(data: CompetitorIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    c = Competitor(user_id=user.id, **data.model_dump())
    db.add(c)
    db.commit()
    db.refresh(c)
    return {"id": c.id, "name": c.name}


@app.delete("/competitors/{c_id}")
def delete_competitor(c_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Competitor).filter(Competitor.id == c_id, Competitor.user_id == user.id).first()
    if not c:
        raise HTTPException(404, "مش لاقيه")
    db.delete(c)
    db.commit()
    return {"ok": True}


# ── Dashboard ────────────────────────────────────────
@app.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    trans   = db.query(Transaction).filter(Transaction.user_id == user.id).all()
    posts   = db.query(ScheduledPost).filter(ScheduledPost.user_id == user.id,
                                             ScheduledPost.published == False).all()
    perf    = db.query(PostPerformance).filter(PostPerformance.user_id == user.id).all()
    biz     = db.query(Business).filter(Business.user_id == user.id).first()
    comps   = db.query(Competitor).filter(Competitor.user_id == user.id).count()

    sales   = sum(t.amount for t in trans if t.type == "sale")
    expense = sum(t.amount for t in trans if t.type == "expense")
    orders  = sum(1 for t in trans if t.type == "sale")
    avg_eng = sum(p.engagement for p in perf) / len(perf) if perf else 0

    return {
        "user":           {"name": user.name, "plan": user.plan},
        "biz":            biz_dict(biz),
        "finance":        {"sales": sales, "expense": expense,
                           "profit": round(sales - expense, 2), "orders": orders},
        "pending_posts":  len(posts),
        "avg_engagement": round(avg_eng, 1),
        "competitors":    comps
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
