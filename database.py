from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from db.base import Base
from db import models
from passlib.context import CryptContext
from fastapi import Depends
from sqlalchemy.orm import Session

SQLALCHEMY_DATABASE_URL = "sqlite:///./manager.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

with engine.connect() as conn:
    result = conn.execute(text("PRAGMA table_info(users);"))
    columns = [row[1] for row in result.fetchall()]
    if "raw_password" not in columns:
        conn.execute(text("ALTER TABLE users ADD COLUMN raw_password TEXT;"))
        print("Колонка raw_password додана")
    else:
        # print("Колонка raw_password вже існує")
        pass

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db: Session = Depends(get_db)
