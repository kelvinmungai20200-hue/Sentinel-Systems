import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

# LOAD ENV VARIABLES
load_dotenv()

# DATABASE URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///sentinel.db"
)

# FIX RENDER POSTGRES URL
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

# DATABASE ENGINE
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

# SESSION
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# BASE MODEL
Base = declarative_base()