from sqlalchemy import Column, Integer, String, DateTime, JSON
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    plan = Column(String, default="free")
    scans_used = Column(Integer, default=0)

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    url = Column(String)
    score = Column(Integer)
    details = Column(JSON)  
    created_at = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String)
    checkout_id = Column(String, unique=True)
    amount = Column(Integer)
    status = Column(String, default="pending")
