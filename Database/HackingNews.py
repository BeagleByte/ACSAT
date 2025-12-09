from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text, JSON, Boolean, Index, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
from datetime import datetime
import uuid

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cve_user:password@localhost: 5432/cve_intelligence_db")

engine = create_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

class HackingNews(Base):
    """Hacking news from various sources"""
    __tablename__ = "hacking_news"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    content = Column(Text)
    source = Column(String(100), index=True)
    source_url = Column(String(500), unique=True, index=True)
    published_date = Column(DateTime, index=True)
    category = Column(String(50), index=True)
    relevance_score = Column(Integer, default=0)
    is_darknet = Column(Boolean, default=False, index=True)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)