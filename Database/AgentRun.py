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

class AgentRun(Base):
    """Track agent execution history"""
    __tablename__ = "agent_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_name = Column(String(100), index=True)
    status = Column(String(20), index=True)  # "running", "success", "failed"
    items_collected = Column(Integer, default=0)
    items_processed = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    metadata = Column(JSON, default=dict)