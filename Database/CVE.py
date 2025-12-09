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

class CVE(Base):
    """CVE vulnerability record"""
    __tablename__ = "cves"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String(20), unique=True, index=True, nullable=False)  # e.g., CVE-2024-1234
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(String(10), nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    affected_products = Column(JSON, default=list)
    references = Column(JSON, default=list)
    published_date = Column(DateTime, index=True)
    modified_date = Column(DateTime, nullable=True)
    source = Column(String(50), index=True)  # "nvd", "nist_bulk_import", "mitre", etc.
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to POCs
    pocs = relationship("POC", back_populates="cve", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_cve_severity', 'severity'),
        Index('idx_cve_published', 'published_date'),
    )
