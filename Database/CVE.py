from sqlalchemy import Column, String, DateTime, Integer, Text, JSON, Index
from Database.base import Base  # Import shared Base
import uuid
from datetime import datetime


class CVE(Base):
    """CVE vulnerability records"""
    __tablename__ = "cves"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255))
    description = Column(Text)
    severity = Column(String(20), index=True)
    cvss_score = Column(String(10))
    published_date = Column(DateTime, index=True)
    last_modified = Column(DateTime)
    source = Column(String(100), default="NIST")
    affected_products = Column(JSON, default=list)
    references = Column(JSON, default=list)
    status = Column(String(50), default="published", index=True)
    cve_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_cve_published', 'published_date'),
        Index('idx_cve_severity', 'severity'),
        Index('idx_cve_source', 'source'),
    )
