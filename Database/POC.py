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

class POC(Base):
    """
    Proof of Concept / Exploit information for CVEs.

    Stores links and details about publicly available POCs, exploits, and payloads.
    """
    __tablename__ = "pocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign key to CVE
    cve_id = Column(String(20), ForeignKey("cves.cve_id"), index=True, nullable=False)
    cve = relationship("CVE", back_populates="pocs")

    # POC status
    found = Column(Boolean, default=False, index=True)  # True if POC exists, False if not found

    # POC details
    title = Column(String(255))  # POC title/name
    description = Column(Text)  # Brief description of the POC
    url = Column(String(500), unique=True, index=True)  # Direct link to POC
    source = Column(String(100), index=True)  # Where we found it:  "github", "exploit-db", "packetstorm", etc.

    # POC characteristics
    poc_type = Column(String(50), index=True)  # "exploit", "metasploit", "script", "poc", "tool", etc.
    language = Column(String(50))  # Python, JavaScript, Bash, Java, etc.

    # Metadata
    verified = Column(Boolean, default=False)  # Whether we've manually verified it works
    stars = Column(Integer, default=0)  # GitHub stars (if from GitHub)
    forks = Column(Integer, default=0)  # GitHub forks
    watchers = Column(Integer, default=0)  # GitHub watchers

    # Tracking
    found_at = Column(DateTime, default=datetime.utcnow, index=True)  # When we found this POC
    last_verified = Column(DateTime, nullable=True)  # Last time verified

    metadata = Column(JSON, default=dict)  # Extra data (tags, author, etc.)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_poc_found', 'found'),
        Index('idx_poc_source', 'source'),
        Index('idx_poc_cve_found', 'cve_id', 'found'),
    )
