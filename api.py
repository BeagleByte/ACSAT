"""
FastAPI server for data access and dashboard backend.
"""
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from Database.database import init_db, get_db, CVE, HackingNews, AgentRun
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import logging
# Add these imports at the top
from Database.database import POC
logger = logging.getLogger(__name__)

app = FastAPI(title="CVE Intelligence API")

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Initialize database on startup
@app.on_event("startup")
async def startup():
    init_db()
    logger.info("Database initialized")


# ==================== Pydantic Models ====================

class CVEResponse(BaseModel):
    id: str
    cve_id: str
    title: str
    description: Optional[str]
    severity: str
    cvss_score: Optional[str]
    published_date: datetime
    source: str
    affected_products: list
    references: list

    class Config:
        from_attributes = True


class NewsResponse(BaseModel):
    id: str
    title: str
    content: Optional[str]
    source: str
    published_date: datetime
    category: str
    relevance_score: int
    is_darknet: bool

    class Config:
        from_attributes = True


class AgentRunResponse(BaseModel):
    id: str
    agent_name: str
    status: str
    items_collected: int
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ==================== POC Endpoints ====================

class POCResponse(BaseModel):
    id: str
    cve_id: str
    found: bool
    title: Optional[str]
    description: Optional[str]
    url: Optional[str]
    source: str
    poc_type: Optional[str]
    language: Optional[str]
    stars: int
    verified: bool
    found_at: datetime

    class Config:
        from_attributes = True


@app.get("/api/pocs/{cve_id}", response_model=List[POCResponse])
async def get_pocs_for_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get all POCs for a specific CVE"""
    pocs = db.query(POC).filter(POC.cve_id == cve_id).order_by(desc(POC.stars)).all()
    return pocs


@app.get("/api/pocs", response_model=List[POCResponse])
async def get_all_pocs(
        skip: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        source: Optional[str] = None,
        found: Optional[bool] = None,
        db: Session = Depends(get_db)
):
    """Get POCs with optional filtering"""
    query = db.query(POC)

    if source:
        query = query.filter(POC.source == source)

    if found is not None:
        query = query.filter(POC.found == found)

    pocs = query.order_by(desc(POC.found_at)).offset(skip).limit(limit).all()
    return pocs


@app.get("/api/pocs/stats/summary")
async def get_poc_stats(db: Session = Depends(get_db)):
    """Get POC statistics"""
    total_pocs = db.query(POC).count()
    cves_with_pocs = db.query(POC.cve_id).distinct().count()
    cves_without_pocs = db.query(CVE).filter(
        ~CVE.cve_id.in_(db.query(POC.cve_id).distinct())
    ).count()

    by_source = {}
    for source in db.query(POC.source).distinct():
        count = db.query(POC).filter(POC.source == source[0]).count()
        by_source[source[0]] = count

    return {
        "total_pocs": total_pocs,
        "cves_with_pocs": cves_with_pocs,
        "cves_without_pocs": cves_without_pocs,
        "by_source": by_source
    }

# ==================== CVE Endpoints ====================

@app.get("/api/cves", response_model=List[CVEResponse])
async def get_cves(
        skip: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        severity: Optional[str] = None,
        search: Optional[str] = None,
        db: Session = Depends(get_db)
):
    """Get CVEs with optional filtering and search"""
    query = db.query(CVE)

    if severity:
        query = query.filter(CVE.severity == severity.upper())

    if search:
        query = query.filter(
            or_(
                CVE.cve_id.ilike(f"%{search}%"),
                CVE.title.ilike(f"%{search}%"),
                CVE.description.ilike(f"%{search}%")
            )
        )

    cves = query.order_by(desc(CVE.published_date)).offset(skip).limit(limit).all()
    return cves


@app.get("/api/cves/{cve_id}", response_model=CVEResponse)
async def get_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get a specific CVE"""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@app.get("/api/cves/stats/summary")
async def get_cve_stats(db: Session = Depends(get_db)):
    """Get CVE statistics"""
    severities = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = db.query(CVE).filter(CVE.severity == sev).count()
        severities[sev] = count

    total = db.query(CVE).count()
    recent_24h = db.query(CVE).filter(
        CVE.published_date >= datetime.utcnow() - timedelta(days=1)
    ).count()

    return {
        "total_cves": total,
        "recent_24h": recent_24h,
        "by_severity": severities
    }


# ==================== News Endpoints ====================

@app.get("/api/news", response_model=List[NewsResponse])
async def get_news(
        skip: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        category: Optional[str] = None,
        source: Optional[str] = None,
        is_darknet: Optional[bool] = None,
        db: Session = Depends(get_db)
):
    """Get hacking news with filters"""
    query = db.query(HackingNews)

    if category:
        query = query.filter(HackingNews.category == category)

    if source:
        query = query.filter(HackingNews.source == source)

    if is_darknet is not None:
        query = query.filter(HackingNews.is_darknet == is_darknet)

    news = query.order_by(desc(HackingNews.published_date)).offset(skip).limit(limit).all()
    return news


@app.get("/api/news/stats/summary")
async def get_news_stats(db: Session = Depends(get_db)):
    """Get news statistics"""
    total = db.query(HackingNews).count()
    darknet = db.query(HackingNews).filter(HackingNews.is_darknet == True).count()

    categories = {}
    for item in db.query(HackingNews.category).distinct():
        cat = item[0]
        count = db.query(HackingNews).filter(HackingNews.category == cat).count()
        categories[cat] = count

    return {
        "total_news": total,
        "darknet_items": darknet,
        "by_category": categories
    }


# ==================== Agent Status Endpoints ====================

@app.get("/api/agents/runs", response_model=List[AgentRunResponse])
async def get_agent_runs(
        agent_name: Optional[str] = None,
        limit: int = Query(20, ge=1, le=100),
        db: Session = Depends(get_db)
):
    """Get agent execution history"""
    query = db.query(AgentRun)

    if agent_name:
        query = query.filter(AgentRun.agent_name == agent_name)

    runs = query.order_by(desc(AgentRun.started_at)).limit(limit).all()
    return runs


@app.get("/api/agents/status")
async def get_agent_status(db: Session = Depends(get_db)):
    """Get current agent status"""
    agents = ["cve_agent", "news_agent", "darknet_agent"]
    status = {}

    for agent_name in agents:
        last_run = db.query(AgentRun).filter(
            AgentRun.agent_name == agent_name
        ).order_by(desc(AgentRun.started_at)).first()

        if last_run:
            status[agent_name] = {
                "last_run": last_run.completed_at,
                "status": last_run.status,
                "items_processed": last_run.items_processed
            }
        else:
            status[agent_name] = {
                "last_run": None,
                "status": "never_run",
                "items_processed": 0
            }

    return status


# ==================== Health Check ====================

@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)