"""
Agno agents for collecting CVE and hacking news data.
Uses LOCAL Ollama models instead of OpenAI (free and private! ).

Installation:
- pip install ollama agno
- Download a model:  ollama pull mistral (or llama2, neural-chat, etc.)
- Start Ollama: ollama serve
"""

# ==================== IMPORTS ====================
from agno.agent import Agent
# Agent:  Base class from Agno framework that handles tool calling, memory, and LLM interactions
# An Agent is an autonomous entity that can use tools (like WebsiteTools) to accomplish tasks

from agno.models. ollama import Ollama
# OpenAIChat: LLM model wrapper for OpenAI's API (gpt-4-turbo, gpt-4, etc.)
# Other options: anthropic. Claude, replicate models, etc.
# The model is what "thinks" and decides which tools to use and how to respond

from agno.tools.website import WebsiteTools
# WebsiteTools: Agno toolkit for reading/scraping website content
# Methods include: read_url(url), add_website_to_knowledge_base(url)
# Uses BeautifulSoup4 internally to parse HTML

# os:  For reading environment variables (API keys, config)

# feedparser: Library for parsing RSS/Atom feeds
# Used to fetch news from RSS feeds (Hacker News, BleepingComputer)

import httpx
# httpx: Async HTTP client (similar to requests but better for async)
# Used to fetch JSON data from APIs (NVD feeds)

# json:  For parsing/serializing JSON data

from datetime import datetime
# datetime: For timestamp handling, recording when CVEs/news were published

from Database.database import CVE, HackingNews, AgentRun
# SessionLocal: Factory for creating database sessions
# CVE, HackingNews, AgentRun: SQLAlchemy ORM models (database tables)

from sqlalchemy. orm import Session
# Session: Type hint for database session objects

# Optional: Type hint for optional function parameters

import logging
# logging:  For recording agent activity and errors

# Configure logger for this module
# Logs will show which agent is running, what it found, and any errors
logger = logging.getLogger(__name__)


class CVECollectorAgent:
    """
    Agent to collect CVE data from RSS feeds and JSON APIs.
    Uses local Ollama model for reasoning (no API costs! ).
    """

    def __init__(self, model_name: str = "mistral"):
        """
        Initialize CVE collector agent with local Ollama model.

        Args:
            model_name (str): Name of Ollama model to use.
                            Options: "mistral", "llama2", "neural-chat", "orca-mini", etc.
                            Make sure model is installed:  ollama pull <model_name>
        """
        self.agent = Agent(
            name="cve-collector",

            # CHANGED: Use Ollama instead of OpenAIChat
            # - model_name:  which Ollama model to use
            # - base_url: where Ollama server is running (default localhost:11434)
            # - timeout: how long to wait for response (increase if model is slow)
            model=Ollama(
                model_id=model_name,  # e.g., "mistral", "llama2"
                base_url="http://localhost:11434",  # Ollama server URL
                timeout=120  # 2 minutes timeout (local inference can be slow)
            ),

            tools=[WebsiteTools()],

            # System instructions/prompt that guides agent behavior
            # Tells the agent what its role is, what sources to check, what to extract
            instructions="""
            You are a CVE intelligence agent. Your job is to:   
            1. Fetch CVE data from NVD RSS feeds and other sources
            2. Parse and enrich CVE information
            3. Extract severity, affected products, and references
            4. Store normalized data in the database

            Sources to check:
            - NVD RSS:   https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json
            - Mitre:   https://www.cvedetails.com/

            Ensure all CVE records include:  cve_id, title, description, severity, cvss_score, affected_products, references.   
            """,
            markdown=True
        )

    def run(self, db: Session) -> dict:
        """
        Main execution method for the CVE collector agent.

        Flow:
        1. Create an AgentRun record to track this execution
        2. Call _fetch_nvd_feed() to collect CVEs
        3. Update the AgentRun record with results (success/failure)
        4. Return summary dict

        Args:
            db (Session): Database session for storing records

        Returns:
            dict: Result status and count of CVEs collected
                  Example: {"status": "success", "cves_collected": 25}
        """

        # Create a record in agent_runs table to track this execution
        # Status starts as "running"
        run_record = AgentRun(agent_name="cve_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            # Log that execution is starting
            logger.info("Starting CVE collection...")

            # Call the main collection method - this fetches CVEs from NVD
            # Returns a list of CVE objects that were added to database
            cves_collected = self._fetch_nvd_feed(db)

            run_record.status = "success"
            run_record.items_collected = len(cves_collected)
            run_record.items_processed = len(cves_collected)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"CVE collection completed:  {len(cves_collected)} CVEs")
            return {"status": "success", "cves_collected": len(cves_collected)}

        except Exception as e:
            logger.error(f"CVE collection failed: {str(e)}")
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "error": str(e)}

    def _fetch_nvd_feed(self, db: Session) -> list:
        """
        Fetch CVE data from NVD JSON feed and store in database.

        Process:
        1. Make HTTP GET request to NVD recent CVEs JSON endpoint
        2. Parse the JSON response
        3. For each CVE in the feed:
           - Extract CVE ID, title, description, severity, CVSS score
           - Check if it already exists in database (avoid duplicates)
           - Create CVE object and add to session
        4. Commit all new CVEs to database

        Args:
            db (Session): Database session

        Returns:
            list:  List of CVE objects that were added
        """

        # NVD official JSON feed containing recent CVE data
        # This endpoint returns the latest CVEs with all their metadata
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json"

        # List to collect CVE objects we're adding
        cves = []

        try:
            # Make HTTP request to fetch the NVD feed
            # timeout=30 seconds:  if feed doesn't respond in 30s, fail gracefully
            response = httpx.get(url, timeout=30)

            # Raise exception if HTTP status is not 2xx (200-299)
            # This catches 404, 500, etc.
            response.raise_for_status()

            # Parse JSON response into Python dict
            data = response.json()

            # Iterate through CVE items in the response
            # [: 50] limits to first 50 items to avoid overload (can adjust or remove)
            for item in data.get("CVE_Items", [])[:50]:

                # Extract the "cve" object which contains CVE metadata
                cve_data = item.get("cve", {})

                # Extract the "impact" object which contains severity/CVSS info
                impact = item.get("impact", {})

                cve_id = cve_data.get("CVE_data_meta", {}).get("ID")
                if not cve_id:
                    continue

                existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if existing:
                    continue

                cve = CVE(
                    cve_id=cve_id,
                    title=cve_data.get("CVE_data_meta", {}).get("ID", ""),
                    description="; ".join([
                        d.get("value", "")
                        for d in cve_data.get("description", {}).get("description_data", [])
                    ]),
                    severity=impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN"),
                    cvss_score=str(impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "N/A")),
                    source="nvd",
                    published_date=datetime.fromisoformat(
                        item.get("publishedDate", "").replace("Z", "+00:00")
                    ),
                )
                db.add(cve)
                cves.append(cve)

            db.commit()

        except Exception as e:
            logger.error(f"Error fetching NVD feed: {e}")

        return cves