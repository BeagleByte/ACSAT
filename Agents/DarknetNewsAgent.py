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

# httpx: Async HTTP client (similar to requests but better for async)
# Used to fetch JSON data from APIs (NVD feeds)

# json:  For parsing/serializing JSON data

from datetime import datetime
# datetime: For timestamp handling, recording when CVEs/news were published

from Database import CVE, HackingNews, AgentRun
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


class DarknetNewsAgent:
    """
    Agent to monitor darknet for hacking news.
    Uses local Ollama model for threat intelligence analysis.
    (Optional, requires Tor setup)
    """

    def __init__(self, use_tor: bool = False, model_name: str = "mistral"):
        """
        Initialize darknet agent with local Ollama model.

        Args:
            use_tor (bool): Whether Tor is configured
            model_name (str): Ollama model name
        """
        self.use_tor = use_tor

        self.agent = Agent(
            name="darknet-agent",

            # CHANGED: Use Ollama model
            model=Ollama(
                id=model_name,
                host="http://192.168.1.155:11434",
                timeout=120
            ),

            tools=[WebsiteTools()],

            instructions="""
            You are a darknet intelligence agent. Your role is to:  
            1. Monitor darknet forums (via Tor, if enabled)
            2. Track threat actor activity on known forums
            3. Aggregate exploit kits, 0-days, and vulnerability discussions
            4. Flag emerging threats

            Note: This requires Tor browser/socks5 proxy configured.  
            Focus on high-signal sources only.
            """,
            markdown=True
        )

    def run(self, db:  Session) -> dict:
        """Execute darknet news collection"""
        if not self.use_tor:
            logger.warning("Darknet agent disabled (Tor not configured)")
            return {"status": "skipped", "reason": "Tor not configured"}

        run_record = AgentRun(agent_name="darknet_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger.info("Starting darknet news collection...")
            news_items = self._fetch_darknet_forums(db)

            run_record.status = "success"
            run_record.items_collected = len(news_items)
            run_record.items_processed = len(news_items)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"Darknet collection completed: {len(news_items)} items")
            return {"status": "success", "darknet_news_collected": len(news_items)}

        except Exception as e:
            logger.error(f"Darknet collection failed: {str(e)}")
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime. utcnow()
            db.commit()
            return {"status": "failed", "error": str(e)}

    def _fetch_darknet_forums(self, db: Session) -> list:
        """Placeholder for darknet data fetching"""
        logger.info("Darknet agent:  placeholder (requires Tor setup)")
        return []