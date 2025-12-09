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

import feedparser
# feedparser: Library for parsing RSS/Atom feeds
# Used to fetch news from RSS feeds (Hacker News, BleepingComputer)

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

class HackingNewsAgent:
    """
    Agent to collect hacking news from public sources.
    Uses local Ollama model for categorization and relevance scoring.
    """

    def __init__(self, model_name: str = "mistral"):
        """
        Initialize hacking news agent with local Ollama model.

        Args:
            model_name (str): Ollama model name
        """
        self.agent = Agent(
            name="hacking-news-agent",

            # CHANGED: Use Ollama model
            model=Ollama(
                model_id=model_name,
                base_url="http://localhost:11434",
                timeout=120
            ),

            tools=[WebsiteTools()],

            instructions="""
            You are a hacking news aggregator agent.  Collect news from:  
            1.  Hacker News (via RSS or API)
            2. Reddit security subreddits (r/hacking, r/netsec, r/cybersecurity)
            3. SecurityFocus
            4. BleepingComputer
            5. Twitter/X (security researchers, accounts)

            For each news item, extract:
            - Title
            - Content/description
            - Source
            - Category (exploit, breach, threat, tool, advisory, etc.)
            - Relevance score (0-100) based on severity and impact

            Avoid duplicates by checking source URLs.  
            """,
            markdown=True
        )

    def run(self, db: Session) -> dict:
        """Execute hacking news collection"""
        run_record = AgentRun(agent_name="news_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger.info("Starting hacking news collection...")
            news_items = self._fetch_hacker_news(db) + self._fetch_bleepingcomputer(db)

            run_record.status = "success"
            run_record.items_collected = len(news_items)
            run_record.items_processed = len(news_items)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"News collection completed: {len(news_items)} items")
            return {"status": "success", "news_collected": len(news_items)}

        except Exception as e:
            logger.error(f"News collection failed: {str(e)}")
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime. utcnow()
            db.commit()
            return {"status": "failed", "error": str(e)}

    def _fetch_hacker_news(self, db: Session) -> list:
        """Fetch from Hacker News"""
        url = "https://news.ycombinator.com/rss"
        items = []

        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[: 20]:
                source_url = entry.get("link", "")

                existing = db.query(HackingNews).filter(
                    HackingNews.source_url == source_url
                ).first()
                if existing:
                    continue

                news = HackingNews(
                    title=entry.get("title", ""),
                    content=entry.get("summary", "")[: 1000],
                    source="hacker_news",
                    source_url=source_url,
                    published_date=(
                        datetime(*entry.published_parsed[: 6])
                        if hasattr(entry, 'published_parsed')
                        else datetime.utcnow()
                    ),
                    category="news",
                    relevance_score=50
                )
                db.add(news)
                items.append(news)

            db. commit()

        except Exception as e:
            logger.error(f"Error fetching Hacker News: {e}")

        return items

    def _fetch_bleepingcomputer(self, db: Session) -> list:
        """Fetch from BleepingComputer"""
        url = "https://www.bleepingcomputer.com/feed/"
        items = []

        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[: 20]:
                source_url = entry.get("link", "")

                existing = db. query(HackingNews).filter(
                    HackingNews.source_url == source_url
                ).first()
                if existing:
                    continue

                news = HackingNews(
                    title=entry. get("title", ""),
                    content=entry.get("summary", "")[:1000],
                    source="bleepingcomputer",
                    source_url=source_url,
                    published_date=(
                        datetime(*entry.published_parsed[:6])
                        if hasattr(entry, 'published_parsed')
                        else datetime.utcnow()
                    ),
                    category="breach",
                    relevance_score=70
                )
                db.add(news)
                items.append(news)

            db.commit()

        except Exception as e:
            logger.error(f"Error fetching BleepingComputer: {e}")

        return items

