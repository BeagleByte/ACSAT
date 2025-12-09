"""
Background task scheduler using APScheduler.
Runs agents on a schedule to keep data fresh.
Uses local Ollama models (no API costs! ).
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
import os
from Database.database import SessionLocal
from Agents import CVECollectorAgent, HackingNewsAgent, DarknetNewsAgent
from Agents.poc_hunter_agent import POCHunterAgent

logger = logging.getLogger(__name__)

class TaskScheduler:
    def __init__(self, model_name: str = "mistral"):
        """
        Initialize scheduler with Ollama model.

        Args:
            model_name (str): Ollama model to use
                            Popular options:
                            - "mistral" (fast, good for most tasks)
                            - "llama2" (larger, more capable)
                            - "neural-chat" (good for chat/instructions)
                            - "orca-mini" (small, good on low RAM)
        """
        self.scheduler = BackgroundScheduler()
        self.poc_hunter = POCHunterAgent(model_name=model_name)
        # Initialize agents with the specified model
        self.cve_agent = CVECollectorAgent(model_name=model_name)
        self.news_agent = HackingNewsAgent(model_name=model_name)
        self.darknet_agent = DarknetNewsAgent(
            use_tor=os.getenv("DARKNET_ENABLED", "false").lower() == "true",
            model_name=model_name
        )

    def start(self):
        """Start the scheduler"""
        # CVE collection every hour
        self.scheduler.add_job(
            self._run_cve_agent,
            trigger=IntervalTrigger(hours=1),
            id="cve_job",
            name="CVE Collection",
            replace_existing=True
        )

        # Hacking news every 30 minutes
        self.scheduler.add_job(
            self._run_news_agent,
            trigger=IntervalTrigger(minutes=30),
            id="news_job",
            name="Hacking News Collection",
            replace_existing=True
        )
        # POC hunting every 24 hours (or adjust frequency)
        self.scheduler.add_job(
            self._run_poc_hunter,
            trigger=IntervalTrigger(hours=24),
            id="poc_hunter_job",
            name="POC Hunter (Ollama + DuckDuckGo)",
            replace_existing=True
        )
        # Darknet news every 6 hours (if enabled)
        if os.getenv("DARKNET_ENABLED", "false").lower() == "true":
            self.scheduler.add_job(
                self._run_darknet_agent,
                trigger=IntervalTrigger(hours=6),
                id="darknet_job",
                name="Darknet News Collection",
                replace_existing=True
            )

        self.scheduler.start()
        logger.info("Task scheduler started")

    def _run_poc_hunter(self):
        """Run POC hunter with Ollama + DuckDuckGo"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Starting POC Hunter...")
            result = self.poc_hunter.run(db, limit=20, max_results_per_cve=5)
            logger.info(f"[Scheduled] POC Hunter completed:  {result}")
        except Exception as e:
            logger.error(f"[Scheduled] POC Hunter failed: {e}")
        finally:
            db.close()


    def stop(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        logger.info("Task scheduler stopped")

    def _run_cve_agent(self):
        """Run CVE agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running CVE agent...")
            result = self.cve_agent.run(db)
            logger.info(f"[Scheduled] CVE agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] CVE agent failed: {e}")
        finally:
            db.close()

    def _run_news_agent(self):
        """Run news agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running hacking news agent...")
            result = self.news_agent.run(db)
            logger.info(f"[Scheduled] News agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] News agent failed: {e}")
        finally:
            db.close()

    def _run_darknet_agent(self):
        """Run darknet agent in background"""
        db = SessionLocal()
        try:
            logger.info("[Scheduled] Running darknet agent...")
            result = self.darknet_agent.run(db)
            logger.info(f"[Scheduled] Darknet agent result: {result}")
        except Exception as e:
            logger.error(f"[Scheduled] Darknet agent failed: {e}")
        finally:
            db.close()