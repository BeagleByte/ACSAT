"""
Agent Scheduler - Runs CVE and Darknet agents automatically.
CVE collector runs ONCE PER DAY (not every hour - CVEs are published daily).
"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from Agents.CVECollectorAgent import CVECollectorAgent
from Agents.DarknetNewsAgent import DarknetNewsAgent
from Database.DatabaseManager import get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentScheduler:
    """Manages automated agent execution"""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.cve_agent = CVECollectorAgent(model_name="mistral")
        self.darknet_agent = DarknetNewsAgent(model_name="mistral")

    def start(self):
        """Start scheduled agent jobs"""
        logger.info("🚀 Starting Agent Scheduler...")

        # Schedule CVE collector - ONCE PER DAY at 2:00 AM
        # CVEs are published daily, no need to check every hour
        self.scheduler.add_job(
            func=self._run_cve_agent,
            trigger=CronTrigger(hour=2, minute=0),  # Run at 2:00 AM daily
            id='cve_collector',
            name='CVE Collector Agent (Daily)',
            replace_existing=True
        )

        # Schedule darknet scraper - TWICE PER DAY (morning and evening)
        self.scheduler.add_job(
            func=self._run_darknet_agent,
            trigger=CronTrigger(hour='8,20', minute=0),  # Run at 8:00 AM and 8:00 PM
            id='darknet_scraper',
            name='Darknet News Scraper (2x daily)',
            replace_existing=True
        )

        # Optional: Run CVE collector immediately on startup (for testing)
        self.scheduler.add_job(
            func=self._run_cve_agent,
            id='cve_collector_startup',
            name='CVE Collector (Startup)'
        )

        self.scheduler.start()
        logger.info("✓ Scheduler started")
        logger.info("  📡 CVE Collector: Daily at 2:00 AM")
        logger.info("  🕵️ Darknet Scraper: 2x daily (8 AM, 8 PM)")

    def _run_cve_agent(self):
        """Execute CVE collector agent"""
        logger.info("⏰ Running scheduled CVE collection...")
        db = next(get_db())
        try:
            result = self.cve_agent.run(db)
            logger.info(f"✓ CVE collection: {result}")
        except Exception as e:
            logger.error(f"✗ CVE collection failed: {e}")
        finally:
            db.close()

    def _run_darknet_agent(self):
        """Execute darknet scraper agent"""
        logger.info("⏰ Running scheduled darknet scraping...")
        db = next(get_db())
        try:
            result = self.darknet_agent.run(db)
            logger.info(f"✓ Darknet scraping: {result}")
        except Exception as e:
            logger.error(f"✗ Darknet scraping failed: {e}")
        finally:
            db.close()

    def stop(self):
        """Stop scheduler"""
        self.scheduler.shutdown()
        logger.info("✓ Scheduler stopped")


def run_scheduler():
    """Main entry point"""
    scheduler = AgentScheduler()
    scheduler.start()

    try:
        import time
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.stop()


if __name__ == "__main__":
    run_scheduler()
