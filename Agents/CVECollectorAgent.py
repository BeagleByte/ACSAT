"""
Agno agents for collecting CVE and hacking news data.
Uses LOCAL Ollama models instead of OpenAI (free and private!).

Installation:
- pip install ollama agno
- Download a model: ollama pull mistral (or llama2, neural-chat, etc.)
- Start Ollama: ollama serve
"""

# ==================== IMPORTS ====================
from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.tools.website import WebsiteTools
import httpx
from datetime import datetime
from Database import CVE, HackingNews, AgentRun
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)


class CVECollectorAgent:
    """
    Agent to collect CVE data from NIST recent JSON feed.
    Uses local Ollama model for reasoning (no API costs!).

    Strategy:
    1. Get last CVE ID from database
    2. Fetch recent CVEs JSON from NIST
    3. Loop through and skip entries already in database
    4. Insert only new CVEs
    """

    def __init__(self, model_name: str = "mistral"):
        """
        Initialize CVE collector agent with local Ollama model.

        Args:
            model_name (str): Name of Ollama model to use.
        """
        self.agent = Agent(
            name="cve-collector",
            model=Ollama(
                model_id=model_name,
                base_url="http://localhost:11434",
                timeout=120
            ),
            tools=[WebsiteTools()],
            instructions="""
            You are a CVE intelligence agent. Your job is to:
            1. Fetch recent CVE data from NVD JSON feed
            2. Parse and extract CVE information
            3. Skip CVEs already in database
            4. Store only NEW CVE records

            Source: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json

            Extract: cve_id, title, description, severity, cvss_score, affected_products, references.
            """,
            markdown=True
        )

    def run(self, db: Session) -> dict:
        """
        Main execution method for the CVE collector agent.

        Flow:
        1. Create AgentRun record to track execution
        2. Get last CVE ID from database
        3. Fetch recent CVEs from NIST JSON
        4. Skip existing CVEs, insert new ones
        5. Update AgentRun record with results

        Args:
            db (Session): Database session

        Returns:
            dict: Result status and count of NEW CVEs collected
        """
        run_record = AgentRun(agent_name="cve_agent", status="running")
        db.add(run_record)
        db.commit()

        try:
            logger.info("Starting CVE collection...")

            # Get last CVE ID from database (to know where we left off)
            last_cve_id = self._get_last_cve_id(db)
            logger.info(f"Last CVE in database: {last_cve_id or 'None (empty DB)'}")

            # Fetch recent CVEs from NIST and filter out existing ones
            cves_collected = self._fetch_nvd_feed(db, last_cve_id)

            # Update run record
            run_record.status = "success"
            run_record.items_collected = len(cves_collected)
            run_record.items_processed = len(cves_collected)
            run_record.completed_at = datetime.utcnow()
            db.commit()

            logger.info(f"CVE collection completed: {len(cves_collected)} NEW CVEs added")
            return {"status": "success", "cves_collected": len(cves_collected)}

        except Exception as e:
            logger.error(f"CVE collection failed: {str(e)}")
            run_record.status = "failed"
            run_record.error_message = str(e)
            run_record.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "failed", "error": str(e)}

    def _get_last_cve_id(self, db: Session) -> str:
        """
        Get the most recent CVE ID from database.

        This tells us which CVE was the last one inserted,
        so we can skip it and older CVEs when fetching new data.

        Args:
            db (Session): Database session

        Returns:
            str: Last CVE ID (e.g., "CVE-2024-12345") or None if DB is empty
        """
        try:
            # Query the most recent CVE by published_date
            last_cve = db.query(CVE).order_by(CVE.published_date.desc()).first()
            return last_cve.cve_id if last_cve else None
        except Exception as e:
            logger.warning(f"Could not get last CVE ID: {e}")
            return None

    def _fetch_nvd_feed(self, db: Session, last_cve_id: str = None) -> list:
        """
        Fetch CVE data from NIST recent JSON feed.
        Skip CVEs that already exist in database.

        Process:
        1. Fetch recent CVEs JSON from NIST
        2. Loop through each CVE item
        3. Check if CVE ID already exists in database
        4. If exists: skip it
        5. If new: parse and insert into database

        Args:
            db (Session): Database session
            last_cve_id (str): Last CVE ID in database (for logging/reference)

        Returns:
            list: List of NEW CVE objects that were added
        """
        # NIST recent CVEs JSON feed (contains last ~8 days of CVEs)
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json"

        cves = []  # Track new CVEs added

        try:
            logger.info(f"Fetching recent CVEs from NIST: {url}")

            # Fetch the JSON feed
            response = httpx.get(url, timeout=60)
            response.raise_for_status()

            data = response.json()
            cve_items = data.get("CVE_Items", [])

            logger.info(f"NIST feed contains {len(cve_items)} CVE items")

            # Loop through each CVE in the feed
            for item in cve_items:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")

                if not cve_id:
                    continue  # Skip if no CVE ID

                # CHECK IF CVE ALREADY EXISTS IN DATABASE
                existing_cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if existing_cve:
                    # Already have this CVE - skip it
                    logger.debug(f"Skipping existing CVE: {cve_id}")
                    continue

                # NEW CVE - parse and insert
                logger.info(f"Found NEW CVE: {cve_id}")

                # Extract description (English)
                descriptions = cve_data.get("description", {}).get("description_data", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CVSS score and severity
                impact = item.get("impact", {})
                cvss_v3 = impact.get("baseMetricV3", {})
                cvss_v2 = impact.get("baseMetricV2", {})

                cvss_score = "N/A"
                severity = "UNKNOWN"

                # Prefer CVSS v3
                if cvss_v3:
                    cvss_data = cvss_v3.get("cvssV3", {})
                    cvss_score = str(cvss_data.get("baseScore", "N/A"))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                elif cvss_v2:
                    cvss_data = cvss_v2.get("cvssV2", {})
                    cvss_score = str(cvss_data.get("baseScore", "N/A"))
                    # Map CVSS v2 score to severity
                    try:
                        score = float(cvss_score)
                        if score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    except ValueError:
                        severity = "UNKNOWN"

                # Extract references
                references = []
                ref_data = cve_data.get("references", {}).get("reference_data", [])
                for ref in ref_data:
                    url_ref = ref.get("url")
                    if url_ref:
                        references.append(url_ref)

                # Extract affected products (CPE)
                affected_products = []
                configurations = item.get("configurations", {})
                nodes = configurations.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpe_match", [])
                    for cpe in cpe_matches:
                        cpe_uri = cpe.get("cpe23Uri", "")
                        if cpe_uri:
                            # Parse CPE to extract product name
                            # Example: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
                            parts = cpe_uri.split(":")
                            if len(parts) >= 5:
                                product = f"{parts[3]} {parts[4]}"
                                if product not in affected_products:
                                    affected_products.append(product)

                # Published date
                published = item.get("publishedDate", "")
                try:
                    published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    published_date = datetime.utcnow()

                # Last modified date
                last_modified = item.get("lastModifiedDate", "")
                try:
                    last_modified_date = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    last_modified_date = datetime.utcnow()

                # Create CVE object
                cve = CVE(
                    cve_id=cve_id,
                    title=cve_id,  # Use CVE ID as title (NIST doesn't provide separate title)
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    published_date=published_date,
                    last_modified=last_modified_date,
                    source="NIST",
                    affected_products=affected_products,
                    references=references,
                    status="published"
                )

                # Add to database session
                db.add(cve)
                cves.append(cve)

            # Commit all new CVEs to database
            db.commit()

            logger.info(f"Successfully added {len(cves)} NEW CVEs to database")

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch NIST feed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Failed to process CVEs: {str(e)}")
            db.rollback()
            raise

        return cves
