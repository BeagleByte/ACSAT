"""
Script to bulk import historical CVE data from NIST JSON files.

NIST publishes CVE feeds as JSON files for different years:
- nvdcve-1.1-2024.json
- nvdcve-1.1-2023.json
- nvdcve-1.1-2022.json
- ...  etc

Download from: https://nvd.nist.gov/feeds/json/cve/1.1/

Usage:
    python NISTCVEImporter.py --file nvdcve-1.1-2024.json
    python import_nist_cves. py --dir ./nist_data/  # Import all JSON files in directory
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict
from Database.DatabaseManager import init_db
from Database import CVE, SessionLocal


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NISTCVEImporter:
    """Imports CVEs from NIST JSON feeds into PostgreSQL database"""

    def __init__(self):
        """Initialize importer with database session"""
        self.db = SessionLocal()
        self.imported_count = 0
        self.skipped_count = 0
        self.error_count = 0

    def import_file(self, file_path: str) -> Dict[str, int]:
        """Import CVEs from a single NIST JSON file (handles both 1.1 and 2.0 formats)"""
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return {"imported": 0, "skipped": 0, "errors": 1}

        logger.info(f"Starting import from: {file_path}")
        self.imported_count = 0
        self.skipped_count = 0
        self.error_count = 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Detect format: 1.1 has CVE_Items, 2.0 has vulnerabilities
            if "CVE_Items" in data:
                cve_items = data.get("CVE_Items", [])
                format_version = "1.1"
            else:
                cve_items = data.get("vulnerabilities", [])
                format_version = "2.0"

            total_items = len(cve_items)
            logger.info(f"Found {total_items} CVEs in file (NIST format {format_version})")

            for idx, item in enumerate(cve_items, 1):
                if idx % 100 == 0:
                    logger.info(f"Processing {idx}/{total_items}...")

                try:
                    self._process_cve_item(item, format_version)
                    # performace optimization: commit in batches
                    if idx % 500 == 0:  # Commit every 500 records
                        self.db.commit()
                except Exception as e:
                    logger.warning(f"Error processing CVE item {idx}: {e}")
                    self.error_count += 1

            self.db.commit()

            logger.info(f"✓ Import completed!")
            logger.info(f"  - Imported: {self.imported_count}")
            logger.info(f"  - Skipped (duplicates): {self.skipped_count}")
            logger.info(f"  - Errors: {self.error_count}")

            return {
                "imported": self.imported_count,
                "skipped": self.skipped_count,
                "errors": self.error_count
            }

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON file: {e}")
            return {"imported": 0, "skipped": 0, "errors": 1}
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return {"imported": 0, "skipped": 0, "errors": 1}

    def _process_cve_item(self, item: Dict, format_version: str = "1.1"):
        """Process a single CVE item from NIST JSON (handles both 1.1 and 2.0 formats)"""
        # Extract CVE ID based on format
        if format_version == "2.0":
            cve_id = item.get("cve", {}).get("id")
            cve_data = item.get("cve", {})
        else:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID")

        if not cve_id:
            self.error_count += 1
            return

        # Check if CVE already exists
        existing = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if existing:
            self.skipped_count += 1
            return

        # Extract description
        description_parts = []
        if format_version == "2.0":
            for desc_item in cve_data.get("descriptions", []):
                desc_value = desc_item.get("value", "").strip()
                if desc_value:
                    description_parts.append(desc_value)
                    break  # Use only English description
        else:
            for desc_item in cve_data.get("description", {}).get("description_data", []):
                desc_value = desc_item.get("value", "").strip()
                if desc_value:
                    description_parts.append(desc_value)

        description = " ".join(description_parts)

        # Extract references
        references = []
        if format_version == "2.0":
            for ref_data in cve_data.get("references", []):
                url = ref_data.get("url", "").strip()
                if url:
                    references.append(url)
        else:
            for ref_data in cve_data.get("references", {}).get("reference_data", []):
                url = ref_data.get("url", "").strip()
                if url:
                    references.append(url)

        # Extract CVSS data
        severity = "UNKNOWN"
        cvss_score = None
        cvss_vector = ""
        base_metric_v3 = {}

        if format_version == "2.0":
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                base_metric_v3 = {"cvssV3": cvss_data}
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                base_metric_v3 = {"cvssV3": cvss_data}
        else:
            impact = item.get("impact", {})
            base_metric_v3 = impact.get("baseMetricV3", {})
            cvss_v3 = base_metric_v3.get("cvssV3", {})
            severity = cvss_v3.get("baseSeverity", "UNKNOWN")
            cvss_score = cvss_v3.get("baseScore")
            cvss_vector = cvss_v3.get("vectorString", "")

        # Extract affected products/CPE
        affected_products = []
        if format_version == "2.0":
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "").strip()
                        if cpe:
                            affected_products.append(cpe)
        else:
            for config in item.get("configurations", {}).get("nodes", []):
                for cpe_match in config.get("cpe_match", []):
                    cpe = cpe_match.get("cpe23Uri", "").strip()
                    if cpe:
                        affected_products.append(cpe)

        # Parse dates
        if format_version == "2.0":
            pub_date_str = cve_data.get("published", "")
            mod_date_str = cve_data.get("lastModified", "")
        else:
            pub_date_str = item.get("publishedDate", "")
            mod_date_str = item.get("lastModifiedDate", "")

        try:
            published_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
        except:
            published_date = datetime.utcnow()

        try:
            modified_date = datetime.fromisoformat(mod_date_str.replace("Z", "+00:00"))
        except:
            modified_date = None

        # Create CVE object
        cve = CVE(
            cve_id=cve_id,
            title=cve_id,
            description=description[:5000],
            severity=severity,
            cvss_score=str(cvss_score) if cvss_score else None,
            affected_products=affected_products,
            references=references,
            published_date=published_date,
            last_modified=modified_date,  # Changed from modified_date to last_modified
            source="nist_bulk_import",
            cve_metadata={  # Changed from metadata to cve_metadata
                "import_source": "NIST JSON Feed",
                "format_version": format_version,
                "cvss_vector": cvss_vector,
                "impact_v3": base_metric_v3
            }
        )

        self.db.add(cve)
        self.imported_count += 1

    def close(self):
        """Close database session"""
        self.db.close()

    def import_directory(self, dir_path: str) -> Dict[str, int]:
        """Import CVEs from all NIST JSON files in a directory"""
        dir_path = Path(dir_path)

        if not dir_path.is_dir():
            logger.error(f"Directory not found: {dir_path}")
            return {"imported": 0, "skipped": 0, "errors": 1}

        # Find all NIST CVE JSON files (handles both 1.1 and 2.0 formats)
        json_files = sorted(dir_path.glob("nvdcve-*.json"))

        if not json_files:
            logger.warning(f"No NIST CVE files found in {dir_path}/")
            logger.warning("Expected files like: nvdcve-2.0-2025.json, nvdcve-1.1-2024.json, etc.")
            return {"imported": 0, "skipped": 0, "errors": 0}

        logger.info(f"Found {len(json_files)} CVE files to import")

        total_imported = 0
        total_skipped = 0
        total_errors = 0

        for file_path in json_files:
            logger.info(f"\n{'='*60}")
            result = self.import_file(str(file_path))
            total_imported += result["imported"]
            total_skipped += result["skipped"]
            total_errors += result["errors"]

        logger.info(f"\n{'='*60}")
        logger.info("✓ Directory import completed!")
        logger.info(f"  - Total Imported: {total_imported}")
        logger.info(f"  - Total Skipped: {total_skipped}")
        logger.info(f"  - Total Errors: {total_errors}")

        return {
            "imported": total_imported,
            "skipped": total_skipped,
            "errors": total_errors
        }

def main():
    """Command-line interface for CVE import"""
    parser = argparse.ArgumentParser(
        description="Import NIST CVE data from JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import a single file
  python NISTCVEImporter.py --file nvdcve-1.1-2024.json

  # Import all files from directory
  python NISTCVEImporter.py --dir ./nist_data/

  # Initialize database first
  python NISTCVEImporter.py --init-db --dir ./nist_data/
        """
    )

    parser.add_argument(
        "--file",
        type=str,
        help="Path to a single NIST CVE JSON file"
    )
    parser.add_argument(
        "--dir",
        type=str,
        help="Path to directory containing NIST CVE JSON files"
    )
    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize database tables before import"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.file and not args.dir:
        parser.print_help()
        print("\nError: Must provide either --file or --dir")
        return

    # Initialize database if requested
    if args.init_db:
        logger.info("Initializing database tables...")
        init_db()
        logger.info("✓ Database tables created")

    # Create importer
    importer = NISTCVEImporter()

    try:
        # Import data
        if args.file:
            importer.import_file(args.file)
        elif args.dir:
            importer.import_directory(args.dir)

    finally:
        importer.close()


if __name__ == "__main__":
    main()