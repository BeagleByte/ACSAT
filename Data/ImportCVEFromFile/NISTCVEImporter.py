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

import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict
from Database import  CVE
from Database.DatabaseManager import init_db
from Database.database import SessionLocal

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
        """
        Import CVEs from a single NIST JSON file.

        Args:
            file_path (str): Path to NIST CVE JSON file

        Returns:
            dict: Statistics about import (imported, skipped, errors)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return {"imported": 0, "skipped": 0, "errors": 1}

        logger.info(f"Starting import from:  {file_path}")
        self.imported_count = 0
        self.skipped_count = 0
        self.error_count = 0

        try:
            # Read JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Extract CVE items
            cve_items = data.get("CVE_Items", [])
            total_items = len(cve_items)

            logger.info(f"Found {total_items} CVEs in file")

            # Process each CVE
            for idx, item in enumerate(cve_items, 1):
                # Log progress every 100 items
                if idx % 100 == 0:
                    logger.info(f"Processing {idx}/{total_items}...")

                try:
                    self._process_cve_item(item)
                except Exception as e:
                    logger.warning(f"Error processing CVE item {idx}: {e}")
                    self.error_count += 1

            # Commit all changes
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

    def _process_cve_item(self, item: Dict):
        """
        Process a single CVE item from NIST JSON.

        NIST JSON structure:
        {
          "cve":  {
            "CVE_data_meta": {
              "ID": "CVE-2024-1234"
            },
            "description": {
              "description_data": [
                {"value": "Description text... "}
              ]
            },
            "references": {... }
          },
          "impact": {
            "baseMetricV3": {
              "cvssV3": {
                "baseSeverity": "HIGH",
                "baseScore": 9.8,
                "vectorString":  "..."
              }
            }
          },
          "publishedDate": "2024-01-15T12:30:00Z",
          "lastModifiedDate": "2024-01-20T10:00:00Z"
        }
        """

        # Extract CVE metadata
        cve_data = item.get("cve", {})
        cve_meta = cve_data.get("CVE_data_meta", {})
        cve_id = cve_meta.get("ID")

        # Skip if no CVE ID
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
        for desc_item in cve_data.get("description", {}).get("description_data", []):
            desc_value = desc_item.get("value", "").strip()
            if desc_value:
                description_parts.append(desc_value)
        description = " ".join(description_parts)

        # Extract references
        references = []
        for ref_data in cve_data.get("references", {}).get("reference_data", []):
            url = ref_data.get("url", "").strip()
            if url:
                references.append(url)

        # Extract impact/severity info
        impact = item.get("impact", {})
        base_metric_v3 = impact.get("baseMetricV3", {})
        cvss_v3 = base_metric_v3.get("cvssV3", {})

        severity = cvss_v3.get("baseSeverity", "UNKNOWN")
        cvss_score = cvss_v3.get("baseScore")
        cvss_vector = cvss_v3.get("vectorString", "")

        # Extract affected products/CPE
        affected_products = []
        for config in item.get("configurations", {}).get("nodes", []):
            for cpe_match in config.get("cpe_match", []):
                cpe = cpe_match.get("cpe23Uri", "").strip()
                if cpe:
                    affected_products.append(cpe)

        # Parse dates
        try:
            published_date = datetime.fromisoformat(
                item.get("publishedDate", "").replace("Z", "+00:00")
            )
        except:
            published_date = datetime.utcnow()

        try:
            modified_date = datetime.fromisoformat(
                item.get("lastModifiedDate", "").replace("Z", "+00:00")
            )
        except:
            modified_date = None

        # Create CVE object
        cve = CVE(
            cve_id=cve_id,
            title=cve_id,  # NIST doesn't have separate titles
            description=description[: 5000],  # Limit to 5000 chars
            severity=severity,
            cvss_score=str(cvss_score) if cvss_score else None,
            cvss_vector=cvss_vector,
            affected_products=affected_products,
            references=references,
            published_date=published_date,
            modified_date=modified_date,
            source="nist_bulk_import",  # Mark as bulk imported
            metadata={
                "import_source": "NIST JSON Feed",
                "impact_v3": base_metric_v3
            }
        )

        # Add to session
        self.db.add(cve)
        self.imported_count += 1

    def import_directory(self, directory: str) -> Dict[str, int]:
        """
        Import all NIST JSON files from a directory.

        Args:
            directory (str): Path to directory containing NIST JSON files

        Returns:
            dict: Combined statistics
        """
        dir_path = Path(directory)

        if not dir_path.is_dir():
            logger.error(f"Directory not found: {directory}")
            return {"imported": 0, "skipped": 0, "errors": 1}

        # Find all NIST CVE JSON files
        json_files = sorted(dir_path.glob("nvdcve-1.1-*. json"))

        if not json_files:
            logger.warning(f"No NIST CVE files found in {directory}")
            logger.warning("Expected files like:  nvdcve-1.1-2024.json, nvdcve-1.1-2023.json, etc.")
            return {"imported": 0, "skipped": 0, "errors": 0}

        logger.info(f"Found {len(json_files)} NIST CVE files")

        total_imported = 0
        total_skipped = 0
        total_errors = 0

        # Import each file
        for json_file in json_files:
            logger.info(f"\n{'=' * 60}")
            result = self.import_file(str(json_file))
            total_imported += result["imported"]
            total_skipped += result["skipped"]
            total_errors += result["errors"]

        logger.info(f"\n{'=' * 60}")
        logger.info("TOTAL IMPORT RESULTS:")
        logger.info(f"  - Total Imported: {total_imported}")
        logger.info(f"  - Total Skipped: {total_skipped}")
        logger.info(f"  - Total Errors: {total_errors}")
        logger.info(f"{'=' * 60}\n")

        return {
            "imported": total_imported,
            "skipped": total_skipped,
            "errors": total_errors
        }

    def close(self):
        """Close database session"""
        self.db.close()


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