"""
Input validation to prevent SQL injection and other attacks.

PREVENTS: SQL injection, code injection, XSS, path traversal
"""

import logging
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


# ==================== VALIDATORS ====================

class InputValidator:
    """Validate all user/external inputs"""

    @staticmethod
    def validate_cve_id(cve_id: str) -> str:
        """
        Validate CVE ID format.

        Valid format: CVE-YYYY-NNNNN (e.g., CVE-2024-12345)

        Args:
            cve_id (str): CVE ID to validate

        Returns:
            str:  Validated CVE ID

        Raises:
            ValueError: If invalid format
        """
        # CVE IDs must match strict pattern
        pattern = r'^CVE-\d{4}-\d{4,}$'

        if not re.match(pattern, cve_id):
            raise ValueError(
                f"Invalid CVE ID format: {cve_id}.  "
                f"Must be CVE-YYYY-NNNNN (e.g., CVE-2024-12345)"
            )

        return cve_id

    @staticmethod
    def validate_search_query(query: str, max_length: int = 256) -> str:
        """
        Validate search query to prevent injection attacks.

        Args:
            query (str): Search query
            max_length (int): Max query length

        Returns:
            str: Validated query

        Raises:
            ValueError: If invalid
        """
        if not query:
            raise ValueError("Search query cannot be empty")

        if len(query) > max_length:
            raise ValueError(f"Search query too long (max {max_length} chars)")

        # Remove dangerous characters but allow safe search terms
        # Allow:  alphanumeric, spaces, hyphens, underscores, colons, quotes
        dangerous_chars = re.findall(r'[;\'"\n\r\x00]', query)
        if dangerous_chars:
            logger.warning(
                f"⚠️  Search query contains suspicious characters: {dangerous_chars}. "
                f"Query:  {query}"
            )
            # Remove dangerous characters
            query = re.sub(r'[;\'"\n\r\x00]', '', query)

        return query.strip()

    @staticmethod
    def validate_file_path(file_path: str, base_directory: str) -> Path:
        """
        Validate file path to prevent directory traversal attacks.

        Args:
            file_path (str): File path to validate
            base_directory (str): Base directory (files must be inside this)

        Returns:
            Path: Validated file path

        Raises:
            ValueError: If path is outside base directory
        """
        base = Path(base_directory).resolve()
        target = Path(file_path).resolve()

        # Check if target is inside base directory
        try:
            target.relative_to(base)
        except ValueError:
            raise ValueError(
                f"Path traversal detected!  "
                f"File path '{file_path}' is outside allowed directory '{base_directory}'"
            )

        return target

    @staticmethod
    def validate_url(url: str, max_length: int = 2048) -> str:
        """
        Validate URL to prevent injection attacks.

        Args:
            url (str): URL to validate
            max_length (int): Max URL length

        Returns:
            str: Validated URL

        Raises:
            ValueError: If invalid
        """
        if not url:
            raise ValueError("URL cannot be empty")

        if len(url) > max_length:
            raise ValueError(f"URL too long (max {max_length} chars)")

        # Check for suspicious patterns
        if any(dangerous in url.lower() for dangerous in ['javascript:', 'data:']):
            raise ValueError(f"Dangerous URL scheme detected: {url}")

        return url.strip()

    @staticmethod
    def validate_integer(value: Any, min_val: int = 0,
                         max_val: int = 1000000, name: str = "value") -> int:
        """
        Validate integer input.

        Args:
            value:  Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            name:  Name for error messages

        Returns:
            int: Validated integer

        Raises:
            ValueError: If invalid
        """
        try:
            val = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"{name} must be an integer, got {type(value).__name__}")

        if not (min_val <= val <= max_val):
            raise ValueError(
                f"{name} must be between {min_val} and {max_val}, got {val}"
            )

        return val

    @staticmethod
    def validate_model_name(model_name: str) -> str:
        """
        Validate Ollama model name.

        Args:
            model_name (str): Model name to validate

        Returns:
            str:  Validated model name

        Raises:
            ValueError: If invalid
        """
        # Model names must be alphanumeric with hyphens
        if not re.match(r'^[a-z0-9\-]+$', model_name.lower()):
            raise ValueError(
                f"Invalid model name:  {model_name}. "
                f"Must contain only alphanumeric characters and hyphens."
            )

        return model_name


# ==================== USAGE HELPER ====================

def validate_agent_params(
        cve_ids: Optional[List[str]] = None,
        limit: int = 50,
        max_pocs: int = 10
) -> Dict[str, Any]:
    """
    Validate parameters for agent execution.

    Returns:
        dict: Validated parameters
    """
    validator = InputValidator()

    # Validate CVE IDs if provided
    if cve_ids:
        validated_ids = []
        for cve_id in cve_ids:
            try:
                validated_ids.append(validator.validate_cve_id(cve_id))
            except ValueError as e:
                logger.error(f"Invalid CVE ID: {e}")
        cve_ids = validated_ids

    # Validate limits
    limit = validator.validate_integer(limit, min_val=1, max_val=100, name="limit")
    max_pocs = validator.validate_integer(max_pocs, min_val=1, max_val=50, name="max_pocs")

    return {
        "cve_ids": cve_ids,
        "limit": limit,
        "max_pocs": max_pocs
    }