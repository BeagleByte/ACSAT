"""
Secure configuration management with validation.

This module:
1. Loads environment variables with defaults
2. Validates all security-critical configs
3. Prevents sensitive data from being logged
4. Enforces safe defaults
"""

import logging
import os
from datetime import timedelta
from typing import Optional

from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

# ==================== SECURITY CONSTANTS ====================

# Rate limiting (prevent API abuse)
RATE_LIMITS = {
    "nvd_api": {
        "requests_per_minute": 10,  # NVD allows 10 req/min per IP
        "timeout_seconds": 30
    },
    "github_api": {
        "requests_per_minute": 30,  # Depends on auth (60 with token)
        "timeout_seconds": 15
    },
    "duckduckgo": {
        "requests_per_minute": 20,  # Respectful limit
        "timeout_seconds": 10
    },
    "news_feeds": {
        "requests_per_minute": 5,
        "timeout_seconds": 20
    }
}

# Resource limits (prevent exhaustion)
RESOURCE_LIMITS = {
    "max_cves_per_run": 50,  # Max CVEs to process per agent run
    "max_pocs_per_cve": 10,  # Max POCs to store per CVE
    "max_news_items_per_run": 100,  # Max news items per run
    "max_darknet_items_per_run": 20,  # Darknet is expensive
    "max_concurrent_jobs": 3,  # Max jobs running simultaneously
    "max_database_connections": 20,  # Connection pool size
    "request_timeout_seconds": 30,  # Global request timeout
}

# Retry/Backoff strategy
RETRY_CONFIG = {
    "max_retries": 3,
    "initial_backoff_seconds": 5,  # Start with 5 second delay
    "max_backoff_seconds": 300,  # Max 5 minute delay
    "backoff_multiplier": 2,  # Exponential:  5, 10, 20, 40...
    "jitter": True,  # Add randomness to prevent thundering herd
}

# Job execution windows
JOB_TIMEOUTS = {
    "cve_agent": timedelta(minutes=15),  # CVE collection should finish in 15 min
    "news_agent": timedelta(minutes=10),  # News collection in 10 min
    "poc_hunter": timedelta(minutes=60),  # POC hunting can take longer
    "darknet_agent": timedelta(minutes=30),  # Darknet in 30 min
    "import_job": timedelta(minutes=120),  # Imports can be long (2 hours)
}


# ==================== PYDANTIC CONFIG VALIDATION ====================

class DatabaseConfig(BaseModel):
    """Database configuration with validation"""
    url: str = Field(
        default="postgresql://cve_user:password@localhost: 5432/cve_intelligence_db",
        description="PostgreSQL connection string"
    )
    pool_size: int = Field(
        default=10,
        ge=5,  # Min 5 connections
        le=50,  # Max 50 connections
        description="Database connection pool size"
    )
    max_overflow: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Max overflow connections beyond pool_size"
    )
    echo: bool = Field(
        default=False,
        description="Log all SQL queries (security risk in production! )"
    )

    @validator('url')
    def validate_database_url(cls, v):
        """Validate database URL format"""
        if not v.startswith(('postgresql://', 'postgres://')):
            raise ValueError('Database URL must use postgresql: // scheme')
        # Warn if password in URL (security risk)
        if '@' in v and '://' in v:
            scheme, rest = v.split('://', 1)
            if ': ' in rest.split('@')[0]:
                logger.warning(
                    "⚠️  Database password found in URL.  "
                    "Consider using environment variables instead."
                )
        return v


class OllamaConfig(BaseModel):
    """Ollama LLM configuration with validation"""
    base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL"
    )
    model_id: str = Field(
        default="mistral",
        description="Model name to use (must be installed in Ollama)"
    )
    timeout: int = Field(
        default=120,
        ge=30,  # Min 30 seconds
        le=600,  # Max 10 minutes
        description="Timeout for LLM inference"
    )

    @validator('base_url')
    def validate_ollama_url(cls, v):
        """Validate Ollama URL is local (security)"""
        if 'localhost' not in v and '127.0.0.1' not in v:
            logger.warning(
                f"⚠️  Ollama URL is not localhost:  {v}. "
                "This may be a security risk."
            )
        return v


class DarkneyConfig(BaseModel):
    """Darknet monitoring configuration with validation"""
    enabled: bool = Field(
        default=False,
        description="Enable darknet monitoring"
    )
    tor_socks_port: int = Field(
        default=9050,
        ge=1024,  # Non-privileged port
        le=65535,
        description="Tor SOCKS5 proxy port"
    )
    tor_control_port: int = Field(
        default=9051,
        ge=1024,
        le=65535,
        description="Tor control port"
    )
    verify_tor: bool = Field(
        default=True,
        description="Verify Tor is running before starting"
    )

    @validator('enabled')
    def warn_darknet(cls, v):
        """Warn about darknet monitoring risks"""
        if v:
            logger.warning(
                "⚠️  ⚠️  DARKNET MONITORING ENABLED ⚠️  ⚠️\n"
                "    This feature requires:\n"
                "    1. Tor Browser running (ollama serve)\n"
                "    2. Legal authorization for your jurisdiction\n"
                "    3. VPN + additional anonymity measures recommended\n"
                "    4. Careful monitoring of accessed sites\n"
            )
        return v


class SecurityConfig(BaseModel):
    """Security and secrets configuration"""
    # Secret validation (never log these)
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub API token (keep secret!)"
    )
    api_secret_key: Optional[str] = Field(
        default=None,
        description="API secret key (keep secret!)"
    )

    # Security flags
    log_sensitive_data: bool = Field(
        default=False,
        description="Log CVE URLs, API responses, etc.  (SECURITY RISK! )"
    )
    validate_ssl: bool = Field(
        default=True,
        description="Validate SSL certificates"
    )
    require_authentication: bool = Field(
        default=True,
        description="Require auth for dashboard (recommended)"
    )


class AppConfig(BaseModel):
    """Main application configuration"""
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    darknet: DarkneyConfig = Field(default_factory=DarkneyConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    # Scheduler settings
    import_watch_directory: str = Field(
        default="./nist_imports",
        description="Directory to watch for JSON imports"
    )
    import_finished_directory: str = Field(
        default="./nist_imports/finished",
        description="Directory to move finished imports"
    )
    import_error_directory: str = Field(
        default="./nist_imports/errors",
        description="Directory to move failed imports"
    )

    # API settings
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000, ge=1024, le=65535)
    dashboard_host: str = Field(default="127.0.0.1")
    dashboard_port: int = Field(default=8050, ge=1024, le=65535)

    class Config:
        """Don't expose secrets in repr"""
        # Custom repr to hide secrets
        fields = {
            'github_token': {'exclude': True},
            'api_secret_key': {'exclude': True},
        }


# ==================== LOAD CONFIGURATION FROM ENV ====================

def load_config() -> AppConfig:
    """
    Load application configuration from environment variables.

    Safety features:
    - Validates all inputs with Pydantic
    - Warns about security risks
    - Uses safe defaults
    - Never logs sensitive data
    """

    logger.info("Loading application configuration...")

    try:
        config = AppConfig(
            database=DatabaseConfig(
                url=os.getenv(
                    "DATABASE_URL",
                    "postgresql://cve_user:password@localhost: 5432/cve_intelligence_db"
                ),
                pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
                max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
                echo=os.getenv("DB_ECHO", "false").lower() == "true"
            ),
            ollama=OllamaConfig(
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
                model_id=os.getenv("OLLAMA_MODEL", "mistral"),
                timeout=int(os.getenv("OLLAMA_TIMEOUT", "120"))
            ),
            darknet=DarkneyConfig(
                enabled=os.getenv("DARKNET_ENABLED", "false").lower() == "true",
                tor_socks_port=int(os.getenv("TOR_SOCKS_PORT", "9050")),
                tor_control_port=int(os.getenv("TOR_CONTROL_PORT", "9051")),
                verify_tor=os.getenv("TOR_VERIFY", "true").lower() == "true"
            ),
            security=SecurityConfig(
                github_token=os.getenv("GITHUB_TOKEN"),
                api_secret_key=os.getenv("API_SECRET_KEY"),
                log_sensitive_data=os.getenv("LOG_SENSITIVE", "false").lower() == "true",
                validate_ssl=os.getenv("VALIDATE_SSL", "true").lower() == "true",
                require_authentication=os.getenv("REQUIRE_AUTH", "true").lower() == "true"
            ),
            import_watch_directory=os.getenv("IMPORT_WATCH_DIR", "./nist_imports"),
            import_finished_directory=os.getenv("IMPORT_FINISHED_DIR", "./nist_imports/finished"),
            import_error_directory=os.getenv("IMPORT_ERROR_DIR", "./nist_imports/errors"),
            api_host=os.getenv("API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("API_PORT", "8000")),
            dashboard_host=os.getenv("DASH_HOST", "127.0.0.1"),
            dashboard_port=int(os.getenv("DASH_PORT", "8050")),
        )

        logger.info("✓ Configuration loaded successfully")
        logger.info(f"  Database: {config.database.url.split('@')[1] if '@' in config.database.url else 'hidden'}")
        logger.info(f"  Ollama Model: {config.ollama.model_id}")
        logger.info(f"  Darknet Enabled: {config.darknet.enabled}")
        logger.info(f"  Auth Required: {config.security.require_authentication}")

        return config

    except Exception as e:
        logger.error(f"✗ Configuration loading failed: {e}")
        logger.error("Please check your environment variables")
        raise


# Global config instance
CONFIG: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get global config (lazy load)"""
    global CONFIG
    if CONFIG is None:
        CONFIG = load_config()
    return CONFIG


# ==================== SECRETS MASKING ====================

class SecretString(str):
    """
    String subclass that never prints its value.
    Useful for passwords, tokens, etc.
    """

    def __repr__(self) -> str:
        return "***REDACTED***"

    def __str__(self) -> str:
        return "***REDACTED***"


def mask_sensitive_data(data: dict) -> dict:
    """
    Remove sensitive fields from dictionaries before logging.

    Args:
        data (dict): Data to sanitize

    Returns:
        dict:  Sanitized copy without secrets
    """
    sensitive_keys = {
        'password', 'token', 'secret', 'key', 'api_key',
        'github_token', 'auth', 'credential', 'Bearer'
    }

    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value

    return sanitized
