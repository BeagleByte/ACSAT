"""
Secure database connection manager with:
1. Connection pooling
2. Automatic cleanup (context manager)
3. Connection leak detection
4. Query logging/monitoring

PREVENTS:  SQL injection (via parameterization), connection leaks, cascading failures
"""

import logging
import threading
from contextlib import contextmanager
from typing import Generator, Optional
from datetime import datetime, timedelta
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool, QueuePool
from Database.DatabaseConfig import get_config
from sqlalchemy import text
logger = logging.getLogger(__name__)


# ==================== CONNECTION TRACKING ====================

class ConnectionTracker:
    """
    Track active database connections to detect leaks.

    If connections aren't closed properly, this will warn you.
    """

    def __init__(self):
        self.active_connections = {}  # Map of thread_id -> (session, timestamp)
        self.lock = threading.Lock()

    def register_connection(self, session: Session):
        """Register a new database connection"""
        thread_id = threading.get_ident()
        with self.lock:
            if thread_id in self.active_connections:
                logger.warning(
                    f"⚠️  Thread {thread_id} already has an active connection.  "
                    "This may cause issues."
                )
            self.active_connections[thread_id] = (session, datetime.utcnow())

    def unregister_connection(self, session: Session):
        """Unregister a closed database connection"""
        thread_id = threading.get_ident()
        with self.lock:
            if thread_id in self.active_connections:
                del self.active_connections[thread_id]

    def check_for_leaks(self, max_age_seconds: int = 300):
        """
        Check for connections held too long (possible leaks).

        Args:
            max_age_seconds (int): Warn if connection open longer than this
        """
        with self.lock:
            now = datetime.utcnow()
            for thread_id, (session, created_at) in self.active_connections.items():
                age = (now - created_at).total_seconds()
                if age > max_age_seconds:
                    logger.warning(
                        f"⚠️  POTENTIAL CONNECTION LEAK:\n"
                        f"    Thread ID: {thread_id}\n"
                        f"    Age: {age:.0f} seconds\n"
                        f"    Created: {created_at}\n"
                        f"    Please ensure db.close() or context managers are used!"
                    )


# ==================== GLOBAL CONNECTION MANAGER ====================

_engine = None
_SessionLocal = None
_connection_tracker = ConnectionTracker()


def init_db():
    """
    Initialize database engine and session factory.

    Called once at application startup.
    Uses connection pooling to reuse connections efficiently.
    """
    global _engine, _SessionLocal

    config = get_config()
    logger.info("Initializing database connection pool...")

    try:
        # Create engine with connection pooling
        _engine = create_engine(
            config.database.url,
            poolclass=QueuePool,  # Use connection pool (not NullPool!)
            pool_size=config.database.pool_size,  # Min 5, default 10
            max_overflow=config.database.max_overflow,  # Additional connections
            pool_pre_ping=True,  # Test connections before using (detect stale connections)
            pool_recycle=3600,  # Recycle connections after 1 hour
            echo=config.database.echo,  # Log SQL if enabled (SECURITY RISK!)
            connect_args={
                "connect_timeout": 10,  # Don't hang forever
                "application_name": "cve_intelligence",
            }
        )

        # Add event listener to detect connection issues
        @event.listens_for(_engine, "connect")
        def on_connect(dbapi_conn, connection_record):
            """Called when a connection is created"""
            logger.debug(f"✓ Database connection opened (pool size: {_engine.pool.size()})")

        @event.listens_for(_engine, "close")
        def on_close(dbapi_conn, connection_record):
            """Called when a connection is closed"""
            logger.debug(f"✓ Database connection closed")

        # Create session factory
        _SessionLocal = sessionmaker(
            bind=_engine,
            expire_on_commit=False,  # Prevent detached instance errors
            autoflush=False,  # Manual control over when flushes happen
            autocommit=False,  # Explicit transaction control
        )

        # Test connection
        with _SessionLocal() as db:
            db.execute(text("SELECT 1"))
            logger.info("✓ Database connection test successful")

        logger.info(f"✓ Database initialized with pool_size={config.database.pool_size}")

    except Exception as e:
        logger.error(f"✗ Database initialization failed: {e}")
        raise


def get_db() -> Generator[Session, None, None]:
    """
    Get a database session with automatic cleanup.

    IMPORTANT: Use this in a context manager (with statement)!

    Usage:
        with get_db() as db:
            result = db.query(CVE).first()
            # db automatically closed and cleaned up

    Raises:
        RuntimeError: If get_db() called before init_db()
    """
    if _SessionLocal is None:
        raise RuntimeError(
            "Database not initialized!  Call init_db() first."
        )

    # Create new session
    db = _SessionLocal()
    thread_id = threading.get_ident()

    try:
        # Track this connection
        _connection_tracker.register_connection(db)
        logger.debug(f"[Thread {thread_id}] Database session opened")

        yield db

        # Commit any pending changes
        db.commit()
        logger.debug(f"[Thread {thread_id}] Database session committed")

    except Exception as e:
        # Rollback on error
        db.rollback()
        logger.warning(f"[Thread {thread_id}] Database session rolled back due to error: {e}")
        raise

    finally:
        # ALWAYS close, even if exception occurred
        db.close()
        _connection_tracker.unregister_connection(db)
        logger.debug(f"[Thread {thread_id}] Database session closed")


def get_db_no_context() -> Session:
    """
    Get a database session WITHOUT automatic cleanup.

    WARNING: You must call db.close() manually!
    Prefer get_db() with context manager instead.

    Only use this if context manager isn't possible.
    """
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized! Call init_db() first.")

    db = _SessionLocal()
    _connection_tracker.register_connection(db)
    return db


def close_all_connections():
    """
    Close all database connections and cleanup.

    Called during application shutdown.
    """
    global _engine

    logger.info("Closing all database connections...")

    # Check for leaks
    _connection_tracker.check_for_leaks(max_age_seconds=60)

    if _engine:
        _engine.dispose()
        logger.info("✓ All database connections closed")


def get_connection_pool_status() -> dict:
    """Get current connection pool statistics"""
    if _engine is None:
        return {"status": "not initialized"}

    pool = _engine.pool
    return {
        "pool_size": pool.size(),
        "checked_out": pool.checkedout(),
        "overflow": getattr(pool, "overflow", "N/A"),
        "queue_size": getattr(pool, "queue", "N/A"),
    }