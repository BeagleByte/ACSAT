"""
Job locking to prevent concurrent execution of the same job.

PREVENTS: Duplicate agent runs, race conditions, database conflicts
"""

import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


# ==================== IN-MEMORY JOB LOCKS ====================

class JobLockManager:
    """
    Manages job execution locks to prevent overlapping runs.

    If a job is already running, subsequent calls wait or are skipped.
    """

    def __init__(self):
        self.active_jobs = {}  # job_name -> (lock, started_at)
        self.lock = threading.Lock()

    def acquire_lock(self, job_name: str, timeout_seconds: int = 600) -> bool:
        """
        Try to acquire a lock for a job.

        Args:
            job_name (str): Name of the job
            timeout_seconds (int): Max seconds job should run

        Returns:
            bool: True if lock acquired, False if job already running
        """
        with self.lock:
            # Check if job is already running
            if job_name in self.active_jobs:
                job_lock, started_at = self.active_jobs[job_name]
                elapsed = (datetime.utcnow() - started_at).total_seconds()

                if elapsed > timeout_seconds:
                    logger.warning(
                        f"⚠️  Job '{job_name}' exceeded timeout ({elapsed:.0f}s > {timeout_seconds}s). "
                        f"Assuming it crashed.  Acquiring new lock."
                    )
                    # Force unlock (job probably crashed)
                    del self.active_jobs[job_name]
                else:
                    logger.warning(
                        f"⚠️  Job '{job_name}' is already running (started {elapsed:.0f}s ago). "
                        f"Skipping concurrent execution."
                    )
                    return False

            # Acquire lock
            job_lock = threading.Lock()
            self.active_jobs[job_name] = (job_lock, datetime.utcnow())
            logger.info(f"✓ Lock acquired for job: {job_name}")

            return True

    def release_lock(self, job_name: str):
        """Release a job lock"""
        with self.lock:
            if job_name in self.active_jobs:
                del self.active_jobs[job_name]
                logger.info(f"✓ Lock released for job: {job_name}")

    def is_running(self, job_name: str) -> bool:
        """Check if a job is currently running"""
        with self.lock:
            return job_name in self.active_jobs

    def get_running_jobs(self) -> list:
        """Get list of all currently running jobs"""
        with self.lock:
            return [
                {
                    "name": name,
                    "elapsed_seconds": (datetime.utcnow() - started_at).total_seconds()
                }
                for name, (_, started_at) in self.active_jobs.items()
            ]


# Global lock manager
_lock_manager = JobLockManager()


def get_lock_manager() -> JobLockManager:
    """Get global lock manager"""
    return _lock_manager


class JobLockContext:
    """
    Context manager for job locking.

    Usage:
        with JobLockContext("cve_agent", timeout=600):
            # Job code here
            ...

    Automatically acquires and releases lock.
    """

    def __init__(self, job_name: str, timeout_seconds: int = 600):
        self.job_name = job_name
        self.timeout_seconds = timeout_seconds
        self.lock_manager = get_lock_manager()
        self.acquired = False

    def __enter__(self):
        """Acquire lock on context entry"""
        self.acquired = self.lock_manager.acquire_lock(
            self.job_name,
            self.timeout_seconds
        )

        if not self.acquired:
            raise RuntimeError(
                f"Could not acquire lock for job '{self.job_name}'.  "
                f"Job is already running."
            )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release lock on context exit"""
        self.lock_manager.release_lock(self.job_name)

        if exc_type is not None:
            logger.error(
                f"Job '{self.job_name}' failed with exception:\n"
                f"  {exc_type.__name__}: {exc_val}"
            )

        return False  # Don't suppress exceptions