#!/bin/bash

set -e

echo "=== CVE Intelligence System Startup ==="

# Activate virtualenv
source .venv/bin/activate

# Set environment
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

# Start PostgreSQL (if needed)
sudo systemctl start postgresql

# Start Redis (if using Celery)
# redis-server --daemonize yes

# Run database migrations (if using Alembic)
# alembic upgrade head

# Start the system (API + Scheduler + Dashboard)
python main.py
