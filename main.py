"""
Main entry point:  start API server and scheduler with local Ollama model.
No API costs, everything runs locally!
"""
import logging
import os
import sys
import asyncio
import threading
import time
from dotenv import load_dotenv
from uvicorn import Config, Server
from app.Scheduler import TaskScheduler
from app.API import app as api_app
from Database.database import init_db

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_api_server():
    """Run FastAPI server in a thread"""
    config = Config(
        app=api_app,
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        log_level="info"
    )
    server = Server(config)
    asyncio.run(server.serve())

if __name__ == "__main__":
    logger.info("Starting CVE Intelligence System with LOCAL Ollama Models...")

    # Which Ollama model to use
    # Options: mistral, llama2, neural-chat, orca-mini, etc.
    model_name = os.getenv("OLLAMA_MODEL", "mistral")
    logger.info(f"Using Ollama model: {model_name}")

    # Check if Ollama is running
    try:
        import httpx
        response = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            logger.info("✓ Ollama is running and accessible")
        else:
            logger.warning("⚠ Ollama responded but with non-200 status")
    except Exception as e:
        logger.error(f"✗ Ollama not accessible at localhost:11434")
        logger.error(f"  Make sure to run:  ollama serve")
        logger.error(f"  Error: {e}")
        sys.exit(1)

    # Initialize database
    init_db()
    logger.info("✓ Database initialized")

    # Start task scheduler with Ollama model
    scheduler = TaskScheduler(model_name=model_name)
    scheduler.start()
    logger.info("✓ Task scheduler started")

    # Start FastAPI server
    api_thread = threading.Thread(target=run_api_server, daemon=False)
    api_thread.start()
    logger.info("✓ API server started (http://0.0.0.0:8000)")

    logger.info("\n" + "="*60)
    logger.info("CVE Intelligence System is running!")
    logger.info("="*60)
    logger.info(f"API Docs:        http://localhost:8000/docs")
    logger.info(f"Dashboard:      http://localhost:8050")
    logger.info(f"Ollama Model:   {model_name}")
    logger.info("="*60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.stop()
        sys.exit(0)