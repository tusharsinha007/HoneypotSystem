#!/usr/bin/env python3
"""
LLMPot — Main Entry Point
Starts the SSH honeypot server with graceful shutdown.
"""

import signal
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

from config import SSH_HOST, SSH_PORT
from honeypot.ssh_server import SSHHoneypotServer
from database.db_manager import DatabaseManager
from utils.logger import get_logger

logger = get_logger("main")


def main():
    """Start the LLMPot SSH honeypot."""
    print(r"""
    ╔══════════════════════════════════════════════╗
    ║            🍯 LLMPot v1.0                    ║
    ║      AI-Driven SSH Honeypot System           ║
    ║                                              ║
    ║  ⚠️  FOR RESEARCH & EDUCATION ONLY           ║
    ╚══════════════════════════════════════════════╝
    """)

    # Initialize database
    logger.info("Initializing database...")
    db = DatabaseManager()
    session_count = db.get_session_count()
    logger.info(f"Database ready. Existing sessions: {session_count}")

    # Create SSH server
    server = SSHHoneypotServer(host=SSH_HOST, port=SSH_PORT)

    # Graceful shutdown handler
    def shutdown_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Start server
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        server.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        server.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
