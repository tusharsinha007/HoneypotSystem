"""
LLMPot — Session Handler
Manages post-authentication interactive shell sessions.
"""

import time
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import MAX_SESSION_DURATION, FAKE_HOSTNAME, FAKE_OS_RELEASE, FAKE_KERNEL
from filesystem.vfs import VirtualFilesystem
from honeypot.command_processor import CommandProcessor
from database.db_manager import DatabaseManager
from analysis.threat_detector import ThreatDetector
from utils.logger import get_logger

logger = get_logger("session")


class SessionHandler:
    """Handles an authenticated SSH session with command processing."""

    def __init__(self, session_id: str, username: str, attacker_ip: str):
        self.session_id = session_id
        self.username = username
        self.attacker_ip = attacker_ip
        self.vfs = VirtualFilesystem()
        self.cmd_processor = CommandProcessor(self.vfs, username)
        self.db = DatabaseManager()
        self.threat_detector = ThreatDetector()
        self.command_count = 0
        self.start_time = time.time()
        self._active = True

        # Set initial directory based on user
        if username == "root":
            self.vfs.chdir("/root")
        else:
            home = f"/home/{username}"
            if self.vfs.exists(home):
                self.vfs.chdir(home)
            else:
                self.vfs.chdir("/tmp")

    def get_motd(self) -> str:
        """Return the Message of the Day banner."""
        return (
            f"\r\nWelcome to {FAKE_OS_RELEASE} (GNU/Linux {FAKE_KERNEL} x86_64)\r\n"
            f"\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f" * Support:        https://ubuntu.com/advantage\r\n"
            f"\r\n"
            f"  System information as of {time.strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
            f"\r\n"
            f"  System load:  0.08              Processes:             127\r\n"
            f"  Usage of /:   27.1% of 46.95GB  Users logged in:       0\r\n"
            f"  Memory usage: 21%               IPv4 address for eth0: 10.0.0.2\r\n"
            f"  Swap usage:   0%\r\n"
            f"\r\n"
            f" * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s\r\n"
            f"   just raised the bar for easy, resilient and secure K8s cluster deployment.\r\n"
            f"\r\n"
            f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 192.168.1.100\r\n"
        )

    def get_prompt(self) -> str:
        """Return current shell prompt."""
        return self.cmd_processor.get_prompt()

    def handle_command(self, command_line: str) -> tuple:
        """
        Process a command from the attacker.
        
        Returns: (output: str, should_exit: bool)
        """
        if not self._active:
            return "", True

        # Check session duration
        elapsed = time.time() - self.start_time
        if elapsed > MAX_SESSION_DURATION:
            logger.warning(
                f"Session {self.session_id} exceeded max duration "
                f"({MAX_SESSION_DURATION}s) — disconnecting"
            )
            self._active = False
            return "\r\nConnection timed out.\r\n", True

        # Process the command
        self.command_count += 1
        output, should_exit = self.cmd_processor.process(command_line)

        # Analyze threat level
        threat_result = self.threat_detector.analyze_command(command_line)

        # Log to database
        try:
            self.db.log_command(
                session_id=self.session_id,
                command=command_line,
                output=output[:500] if output else "",
                is_dangerous=threat_result["is_dangerous"],
                threat_category=threat_result.get("category"),
            )
        except Exception as e:
            logger.error(f"Failed to log command: {e}")

        if threat_result["is_dangerous"]:
            logger.warning(
                f"⚠ DANGEROUS command in session {self.session_id}: "
                f"'{command_line}' [{threat_result['category']}] "
                f"(score: {threat_result['score']})"
            )

        if should_exit:
            self._active = False

        return output, should_exit

    def end_session(self):
        """Clean up session and update database."""
        self._active = False
        try:
            self.db.end_session(self.session_id, self.command_count)
            elapsed = time.time() - self.start_time
            logger.info(
                f"Session ended: {self.session_id} | "
                f"IP: {self.attacker_ip} | "
                f"Commands: {self.command_count} | "
                f"Duration: {elapsed:.1f}s"
            )
        except Exception as e:
            logger.error(f"Failed to end session: {e}")

    @property
    def is_active(self) -> bool:
        return self._active
