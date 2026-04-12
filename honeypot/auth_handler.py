"""
LLMPot — Authentication Handler
Manages SSH authentication with configurable credential acceptance.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import ACCEPTED_CREDENTIALS, AUTH_ACCEPT_PROBABILITY
from utils.logger import get_logger

logger = get_logger("auth")


class AuthHandler:
    """Handles SSH authentication attempts for the honeypot."""

    def __init__(self):
        self.attempt_counts = {}  # IP -> count (for rate limiting)

    def check_credentials(self, username: str, password: str, ip: str) -> bool:
        """
        Check if credentials should be accepted.
        
        Returns True if:
        - Username/password matches known weak credentials
        - Random acceptance with configured probability
        """
        # Track attempts per IP
        self.attempt_counts[ip] = self.attempt_counts.get(ip, 0) + 1
        attempt_num = self.attempt_counts[ip]

        # Log every attempt
        logger.info(
            f"Auth attempt #{attempt_num} from {ip}: "
            f"user='{username}' pass='{password}'"
        )

        # Check against known credentials
        if username in ACCEPTED_CREDENTIALS:
            if password in ACCEPTED_CREDENTIALS[username]:
                logger.warning(
                    f"✓ ACCEPTED known credentials from {ip}: "
                    f"{username}/{password}"
                )
                return True

        # Random acceptance to trap more diverse attackers
        # Higher chance after more attempts (reward persistence)
        adjusted_prob = min(AUTH_ACCEPT_PROBABILITY * (1 + attempt_num * 0.05), 0.4)
        if random.random() < adjusted_prob:
            logger.warning(
                f"✓ ACCEPTED (random) credentials from {ip}: "
                f"{username}/{password} (prob={adjusted_prob:.2f})"
            )
            return True

        logger.info(f"✗ Rejected credentials from {ip}: {username}/{password}")
        return False

    def reset_attempts(self, ip: str):
        """Reset attempt counter for an IP after successful auth."""
        self.attempt_counts.pop(ip, None)

    def get_attempt_count(self, ip: str) -> int:
        """Get number of auth attempts from an IP."""
        return self.attempt_counts.get(ip, 0)
