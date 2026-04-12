"""
LLMPot — Helper Utilities
Miscellaneous shared functions.
"""

import uuid
import hashlib
import math
import string
from datetime import datetime


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return str(uuid.uuid4())


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def password_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password string."""
    if not password:
        return 0.0
    char_counts = {}
    for c in password:
        char_counts[c] = char_counts.get(c, 0) + 1
    length = len(password)
    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def password_complexity_score(password: str) -> int:
    """Score password complexity from 0-10."""
    if not password:
        return 0
    score = 0
    if len(password) >= 4:
        score += 1
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 2
    entropy = password_entropy(password)
    if entropy > 2.5:
        score += 1
    if entropy > 3.5:
        score += 1
    return min(score, 10)


def sanitize_command(command: str) -> str:
    """Sanitize command string for logging (remove control chars)."""
    return "".join(c for c in command if c.isprintable() or c in ("\n", "\t"))


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def hash_ip(ip: str) -> str:
    """Create a pseudonymized hash of an IP (for privacy)."""
    return hashlib.sha256(ip.encode()).hexdigest()[:12]


def get_timestamp() -> str:
    """Get current UTC timestamp as ISO string."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
