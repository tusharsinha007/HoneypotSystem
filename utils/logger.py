"""
LLMPot — Structured Logger
Consistent logging with file rotation and colored console output.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Add parent to path for config import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import LOG_LEVEL, LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for console."""

    COLORS = {
        "DEBUG": Fore.CYAN if HAS_COLORAMA else "",
        "INFO": Fore.GREEN if HAS_COLORAMA else "",
        "WARNING": Fore.YELLOW if HAS_COLORAMA else "",
        "ERROR": Fore.RED if HAS_COLORAMA else "",
        "CRITICAL": Fore.RED + Style.BRIGHT if HAS_COLORAMA else "",
    }
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


_loggers = {}


def get_logger(name: str = "llmpot") -> logging.Logger:
    """Get or create a named logger with console + file handlers."""
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    logger.propagate = False

    if not logger.handlers:
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_fmt = ColoredFormatter(
            "%(asctime)s | %(levelname)-18s | %(name)-12s | %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_fmt)
        logger.addHandler(console_handler)

        # File handler with rotation
        try:
            Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create file handler: {e}")

    _loggers[name] = logger
    return logger
