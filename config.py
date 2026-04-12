"""
LLMPot — Central Configuration
All settings with environment variable overrides.
"""

import os
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
MODEL_DIR = BASE_DIR / "models"
KEY_DIR = BASE_DIR / "keys"

# Create directories on import
for d in (DATA_DIR, LOG_DIR, MODEL_DIR, KEY_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ─── SSH Honeypot ─────────────────────────────────────────────────────────────
SSH_HOST = os.getenv("LLMPOT_SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.getenv("LLMPOT_SSH_PORT", "2222"))
SSH_HOST_KEY_FILE = str(KEY_DIR / "host_key")
SSH_BANNER = os.getenv(
    "LLMPOT_SSH_BANNER",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
)

# Max concurrent connections
MAX_CONNECTIONS = int(os.getenv("LLMPOT_MAX_CONNECTIONS", "50"))
# Max session duration (seconds) — auto-disconnect after this
MAX_SESSION_DURATION = int(os.getenv("LLMPOT_MAX_SESSION_DURATION", "600"))
# Connection timeout (seconds)
CONNECTION_TIMEOUT = int(os.getenv("LLMPOT_CONNECTION_TIMEOUT", "300"))

# ─── Authentication ──────────────────────────────────────────────────────────
# Credentials the honeypot will accept (username: password list)
ACCEPTED_CREDENTIALS = {
    "root": ["root", "toor", "password", "123456", "admin", "pass123"],
    "admin": ["admin", "password", "123456", "admin123"],
    "user": ["user", "password", "123456"],
    "ubuntu": ["ubuntu", "password"],
    "test": ["test", "test123"],
    "guest": ["guest", "guest123"],
}

# Probability of accepting an unknown credential (to trap more attackers)
AUTH_ACCEPT_PROBABILITY = float(os.getenv("LLMPOT_AUTH_ACCEPT_PROB", "0.15"))

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH = str(DATA_DIR / os.getenv("LLMPOT_DB_NAME", "honeypot.db"))

# ─── GeoIP ────────────────────────────────────────────────────────────────────
GEOIP_API_URL = os.getenv("LLMPOT_GEOIP_API", "http://ip-api.com/json/")
GEOIP_RATE_LIMIT = int(os.getenv("LLMPOT_GEOIP_RATE_LIMIT", "40"))  # req/min
GEOIP_CACHE_TTL = int(os.getenv("LLMPOT_GEOIP_CACHE_TTL", "86400"))  # 24h

# ─── AI/ML ────────────────────────────────────────────────────────────────────
ML_MODEL_PATH = str(MODEL_DIR / "kmeans_model.joblib")
ML_SCALER_PATH = str(MODEL_DIR / "feature_scaler.joblib")
ML_NUM_CLUSTERS = int(os.getenv("LLMPOT_ML_CLUSTERS", "4"))
ML_RETRAIN_THRESHOLD = int(os.getenv("LLMPOT_ML_RETRAIN_THRESHOLD", "100"))
ML_MIN_SAMPLES = int(os.getenv("LLMPOT_ML_MIN_SAMPLES", "20"))

# Cluster label mapping
CLUSTER_LABELS = {
    0: "scout",
    1: "brute_forcer",
    2: "malware_dropper",
    3: "data_exfiltrator",
}

# ─── Dashboard ────────────────────────────────────────────────────────────────
DASHBOARD_HOST = os.getenv("LLMPOT_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("LLMPOT_DASHBOARD_PORT", "8501"))
DASHBOARD_REFRESH_INTERVAL = int(os.getenv("LLMPOT_DASHBOARD_REFRESH", "10"))

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LLMPOT_LOG_LEVEL", "INFO")
LOG_FILE = str(LOG_DIR / "honeypot.log")
LOG_MAX_BYTES = int(os.getenv("LLMPOT_LOG_MAX_BYTES", "10485760"))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("LLMPOT_LOG_BACKUP_COUNT", "5"))

# ─── Simulated System Identity ───────────────────────────────────────────────
FAKE_HOSTNAME = os.getenv("LLMPOT_HOSTNAME", "ubuntu-server")
FAKE_OS_RELEASE = "Ubuntu 22.04.3 LTS"
FAKE_KERNEL = "5.15.0-91-generic"
FAKE_ARCH = "x86_64"
FAKE_UPTIME_DAYS = 47
FAKE_IP_ADDRESS = "10.0.0.2"
FAKE_MAC_ADDRESS = "02:42:ac:11:00:02"
