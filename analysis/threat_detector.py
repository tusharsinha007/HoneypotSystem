"""
LLMPot — Threat Detector
Rule-based detection engine for known attack patterns.
"""

import re
from typing import Optional


# ─── Threat Rules ─────────────────────────────────────────────────────────────
# Each rule: (pattern, category, severity, score, description)

THREAT_RULES = [
    # ── Critical (score 90-100) ──
    (r"rm\s+(-rf|-fr|--no-preserve-root)\s+/", "destruction", "critical", 100,
     "Recursive deletion of root filesystem"),
    (r"rm\s+-rf\s+", "destruction", "critical", 95,
     "Recursive forced deletion"),
    (r"dd\s+if=/dev/(zero|random|urandom)\s+of=/dev/sd", "destruction", "critical", 100,
     "Disk overwrite"),
    (r"mkfs\.", "destruction", "critical", 100,
     "Filesystem format"),
    (r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;\s*:", "destruction", "critical", 100,
     "Fork bomb"),
    (r"echo\s+.*/etc/passwd", "privilege_escalation", "critical", 90,
     "Passwd file modification"),
    (r"echo\s+.*/etc/shadow", "privilege_escalation", "critical", 95,
     "Shadow file modification"),

    # ── High (score 70-89) ──
    (r"wget\s+http", "malware_download", "high", 85,
     "File download via wget"),
    (r"curl\s+(-O|-o|http)", "malware_download", "high", 80,
     "File download via curl"),
    (r"tftp\s+", "malware_download", "high", 85,
     "TFTP file transfer"),
    (r"chmod\s+(\+x|777|755)\s+", "persistence", "high", 75,
     "Making file executable"),
    (r"chmod\s+u\+s\s+", "privilege_escalation", "high", 85,
     "Setting SUID bit"),
    (r"useradd\s+", "persistence", "high", 80,
     "Creating new user account"),
    (r"usermod\s+", "persistence", "high", 75,
     "Modifying user account"),
    (r"crontab\s+(-e|-r)", "persistence", "high", 80,
     "Modifying cron jobs"),
    (r"echo\s+.*>>\s*/etc/crontab", "persistence", "high", 85,
     "Appending to system crontab"),
    (r"/tmp/\S+\s*;\s*chmod", "malware_execution", "high", 85,
     "Execute from /tmp after chmod"),
    (r"nohup\s+", "persistence", "high", 70,
     "Running persistent process"),
    (r"\./\S+", "malware_execution", "high", 75,
     "Executing local file"),
    (r"python\s+-c\s+", "malware_execution", "high", 75,
     "Python one-liner execution"),
    (r"perl\s+-e\s+", "malware_execution", "high", 75,
     "Perl one-liner execution"),
    (r"bash\s+-i\s+", "reverse_shell", "high", 90,
     "Interactive bash (possible reverse shell)"),
    (r"/dev/tcp/", "reverse_shell", "high", 95,
     "Bash reverse shell via /dev/tcp"),
    (r"nc\s+(-e|-c)", "reverse_shell", "high", 90,
     "Netcat reverse shell"),

    # ── Medium (score 40-69) ──
    (r"cat\s+/etc/shadow", "reconnaissance", "medium", 65,
     "Reading shadow file"),
    (r"cat\s+/etc/passwd", "reconnaissance", "medium", 50,
     "Reading passwd file"),
    (r"cat\s+/etc/ssh", "reconnaissance", "medium", 55,
     "Reading SSH config"),
    (r"cat\s+/proc/", "reconnaissance", "medium", 40,
     "Reading proc filesystem"),
    (r"find\s+.*-perm", "reconnaissance", "medium", 55,
     "Searching for files by permission"),
    (r"find\s+.*-name\s+.*\.conf", "reconnaissance", "medium", 50,
     "Searching for config files"),
    (r"find\s+.*-name\s+.*\.key", "reconnaissance", "medium", 60,
     "Searching for key files"),
    (r"netstat\s+", "reconnaissance", "medium", 45,
     "Network connection enumeration"),
    (r"ss\s+-", "reconnaissance", "medium", 45,
     "Socket enumeration"),
    (r"iptables\s+", "reconnaissance", "medium", 50,
     "Firewall rule enumeration"),
    (r"history", "reconnaissance", "medium", 40,
     "Command history access"),
    (r"last\s+", "reconnaissance", "medium", 40,
     "Login history check"),
    (r"who\s+", "reconnaissance", "medium", 35,
     "Current user check"),
    (r"lsof\s+", "reconnaissance", "medium", 45,
     "Open file enumeration"),

    # ── Low (score 10-39) ──
    (r"uname\s+-a", "fingerprinting", "low", 20,
     "System fingerprinting"),
    (r"uname\s+-r", "fingerprinting", "low", 15,
     "Kernel version check"),
    (r"whoami", "fingerprinting", "low", 10,
     "User identity check"),
    (r"^id$", "fingerprinting", "low", 10,
     "User ID check"),
    (r"hostname", "fingerprinting", "low", 10,
     "Hostname check"),
    (r"uptime", "fingerprinting", "low", 10,
     "Uptime check"),
    (r"df\s+", "fingerprinting", "low", 15,
     "Disk usage check"),
    (r"free\s+", "fingerprinting", "low", 15,
     "Memory usage check"),
    (r"ls\s+", "exploration", "low", 10,
     "Directory listing"),
    (r"pwd", "exploration", "low", 5,
     "Current directory check"),
    (r"cd\s+", "exploration", "low", 5,
     "Directory navigation"),
]


class ThreatDetector:
    """Rule-based threat detection engine."""

    def __init__(self):
        # Pre-compile all regexes
        self._rules = [
            (re.compile(pattern, re.IGNORECASE), category, severity, score, desc)
            for pattern, category, severity, score, desc in THREAT_RULES
        ]

    def analyze_command(self, command: str) -> dict:
        """
        Analyze a single command for threats.
        
        Returns:
            {
                "command": str,
                "is_dangerous": bool,
                "category": str | None,
                "severity": str,
                "score": int,
                "description": str,
                "matched_rules": list
            }
        """
        if not command:
            return self._safe_result(command)

        matched_rules = []
        max_score = 0
        top_category = None
        top_severity = "safe"
        top_description = ""

        for regex, category, severity, score, desc in self._rules:
            if regex.search(command):
                matched_rules.append({
                    "category": category,
                    "severity": severity,
                    "score": score,
                    "description": desc,
                })
                if score > max_score:
                    max_score = score
                    top_category = category
                    top_severity = severity
                    top_description = desc

        return {
            "command": command,
            "is_dangerous": max_score >= 40,
            "category": top_category,
            "severity": top_severity,
            "score": max_score,
            "description": top_description,
            "matched_rules": matched_rules,
        }

    def analyze_session_commands(self, commands: list) -> dict:
        """
        Analyze all commands from a session.
        
        Returns aggregate threat assessment.
        """
        results = [self.analyze_command(cmd) for cmd in commands]
        dangerous_count = sum(1 for r in results if r["is_dangerous"])
        max_score = max((r["score"] for r in results), default=0)
        categories = list(set(
            r["category"] for r in results if r["category"]
        ))

        # Overall threat level
        if max_score >= 90:
            threat_level = "critical"
        elif max_score >= 70:
            threat_level = "high"
        elif max_score >= 40:
            threat_level = "medium"
        elif max_score >= 10:
            threat_level = "low"
        else:
            threat_level = "safe"

        return {
            "total_commands": len(commands),
            "dangerous_commands": dangerous_count,
            "max_threat_score": max_score,
            "threat_level": threat_level,
            "categories": categories,
            "command_results": results,
        }

    @staticmethod
    def _safe_result(command: str) -> dict:
        return {
            "command": command,
            "is_dangerous": False,
            "category": None,
            "severity": "safe",
            "score": 0,
            "description": "",
            "matched_rules": [],
        }
