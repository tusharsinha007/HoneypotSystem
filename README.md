# 🍯 Honeypot_System — AI-Driven SSH Honeypot System

> **⚠️ For Research & Education Only** — See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md)

A complete, production-ready SSH honeypot that attracts real-world attackers, logs their behavior, uses AI/ML to classify attack patterns, and provides a real-time SOC-style monitoring dashboard — at **zero cost**.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🍯 **SSH Honeypot** | Paramiko-based server emulating OpenSSH 8.9p1 (Ubuntu) |
| 🖥️ **Virtual Filesystem** | 200+ fake files/dirs mimicking Ubuntu 22.04 |
| ⌨️ **Command Emulation** | 45+ Linux commands with realistic output |
| 🗄️ **SQLite Storage** | Thread-safe DB with ML-ready schema |
| 🤖 **ML Analysis** | K-Means clustering (scikit-learn) + rule-based detection |
| 🗺️ **Attack Map** | GeoIP world map with animated attack arcs (PyDeck) |
| 📊 **SOC Dashboard** | Real-time Streamlit dashboard with dark mode |
| 🐳 **Docker Support** | Multi-stage Dockerfile + Compose |
| ☁️ **Free Deployment** | Oracle Cloud Always Free Tier (forever free) |

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
# 1. Clone
git clone https://github.com/tusharsinha007/Honeypot_System.git
cd Honeypot_System

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate SSH host key
python generate_key.py

# 4. Generate training data & train ML model
python training/generate_dataset.py -n 1000
python training/train.py

# 5. Start the honeypot
python main.py
```

### Run the Dashboard

```bash
# In a separate terminal:
streamlit run dashboard/app.py
# Open: http://localhost:8501
```

### Simulate Attacks (for testing)

```bash
# While honeypot is running (default port 2222):
python simulate_attacker.py --profile all
```

---

## 🗂️ Project Structure

```
Honeypot_System/
├── main.py                    # Entry point
├── config.py                  # Central configuration
├── generate_key.py            # SSH host key generator
├── simulate_attacker.py       # Safe attack simulator
├── requirements.txt
│
├── honeypot/                  # SSH Engine (Paramiko)
│   ├── ssh_server.py          # SSH server + connection handling
│   ├── auth_handler.py        # Authentication logic
│   ├── session_handler.py     # Per-session management
│   └── command_processor.py   # 45+ command emulator
│
├── filesystem/                # Virtual Linux Filesystem
│   ├── vfs.py                 # In-memory tree
│   ├── fake_files.py          # Realistic file contents
│   └── fs_data.json           # Filesystem structure
│
├── database/                  # Data Layer (SQLite)
│   ├── db_manager.py          # Thread-safe operations
│   ├── schema.sql             # DB schema
│   └── queries.py             # Analytical queries
│
├── analysis/                  # AI/ML Module
│   ├── threat_detector.py     # Rule-based (50+ patterns)
│   ├── feature_extractor.py   # 15-feature ML vectors
│   ├── ml_analyzer.py         # K-Means clustering
│   └── report_generator.py    # Incident reports
│
├── training/                  # Model Pipeline
│   ├── generate_dataset.py    # Synthetic data (1000+ sessions)
│   ├── train.py               # Train K-Means model
│   └── ingest_data.py         # Import external data
│
├── dashboard/                 # Streamlit SOC UI
│   ├── app.py                 # Main dashboard
│   ├── pages/
│   │   ├── 01_live_monitor.py # Real-time feed
│   │   ├── 02_attack_map.py   # GeoIP world map
│   │   ├── 03_analytics.py    # Charts & trends
│   │   ├── 04_clusters.py     # ML visualization
│   │   └── 05_sessions.py     # Session explorer
│   └── styles/theme.css       # Dark mode theme
│
├── utils/                     # Shared Utilities
│   ├── geoip.py               # IP geolocation
│   ├── logger.py              # Colored logger
│   └── helpers.py             # Misc utilities
│
├── deploy/                    # Deployment
│   ├── setup.sh               # One-command VPS setup
│   ├── Dockerfile             # Multi-stage Docker
│   ├── docker-compose.yml     # Compose orchestration
│   ├── honeypot.service       # systemd unit
│   └── firewall_rules.sh      # iptables config
│
├── tests/                     # Unit Tests
│   ├── test_honeypot.py
│   ├── test_database.py
│   ├── test_vfs.py
│   └── test_ml.py
│
└── scripts/                   # Launchers
    ├── start_system.bat/.sh
    └── run_dashboard.bat/.sh
```

---

## ⚙️ Configuration

All settings in `config.py` can be overridden with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLMPOT_SSH_PORT` | `2222` | Honeypot SSH port |
| `LLMPOT_SSH_HOST` | `0.0.0.0` | Bind address |
| `LLMPOT_LOG_LEVEL` | `INFO` | Logging level |
| `LLMPOT_ML_CLUSTERS` | `4` | Number of K-Means clusters |
| `LLMPOT_DASHBOARD_PORT` | `8501` | Streamlit port |
| `LLMPOT_AUTH_ACCEPT_PROB` | `0.15` | Random auth acceptance rate |

---

## 🤖 ML Pipeline

### Attack Cluster Labels

| Cluster | Label | Description |
|---------|-------|-------------|
| 0 | `scout` | Quick recon — checks system info |
| 1 | `brute_forcer` | Mass credential stuffing |
| 2 | `malware_dropper` | Downloads/executes payloads |
| 3 | `data_exfiltrator` | Steals credentials/files |

### Feature Vector (15 features per session)

```
duration_seconds, command_count, unique_commands,
dangerous_cmd_count, dangerous_cmd_ratio, avg_cmd_interval,
has_download, has_recon, has_persistence, has_destruction,
has_reverse_shell, password_entropy, password_complexity,
auth_attempts_before_success, max_threat_score
```

### Retrain with New Data

```bash
# After accumulating real attack data:
python training/train.py --optimal-k

# Or import from external sources:
python training/ingest_data.py attacks.json --format json
```

---

## 🧪 Testing

```bash
pytest tests/ -v --tb=short
```

---

## ☁️ Production Deployment (Oracle Cloud Free Tier)

### Why Oracle Cloud?

| | Oracle Cloud | AWS Free | GCP Free |
|--|--|--|--|
| **Duration** | **♾️ Forever** | 12 months | 90 days |
| **RAM** | **24 GB** | 1 GB | 1 GB |
| **Storage** | **200 GB** | 30 GB | 30 GB |

### One-Command Deploy

```bash
# SSH into your Oracle Cloud VM
ssh ubuntu@<your-ip> -p 22

# Clone and run setup
git clone https://github.com/tusharsinha007/Honeypot_System.git
cd Honeypot_System
sudo ADMIN_IP=<your-home-ip>/32 bash deploy/setup.sh
```

This will:
1. Move real SSH to port `22222`
2. Bind honeypot to port `22` (the actual trap)
3. Train the ML model
4. Install systemd services for 24/7 operation
5. Configure firewall rules

### Docker Deployment

```bash
cd deploy
docker-compose up -d

# View logs
docker-compose logs -f honeypot
```

---

## 🗺️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         ATTACKER                            │
└──────────────────────────┬──────────────────────────────────┘
                           │ SSH (port 22/2222)
┌──────────────────────────▼──────────────────────────────────┐
│              SSH Honeypot Engine (Paramiko)                  │
│  ┌──────────────┐  ┌────────────┐  ┌──────────────────────┐ │
│  │ Auth Handler │  │ VFS Engine │  │  Command Processor   │ │
│  └──────┬───────┘  └─────┬──────┘  └──────────┬───────────┘ │
└─────────┼────────────────┼──────────────────────┼────────────┘
          │                │                      │
┌─────────▼────────────────▼──────────────────────▼────────────┐
│                    SQLite Database                            │
│  sessions │ commands │ auth_attempts │ ml_models │ reports    │
└──────────────────────────┬────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    AI/ML Pipeline                            │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Threat Detector │  │   Feature    │  │   K-Means ML   │  │
│  │  (50+ rules)    │  │  Extractor  │  │   Clustering   │  │
│  └────────┬────────┘  └──────┬───────┘  └───────┬────────┘  │
└───────────┼─────────────────┼──────────────────┼────────────┘
            │                 │                  │
┌───────────▼─────────────────▼──────────────────▼────────────┐
│                  Streamlit SOC Dashboard                      │
│  Live Monitor │ Attack Map │ Analytics │ Clusters │ Sessions  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Safety Features

- **No real shell access** — fully emulated environment
- **Outbound blocking** — firewall prevents honeypot weaponization
- **Rate limiting** — prevents DoS against the honeypot itself
- **Session duration limit** — auto-disconnect after 10 minutes
- **Systemd sandboxing** — `NoNewPrivileges`, `ProtectSystem`

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

## ⚠️ Disclaimer

See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) before deploying.
