#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# LLMPot — One-Command VPS Setup Script
# Deploys the SSH honeypot on Ubuntu 22.04+ (Oracle Cloud / AWS / GCP)
# ═══════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║            🍯 LLMPot Setup Script                ║"
echo "║       AI-Driven SSH Honeypot Deployment          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root (sudo)${NC}"
    exit 1
fi

# ─── Legal Disclaimer ────────────────────────────────────────────────────────
echo -e "${YELLOW}"
echo "⚠️  LEGAL DISCLAIMER"
echo "═══════════════════════════════════════════════════════"
echo "This system is designed to ATTRACT ATTACKERS."
echo "By proceeding, you acknowledge:"
echo "  1. You have authorization to deploy this on this host"
echo "  2. You understand the risks of running a honeypot"
echo "  3. You will not use captured data for illegal purposes"
echo "  4. You will comply with all applicable laws"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"
read -p "Do you accept? (yes/no): " ACCEPT
if [ "$ACCEPT" != "yes" ]; then
    echo "Setup cancelled."
    exit 0
fi

# ─── Variables ─────────────────────────────────────────────────────────────────
HONEYPOT_USER="honeypot"
HONEYPOT_DIR="/opt/llmpot"
REAL_SSH_PORT=22222
HONEYPOT_SSH_PORT=22
DASHBOARD_PORT=8501
ADMIN_IP="${ADMIN_IP:-0.0.0.0/0}"  # Set your IP for management

echo -e "${CYAN}[*] Step 1: System Update${NC}"
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv git ufw fail2ban

echo -e "${CYAN}[*] Step 2: Move real SSH to port ${REAL_SSH_PORT}${NC}"

echo -e "${YELLOW}⚠️  AZURE WARNING ⚠️${NC}"
echo -e "If you are deploying on Microsoft Azure, you MUST open port ${REAL_SSH_PORT}"
echo -e "in your Network Security Group (NSG) via the Azure Portal BEFORE proceeding."
echo -e "Otherwise, you will lock yourself out of this VM!"
read -p "Have you updated your Azure NSG or are you not using Azure? (yes/no): " NSG_ACCEPT
if [ "$NSG_ACCEPT" != "yes" ]; then
    echo "Setup cancelled. Please update your NSG rules and try again."
    exit 0
fi

# Backup sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Change SSH port
sed -i "s/^#*Port .*/Port ${REAL_SSH_PORT}/" /etc/ssh/sshd_config
systemctl restart sshd
echo -e "${GREEN}[✓] Real SSH moved to port ${REAL_SSH_PORT}${NC}"

echo -e "${CYAN}[*] Step 3: Create honeypot user${NC}"
if ! id "$HONEYPOT_USER" &>/dev/null; then
    useradd -r -m -s /bin/bash "$HONEYPOT_USER"
    echo -e "${GREEN}[✓] User '${HONEYPOT_USER}' created${NC}"
else
    echo -e "${YELLOW}[*] User '${HONEYPOT_USER}' already exists${NC}"
fi

echo -e "${CYAN}[*] Step 4: Install LLMPot${NC}"
mkdir -p "$HONEYPOT_DIR"

# Copy files (assumes running from project directory)
if [ -f "main.py" ]; then
    cp -r . "$HONEYPOT_DIR/"
else
    echo -e "${YELLOW}[*] Cloning from git...${NC}"
    git clone https://github.com/tusharsinha007/Honeypot_System.git "$HONEYPOT_DIR" || {
        echo -e "${RED}[!] Failed to clone. Copy files manually to ${HONEYPOT_DIR}${NC}"
        exit 1
    }
fi

chown -R "$HONEYPOT_USER":"$HONEYPOT_USER" "$HONEYPOT_DIR"

echo -e "${CYAN}[*] Step 5: Python environment setup${NC}"
cd "$HONEYPOT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}[✓] Dependencies installed${NC}"

echo -e "${CYAN}[*] Step 6: Generate host key${NC}"
sudo -u "$HONEYPOT_USER" bash -c "cd ${HONEYPOT_DIR} && source venv/bin/activate && python generate_key.py"

echo -e "${CYAN}[*] Step 7: Initialize database & generate training data${NC}"
sudo -u "$HONEYPOT_USER" bash -c "cd ${HONEYPOT_DIR} && source venv/bin/activate && python training/generate_dataset.py -n 1000"
sudo -u "$HONEYPOT_USER" bash -c "cd ${HONEYPOT_DIR} && source venv/bin/activate && python training/train.py"
echo -e "${GREEN}[✓] ML model trained${NC}"

echo -e "${CYAN}[*] Step 8: Configure firewall${NC}"
# Reset UFW
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Azure Agent Compatibility
ufw allow from 168.63.129.16 to any comment 'Azure Agent'
ufw allow to 168.63.129.16 comment 'Azure Agent'

# Allow management SSH
ufw allow "${REAL_SSH_PORT}/tcp"

# Allow honeypot SSH (from anywhere — this is the trap)
ufw allow "${HONEYPOT_SSH_PORT}/tcp"

# Allow dashboard (restrict to admin IP in production)
ufw allow "${DASHBOARD_PORT}/tcp"

# Enable
ufw --force enable
echo -e "${GREEN}[✓] Firewall configured${NC}"

echo -e "${CYAN}[*] Step 9: Install systemd services${NC}"

# Honeypot service
cat > /etc/systemd/system/llmpot.service << EOF
[Unit]
Description=LLMPot SSH Honeypot
After=network.target

[Service]
Type=simple
User=${HONEYPOT_USER}
WorkingDirectory=${HONEYPOT_DIR}
Environment="LLMPOT_SSH_PORT=${HONEYPOT_SSH_PORT}"
ExecStart=${HONEYPOT_DIR}/venv/bin/python main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${HONEYPOT_DIR}/data ${HONEYPOT_DIR}/logs ${HONEYPOT_DIR}/models
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Dashboard service
cat > /etc/systemd/system/llmpot-dashboard.service << EOF
[Unit]
Description=LLMPot Dashboard
After=network.target llmpot.service

[Service]
Type=simple
User=${HONEYPOT_USER}
WorkingDirectory=${HONEYPOT_DIR}
ExecStart=${HONEYPOT_DIR}/venv/bin/streamlit run dashboard/app.py --server.port=${DASHBOARD_PORT} --server.headless=true --server.address=0.0.0.0
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Allow honeypot to bind to port 22 (needs CAP_NET_BIND_SERVICE)
setcap 'cap_net_bind_service=+ep' "${HONEYPOT_DIR}/venv/bin/python3" 2>/dev/null || true

systemctl daemon-reload
systemctl enable llmpot llmpot-dashboard
systemctl start llmpot
systemctl start llmpot-dashboard

echo -e "${GREEN}[✓] Services installed and started${NC}"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  🍯 LLMPot Installation Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  📡 Honeypot SSH:    Port ${HONEYPOT_SSH_PORT} (public)"
echo -e "  🔒 Management SSH:  Port ${REAL_SSH_PORT}"
echo -e "  📊 Dashboard:        http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
echo ""
echo -e "  Manage services:"
echo -e "    sudo systemctl status llmpot"
echo -e "    sudo systemctl status llmpot-dashboard"
echo -e "    sudo journalctl -u llmpot -f"
echo ""
echo -e "${YELLOW}  ⚠️ Remember to update ADMIN_IP for firewall security${NC}"
echo ""
