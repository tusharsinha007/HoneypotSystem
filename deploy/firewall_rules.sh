#!/bin/bash
# ═══════════════════════════════════════════════════
# LLMPot — Firewall Rules
# iptables configuration for honeypot isolation
# ═══════════════════════════════════════════════════

set -e

HONEYPOT_PORT=${1:-22}
MGMT_PORT=${2:-22222}
DASHBOARD_PORT=${3:-8501}
ADMIN_IP=${4:-"0.0.0.0/0"}

echo "[*] Configuring iptables firewall rules..."

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Azure Agent Compatibility
iptables -A INPUT -s 168.63.129.16 -j ACCEPT
iptables -A OUTPUT -d 168.63.129.16 -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow management SSH (restricted to admin IP)
iptables -A INPUT -p tcp --dport "$MGMT_PORT" -s "$ADMIN_IP" -j ACCEPT

# Allow honeypot SSH (open to the world — this is the trap)
iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT

# Rate limit honeypot connections (max 10 new connections per minute per IP)
iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -m conntrack --ctstate NEW \
    -m recent --set --name HONEYPOT
iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 10 --name HONEYPOT -j DROP

# Allow dashboard (restricted to admin IP)
iptables -A INPUT -p tcp --dport "$DASHBOARD_PORT" -s "$ADMIN_IP" -j ACCEPT

# Allow ICMP (ping) — helps attract scanners
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Block outbound connections from honeypot user (prevent weaponization)
# This prevents the honeypot from being used to attack other systems
iptables -A OUTPUT -m owner --uid-owner honeypot -p tcp --dport 22 -j DROP
iptables -A OUTPUT -m owner --uid-owner honeypot -p tcp --dport 80 -j DROP
iptables -A OUTPUT -m owner --uid-owner honeypot -p tcp --dport 443 -j DROP

# Allow DNS resolution for GeoIP lookups
iptables -A OUTPUT -m owner --uid-owner honeypot -p udp --dport 53 -j ACCEPT
# Allow ip-api.com lookups (port 80 specifically to ip-api.com)
iptables -A OUTPUT -m owner --uid-owner honeypot -p tcp --dport 80 -d 208.95.112.1 -j ACCEPT

# Log dropped packets (optional, can fill logs rapidly)
# iptables -A INPUT -j LOG --log-prefix "LLMPOT-DROP: " --log-level 4

echo "[✓] Firewall rules applied"
echo ""
echo "  Honeypot port: ${HONEYPOT_PORT} (open to world)"
echo "  Management:    ${MGMT_PORT} (admin only)"
echo "  Dashboard:     ${DASHBOARD_PORT} (admin only)"
echo ""

# Save rules (requires iptables-persistent)
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
    echo "[✓] Rules saved persistently"
fi
