#!/bin/bash
set -u

# ==============================================================================
# CCDC 2026: ORACLE LINUX 9 + SPLUNK 9.1.1 DEFENSE
# STRICT CLI MODE - NO GUI - NO WAYLAND
# ==============================================================================

LOG="/root/ccdc_lockdown.log"
BACKUP_DIR="/root/panic_backups"
SPLUNK_HOME="/opt/splunk"
AUDIT_LOG="/var/log/audit/audit.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper Functions
log() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
alert() { echo -e "${RED}[!!!]${NC} $1" | tee -a "$LOG"; }

# 1. ROOT CHECK
if [ "$EUID" -ne 0 ]; then
   echo "[-] This script must be run as root." 
   exit 1
fi

echo -e "${RED}"
echo "   ██████╗ ██╗██████╗ ███████╗"
echo "   ██╔══██╗██║██╔══██╗██╔════╝"
echo "   ██████╔╝██║██████╔╝█████╗  "
echo "   ██╔══██╗██║██╔══██╗██╔══╝  "
echo "   ██║  ██║██║██║  ██║███████╗"
echo "   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
echo "   PURE CLI DEFENSE PROTOCOL"
echo -e "${NC}"

# ==============================================================================
# 0. INPUTS & ANTI-LOCKOUT
# ==============================================================================
warn "Enter the SCORING/BLUE TEAM subnet (e.g., 172.20.240.0/24)."
read -p "Subnet: " SCORING_SUBNET

echo ""
warn "Enter the NEW Splunk Admin Password."
read -s -p "Password: " SPLUNK_PASS
echo ""

# Get Current IP to prevent self-lockout
MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')
if [ -z "$MY_IP" ]; then
    MY_IP="127.0.0.1" # Fallback if running from console
fi
log "Detected your IP as: $MY_IP. Whitelisting to prevent lockout."

# ==============================================================================
# 1. PANIC BACKUPS
# ==============================================================================
log "Creating PANIC BACKUPS..."
mkdir -p "$BACKUP_DIR"
# Backup critical OS files
tar -czf "$BACKUP_DIR/os_backup_$(date +%s).tar.gz" /etc/passwd /etc/shadow /etc/ssh /etc/sysconfig/iptables 2>/dev/null
# Backup Splunk configs (just in case)
if [ -d "$SPLUNK_HOME/etc" ]; then
    tar -czf "$BACKUP_DIR/splunk_etc_$(date +%s).tar.gz" "$SPLUNK_HOME/etc" 2>/dev/null
fi
log "Backups saved to $BACKUP_DIR."

# ==============================================================================
# 2. OS HARDENING (CLI ONLY)
# ==============================================================================
log "Applying OS Hardening..."

# FIX 1: Kill Cockpit (Port 9090)
# This is the web-admin console installed by default on OL9. 
systemctl stop cockpit.socket 2>/dev/null
systemctl disable cockpit.socket 2>/dev/null
log "Cockpit (9090) killed and disabled."

# FIX 2: Kernel Hardening (Sysctl)
cat > /etc/sysctl.d/99-ccdc-hardening.conf <<EOF
# Prevent IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable IP Forwarding (We are not a router)
net.ipv4.ip_forward = 0
# Restrict Kernel Logs
kernel.dmesg_restrict = 1
# Restrict BPF
kernel.unprivileged_bpf_disabled = 1
EOF
sysctl -p /etc/sysctl.d/99-ccdc-hardening.conf >/dev/null
log "Kernel parameters hardened."

# ==============================================================================
# 3. SPLUNK 9.1.1 HARDENING
# ==============================================================================
if [ -d "$SPLUNK_HOME" ]; then
    log "Engaging Splunk Hardening Protocol..."
    
    # Stop Service for config surgery
    "$SPLUNK_HOME/bin/splunk" stop

    # 3.1: IDENTITY NUKE (User-Seed Method)
    # Deleting passwd forces Splunk to read user-seed.conf on next boot
    rm -f "$SPLUNK_HOME/etc/passwd"
    mkdir -p "$SPLUNK_HOME/etc/system/local"
    
    cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF
    log "Splunk local password file wiped and re-seeded."

    # 3.2: WEB.CONF HARDENING
    cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
httpport = 8000
startwebserver = 1
# Disable legacy insecure login (CVE vector)
enable_insecure_login = false
# Disable Python execution via web (Hardens against Web Shells)
enable_python_endpoints = false
# Force HSTS
enableSplunkWebSSL = true
EOF

    # 3.3: DISABLE APP INSTALLS (limits.conf)
    cat > "$SPLUNK_HOME/etc/system/local/limits.conf" <<EOF
[restapi]
enable_install_apps = false
EOF

    # 3.4: DISABLE 'runshellscript' (commands.conf)
    # CRITICAL FOR 9.1.1 - This kills the #1 Red Team persistence method
    cat > "$SPLUNK_HOME/etc/system/local/commands.conf" <<EOF
[runshellscript]
disabled = true
is_risky = true
EOF

    # 3.5: DISABLE ALERT SCRIPTS (alert_actions.conf)
    cat > "$SPLUNK_HOME/etc/system/local/alert_actions.conf" <<EOF
[script]
disabled = 1
EOF
    log "Splunk 'runshellscript' and Scripted Alerts DISABLED."

    # Start Splunk
    "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
else
    warn "Splunk directory not found at $SPLUNK_HOME. Skipping Splunk steps."
fi

# ==============================================================================
# 4. FIREWALL (FIREWALLD / NFTABLES)
# ==============================================================================
log "Configuring Firewalld (Drop-All Strategy)..."
# Ensure firewalld is running
systemctl enable --now firewalld

# Create a clean zone called 'ccdc'
firewall-cmd --permanent --new-zone=ccdc 2>/dev/null
firewall-cmd --permanent --zone=ccdc --set-target=DROP

# Allow SSH (You + Scoring)
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='22' protocol='tcp' accept"
# Allow YOUR IP specifically (Anti-Lockout)
if [ "$MY_IP" != "127.0.0.1" ]; then
    firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$MY_IP' port port='22' protocol='tcp' accept"
fi

# Allow Splunk Web (8000) & Ingestion (9997) - SCORING ONLY
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='8000' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='9997' protocol='tcp' accept"

# Allow ICMP (Ping)
firewall-cmd --permanent --zone=ccdc --add-protocol=icmp

# BLOCK 8089 (Mgmt) to everyone except localhost
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='8089' protocol='tcp' accept"

# Apply to active interface
# Get default interface
ACTIVE_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
if [ ! -z "$ACTIVE_IF" ]; then
    firewall-cmd --permanent --zone=ccdc --change-interface="$ACTIVE_IF"
    firewall-cmd --reload
    log "Firewall locked down on interface $ACTIVE_IF."
else
    warn "Could not detect active interface. Check firewall settings manually."
fi

# ==============================================================================
# 5. IMMUTABLE LOCKDOWN
# ==============================================================================
log "Applying Immutable Locks (Chattr)..."

# 5.1 SSH Keys
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys

# Unlock first to ensure we can edit
chattr -i /root/.ssh/authorized_keys 2>/dev/null

# If file is empty, warn. If not, lock it.
if [ ! -s /root/.ssh/authorized_keys ]; then
    warn "Root authorized_keys is empty. Make sure you have console access just in case."
fi
chattr +i /root/.ssh/authorized_keys
chattr +i /root/.ssh
log "Root SSH keys are now IMMUTABLE (+i)."

# 5.2 Critical Configs
chattr +i /etc/passwd
chattr +i /etc/shadow
log "System User Database is now IMMUTABLE."

# ==============================================================================
# 6. ACTIVE MONITORING DASHBOARD
# ==============================================================================
log "Configuring Auditd Rules..."
# Clear old rules
auditctl -D >/dev/null

# Watch for persistence
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_key_tamper
auditctl -w /etc/passwd -p wa -k user_tamper
auditctl -w /etc/shadow -p wa -k user_tamper
if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    auditctl -w "$SPLUNK_HOME/etc/apps" -p wa -k splunk_app_tamper
fi
auditctl -w /etc/systemd/system -p wa -k service_tamper

# Lock Auditd Configuration (Requires reboot to disable)
auditctl -e 2

echo ""
echo -e "${YELLOW}============================================================${NC}"
echo -e "${YELLOW}   LOCKDOWN COMPLETE. MONITORING MODE ENGAGED.${NC}"
echo -e "${YELLOW}============================================================${NC}"
echo "Watching for:"
echo "1. SSH Key Modifications"
echo "2. User/Password Changes"
echo "3. Splunk App Changes"
echo ""
echo "Press Ctrl+C to stop watching (Protection remains active)."
echo ""

# Create log file if it doesn't exist
touch "$AUDIT_LOG"

# Real-time Log Watcher
tail -f "$AUDIT_LOG" | grep --line-buffered -E 'ssh_key_tamper|user_tamper|splunk_app_tamper|service_tamper|EXECVE'
