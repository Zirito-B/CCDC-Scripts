#!/bin/bash
set -u

# ==============================================================================
# CCDC 2026: ORACLE LINUX 9 + SPLUNK 10.x HARDENING PROTOCOL
# "GOD TIER" - NO GUI - CLI ONLY
# ==============================================================================
# FEATURES:
# 1. Oracle 9 Virtualization Fix (Prevents Console Blackout)
# 2. Splunk 10.x Identity Reset (user-seed.conf + passwd wipe)
# 3. Splunk App Execution Killswitch (commands.conf/limits.conf)
# 4. Immutable Persistence Locking (chattr +i)
# 5. Active Auditd Dashboard (Real-time Alerting)
# ==============================================================================

LOG="/root/ccdc_lockdown.log"
BACKUP_DIR="/root/panic_backups"
SPLUNK_HOME="/opt/splunk"
AUDIT_LOG="/var/log/audit/audit.log"

# ANSI Colors for the Dashboard
RED='\033${NC} $1" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
alert() { echo -e "${RED}[!!!]${NC} $1" | tee -a "$LOG"; }

if]; then
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
echo "   ORACLE 9 / SPLUNK 10 DEFENSE"
echo -e "${NC}"

# ==============================================================================
# 0. INPUTS & ANTI-LOCKOUT
# ==============================================================================
warn "Enter the SCORING/BLUE TEAM subnet (e.g., 172.20.240.0/24)."
warn "If you get this wrong, you block the scoring engine."
read -p "Subnet: " SCORING_SUBNET

echo ""
warn "Enter the NEW Splunk Admin Password."
read -s -p "Password: " SPLUNK_PASS
echo ""

# Get Current IP to prevent self-lockout
MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')
if]; then
    MY_IP="127.0.0.1" # Fallback if running from console
fi
log "Detected your IP as: $MY_IP. Whitelisting this IP to prevent lockout."

# ==============================================================================
# 1. PANIC BACKUPS
# ==============================================================================
log "Creating PANIC BACKUPS..."
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/etc_backup_$(date +%s).tar.gz" /etc/passwd /etc/shadow /etc/ssh /etc/sysconfig/iptables 2>/dev/null
if; then
    tar -czf "$BACKUP_DIR/splunk_etc_$(date +%s).tar.gz" "$SPLUNK_HOME/etc" 2>/dev/null
fi
log "Backups saved to $BACKUP_DIR."

# ==============================================================================
# 2. ORACLE LINUX 9 SPECIFIC HARDENING
# ==============================================================================
log "Applying Oracle Linux 9 Fixes..."

# FIX 1: Wayland Black Screen of Death
# Even if you don't use the GUI, if the system tries to boot GDM (default in OL9),
# it will hang in VMware/Proxmox. This forces X11, saving your console access.
if [ -f /etc/gdm/custom.conf ]; then
    sed -i 's/#WaylandEnable=false/WaylandEnable=false/' /etc/gdm/custom.conf
    # Ensure [daemon] block exists
    if! grep -q "WaylandEnable=false" /etc/gdm/custom.conf; then
        echo -e "[daemon]\nWaylandEnable=false" >> /etc/gdm/custom.conf
    fi
    log "Wayland disabled (Prevents Console Blackout)."
fi

# FIX 2: Kill Cockpit (Port 9090)
# Default on OL9. Web-based root shell. Red Team loves this.
systemctl stop cockpit.socket 2>/dev/null
systemctl disable cockpit.socket 2>/dev/null
log "Cockpit (9090) killed and disabled."

# FIX 3: Kernel Hardening (Sysctl)
cat > /etc/sysctl.d/99-ccdc-hardening.conf <<EOF
# Prevent IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable IP Forwarding (We are not a router)
net.ipv4.ip_forward = 0
# Restrict Kernel Logs (dmesg)
kernel.dmesg_restrict = 1
# Restrict BPF (Common exploit vector)
kernel.unprivileged_bpf_disabled = 1
EOF
sysctl -p /etc/sysctl.d/99-ccdc-hardening.conf >/dev/null
log "Kernel parameters hardened."

# ==============================================================================
# 3. SPLUNK 10.x "GOD TIER" HARDENING
# ==============================================================================
if; then
    log "Engaging Splunk Hardening Protocol..."
    
    # Stop Service for config surgery
    "$SPLUNK_HOME/bin/splunk" stop

    # 3.1: IDENTITY NUKE (User-Seed Method)
    # Delete the local passwd file. This removes ANY backdoor users created by Red Team.
    # Splunk 10.x will regenerate it from user-seed.conf.
    rm -f "$SPLUNK_HOME/etc/passwd"
    mkdir -p "$SPLUNK_HOME/etc/system/local"
    cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF
    log "Splunk local password file wiped and re-seeded."

    # 3.2: KILL WEB ATTACK VECTORS (web.conf)
    cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
httpport = 8000
startwebserver = 1
# Disable legacy insecure login (CVE vector)
enable_insecure_login = false
# Prevent Clickjacking
x_frame_options_sameorigin = true
# Disable Python execution via web (Hardens against Web Shells)
enable_python_endpoints = false
# Force HSTS
enableSplunkWebSSL = true
EOF

    # 3.3: DISABLE APP INSTALLS (limits.conf)
    # Critical for 10.x. Prevents uploading malicious apps via REST API.
    cat > "$SPLUNK_HOME/etc/system/local/limits.conf" <<EOF
[restapi]
enable_install_apps = false
EOF

    # 3.4: DISABLE 'runshellscript' (commands.conf & alert_actions.conf)
    # This kills the #1 Red Team persistence method in Splunk (Alert Scripts).
    cat > "$SPLUNK_HOME/etc/system/local/commands.conf" <<EOF
[runshellscript]
disabled = true
is_risky = true
EOF

    cat > "$SPLUNK_HOME/etc/system/local/alert_actions.conf" <<EOF
[script]
disabled = 1
EOF
    log "Splunk 'runshellscript' and Scripted Alerts DISABLED."

    # 3.5: APP SWEEP
    # Look for executable files inside app directories
    log "Sweeping apps for executables..."
    find "$SPLUNK_HOME/etc/apps" -name "*.sh" -o -name "*.py" -o -name "*.exe" > "$LOG.suspicious_apps"
    if [ -s "$LOG.suspicious_apps" ]; then
        alert "SUSPICIOUS EXECUTABLES FOUND IN SPLUNK APPS! (See $LOG.suspicious_apps)"
        # Optional: chmod them to non-executable
        # xargs -a "$LOG.suspicious_apps" chmod -x
    fi

    # Start Splunk
    "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt
else
    warn "Splunk directory not found. Skipping Splunk steps."
fi

# ==============================================================================
# 4. FIREWALL (NFTABLES via FIREWALLD)
# ==============================================================================
log "Configuring Firewalld (Drop-All Strategy)..."
systemctl enable --now firewalld

# Create a clean zone called 'ccdc'
firewall-cmd --permanent --new-zone=ccdc 2>/dev/null
firewall-cmd --permanent --zone=ccdc --set-target=DROP

# Allow SSH (You + Scoring)
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='22' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$MY_IP' port port='22' protocol='tcp' accept"

# Allow Splunk Web (8000) & Ingestion (9997) - SCORING ONLY
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='8000' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='9997' protocol='tcp' accept"

# Allow ICMP (Ping)
firewall-cmd --permanent --zone=ccdc --add-protocol=icmp

# BLOCK 8089 (Mgmt) to everyone except localhost
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='8089' protocol='tcp' accept"

# Apply to active interface
ACTIVE_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
firewall-cmd --permanent --zone=ccdc --change-interface="$ACTIVE_IF"
firewall-cmd --reload
log "Firewall locked down on interface $ACTIVE_IF."

# ==============================================================================
# 5. IMMUTABLE LOCKDOWN (THE "STAY OUT" PHASE)
# ==============================================================================
log "Applying Immutable Locks (Chattr)..."

# 5.1 SSH Keys
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys
# Ensure we are not locking ourselves out - verify key exists or file is empty
if [ -s /root/.ssh/authorized_keys ]; then
    log "Preserving existing root authorized_keys."
else
    warn "Root authorized_keys is empty. Ensure you have console access!"
fi
# Remove immutable if already set (to allow this script to run multiple times), then set it
chattr -i /root/.ssh/authorized_keys 2>/dev/null
chattr +i /root/.ssh/authorized_keys
chattr +i /root/.ssh
log "Root SSH keys are now IMMUTABLE (+i). Red Team cannot add keys."

# 5.2 Critical Configs
chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/gdm/custom.conf
log "System User Database (passwd/shadow) is now IMMUTABLE."

# ==============================================================================
# 6. ACTIVE MONITORING DASHBOARD (CLI)
# ==============================================================================
log "Configuring Auditd Rules..."
# Clear old rules
auditctl -D >/dev/null

# Watch for persistence
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_key_tamper
auditctl -w /etc/passwd -p wa -k user_tamper
auditctl -w /etc/shadow -p wa -k user_tamper
auditctl -w "$SPLUNK_HOME/etc/apps" -p wa -k splunk_app_tamper
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
echo "3. Splunk App Changes (Persistence)"
echo ""
echo "Press Ctrl+C to stop watching (Protection remains active)."
echo ""

# Real-time Log Watcher
# Filters for our specific audit keys and highlights them
tail -f "$AUDIT_LOG" | grep --line-buffered -E 'ssh_key_tamper|user_tamper|splunk_app_tamper|service_tamper|EXECVE' | while read line; do
    echo -e "${RED} $(date): $line${NC}"
done
