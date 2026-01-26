#!/bin/bash
set -u

# ==============================================================================
# CCDC 2026: ORACLE LINUX 9 + SPLUNK 9.1.1 "TITANIUM v3"
# STATUS: STABLE | SSL: ON | CRASH FIX: APPLIED
# ==============================================================================

LOG="/var/log/ccdc_lockdown.log"
SPLUNK_HOME="/opt/splunk"
BACKUP_DIR="/boot/.recovery_$(date +%s)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
alert() { echo -e "${RED}[!!!]${NC} $1" | tee -a "$LOG"; }

# Root Check
if [ "$EUID" -ne 0 ]; then echo "[-] Run as root."; exit 1; fi

echo -e "${GREEN}"
echo "   ██████╗ ██╗██████╗ ███████╗"
echo "   ██╔══██╗██║██╔══██╗██╔════╝"
echo "   ██████╔╝██║██████╔╝█████╗  "
echo "   ██╔══██╗██║██╔══██╗██╔══╝  "
echo "   ██║  ██║██║██║  ██║███████╗"
echo "   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
echo "   TITANIUM v3 - STABILIZED"
echo -e "${NC}"

# ==============================================================================
# 0. INPUTS & SAFETY CHECKS
# ==============================================================================
warn "Enter SCORING Subnet (e.g., 172.20.240.0/24):"
read -p "Subnet: " SCORING_SUBNET

echo ""
warn "Enter NEW Splunk Admin Password:"
read -s -p "Password: " SPLUNK_PASS
echo ""

# Detect YOUR IP to prevent firewall lockout
MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')
[ -z "$MY_IP" ] && MY_IP="127.0.0.1"
log "Whitelisting Admin IP: $MY_IP"

# ==============================================================================
# 1. UNLOCK & CLEANUP (Fixing Previous Runs)
# ==============================================================================
log "Unlocking any existing immutable files..."
chattr -i "$SPLUNK_HOME/etc/passwd" 2>/dev/null
chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null
chattr -i "$SPLUNK_HOME/etc/system/local/user-seed.conf" 2>/dev/null

log "Stopping Splunk..."
"$SPLUNK_HOME/bin/splunk" stop >/dev/null 2>&1

# ==============================================================================
# 2. STEALTH BACKUPS
# ==============================================================================
mkdir -p "$BACKUP_DIR"
# Backup critical OS files (Hidden in /boot)
tar -czf "$BACKUP_DIR/os_critical.tar.gz" /etc/passwd /etc/shadow /etc/ssh 2>/dev/null
# Backup Splunk Configs
if [ -d "$SPLUNK_HOME/etc" ]; then
    tar -czf "$BACKUP_DIR/splunk_config.tar.gz" "$SPLUNK_HOME/etc/system/local" 2>/dev/null
fi
# Lock the backups so Red Team can't delete them
chattr +i "$BACKUP_DIR/os_critical.tar.gz"
log "Backups hidden in $BACKUP_DIR and LOCKED."

# ==============================================================================
# 3. SPLUNK CONFIGURATION (The Fortress)
# ==============================================================================
log "Applying Splunk Configurations..."

# 3.1: IDENTITY RESET
# We remove the old password file so Splunk assumes it's a fresh install
rm -f "$SPLUNK_HOME/etc/passwd"
mkdir -p "$SPLUNK_HOME/etc/system/local"

# Create Seed File (Splunk reads this on startup to create the new password)
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF

# 3.2: WEB HARDENING (SSL ENABLED)
cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
httpport = 8000
startwebserver = 1
# FORCE HTTPS (This is why your curl http:// failed)
enableSplunkWebSSL = true
# DISABLING ATTACK VECTORS
enable_upload_apps = false
enable_insecure_login = false
enable_python_endpoints = false
tools.sessions.timeout = 5
x_frame_options_sameorigin = true
EOF

# 3.3: API & RCE BLOCKING
cat > "$SPLUNK_HOME/etc/system/local/limits.conf" <<EOF
[restapi]
enable_install_apps = false
EOF

cat > "$SPLUNK_HOME/etc/system/local/commands.conf" <<EOF
[runshellscript]
disabled = true
is_risky = true
EOF

# ==============================================================================
# 4. OS & PERSISTENCE HARDENING
# ==============================================================================
log "Nuking Persistence..."
# Wipe Cron & At
systemctl stop crond
rm -rf /var/spool/cron/*
rm -rf /etc/cron.d/*
# Wipe Systemd Timers (The modern cron)
systemctl list-timers --all | grep -v "systemd" | awk '{print $NF}' | while read timer; do
    [ ! -z "$timer" ] && systemctl mask "$timer" 2>/dev/null
done
# Kill Cockpit (Web Console on 9090)
systemctl disable --now cockpit.socket 2>/dev/null

# ==============================================================================
# 5. FIREWALL (STRICT WHITELIST)
# ==============================================================================
log "Applying Firewall Rules..."
systemctl enable --now firewalld
firewall-cmd --permanent --new-zone=ccdc 2>/dev/null
firewall-cmd --permanent --zone=ccdc --set-target=DROP

# Allow Admin IP (SSH)
[ "$MY_IP" != "127.0.0.1" ] && firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$MY_IP' port port='22' protocol='tcp' accept"
# Allow Scoring (SSH, Splunk Web, Splunk Data)
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='22' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='8000' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='9997' protocol='tcp' accept"
# Allow Ping
firewall-cmd --permanent --zone=ccdc --add-protocol=icmp
# Block 8089 (Mgmt) to Localhost Only
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='8089' protocol='tcp' accept"

# Apply
ACTIVE_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
firewall-cmd --permanent --zone=ccdc --change-interface="$ACTIVE_IF"
firewall-cmd --reload

# ==============================================================================
# 6. STARTUP & DELAYED LOCKING (CRITICAL FIX)
# ==============================================================================
log "Starting Splunk..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt

log "Waiting 15 seconds for Splunk to initialize and seed password..."
# CRITICAL: We wait for Splunk to read user-seed.conf and write to passwd BEFORE locking.
sleep 15

log "Applying FINAL IMMUTABLE LOCKS..."
# Now that Splunk is running, we lock the config files so Red Team can't edit them.
chattr +i "$SPLUNK_HOME/etc/system/local/web.conf"
chattr +i "$SPLUNK_HOME/etc/system/local/limits.conf"
chattr +i "$SPLUNK_HOME/etc/system/local/commands.conf"
# We do NOT lock passwd inside Splunk to prevent database corruption,
# but we DO lock the OS shadow file.
chattr +i /etc/shadow
chattr +i /etc/passwd

echo ""
echo -e "${GREEN}TITANIUM PROTOCOL COMPLETE.${NC}"
echo "----------------------------------------------------"
echo "VERIFY ACCESS:"
echo "1. On your laptop, run:"
echo -e "   ${YELLOW}curl -k -v https://<VM_IP>:8000${NC}"
echo "   (You MUST use https:// and -k for self-signed certs)"
echo ""
echo "2. Login with user: admin"
echo "   Password: [The one you entered]"
echo "----------------------------------------------------"
