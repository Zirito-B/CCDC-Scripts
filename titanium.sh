#!/bin/bash
set -u

LOG="/var/log/ccdc_lockdown.log"
SPLUNK_HOME="/opt/splunk"
BACKUP_DIR="/boot/.recovery_$(date +%s)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG"; }
alert() { echo -e "${RED}[!!!]${NC} $1" | tee -a "$LOG"; }

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

warn "Enter SCORING Subnet (e.g., 172.20.240.0/24):"
read -p "Subnet: " SCORING_SUBNET

echo ""
warn "Enter NEW Splunk Admin Password:"
read -s -p "Password: " SPLUNK_PASS
echo ""

MY_IP=$(echo $SSH_CLIENT | awk '{print $1}')
[ -z "$MY_IP" ] && MY_IP="127.0.0.1"
log "Whitelisting Admin IP: $MY_IP"

log "Unlocking any existing immutable files..."
chattr -i "$SPLUNK_HOME/etc/passwd" 2>/dev/null
chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null
chattr -i "$SPLUNK_HOME/etc/system/local/user-seed.conf" 2>/dev/null

log "Stopping Splunk..."
"$SPLUNK_HOME/bin/splunk" stop >/dev/null 2>&1

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/os_critical.tar.gz" /etc/passwd /etc/shadow /etc/ssh 2>/dev/null

if [ -d "$SPLUNK_HOME/etc" ]; then
    tar -czf "$BACKUP_DIR/splunk_config.tar.gz" "$SPLUNK_HOME/etc/system/local" 2>/dev/null
fi

chattr +i "$BACKUP_DIR/os_critical.tar.gz"
log "Backups hidden in $BACKUP_DIR and LOCKED."

log "Applying Splunk Configurations..."

rm -f "$SPLUNK_HOME/etc/passwd"
mkdir -p "$SPLUNK_HOME/etc/system/local"

cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $SPLUNK_PASS
EOF

cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
httpport = 8000
startwebserver = 1
enableSplunkWebSSL = true
enable_upload_apps = false
enable_insecure_login = false
enable_python_endpoints = false
tools.sessions.timeout = 5
x_frame_options_sameorigin = true
EOF

cat > "$SPLUNK_HOME/etc/system/local/limits.conf" <<EOF
[restapi]
enable_install_apps = false
EOF

cat > "$SPLUNK_HOME/etc/system/local/commands.conf" <<EOF
[runshellscript]
disabled = true
is_risky = true
EOF

log "Nuking Persistence..."
systemctl stop crond
rm -rf /var/spool/cron/*
rm -rf /etc/cron.d/*

systemctl list-timers --all | grep -v "systemd" | awk '{print $NF}' | while read timer; do
    [ ! -z "$timer" ] && systemctl mask "$timer" 2>/dev/null
done

systemctl disable --now cockpit.socket 2>/dev/null

log "Applying Firewall Rules..."
systemctl enable --now firewalld
firewall-cmd --permanent --new-zone=ccdc 2>/dev/null
firewall-cmd --permanent --zone=ccdc --set-target=DROP

[ "$MY_IP" != "127.0.0.1" ] && firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$MY_IP' port port='22' protocol='tcp' accept"

firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='22' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='8000' protocol='tcp' accept"
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='$SCORING_SUBNET' port port='9997' protocol='tcp' accept"

firewall-cmd --permanent --zone=ccdc --add-protocol=icmp
firewall-cmd --permanent --zone=ccdc --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='8089' protocol='tcp' accept"

ACTIVE_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
firewall-cmd --permanent --zone=ccdc --change-interface="$ACTIVE_IF"
firewall-cmd --reload

log "Starting Splunk..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt

log "Waiting 15 seconds for Splunk to initialize and seed password..."
sleep 15

log "Applying FINAL IMMUTABLE LOCKS..."
chattr +i "$SPLUNK_HOME/etc/system/local/web.conf"
chattr +i "$SPLUNK_HOME/etc/system/local/limits.conf"
chattr +i "$SPLUNK_HOME/etc/system/local/commands.conf"
chattr +i /etc/shadow
chattr +i /etc/passwd

echo ""
echo -e "${GREEN}TITANIUM PROTOCOL COMPLETE.${NC}"
echo "----------------------------------------------------"
echo "VERIFY ACCESS:"
echo "1. On your laptop, run:"
echo -e "   ${YELLOW}curl -k -v https://<VM_IP>:8000${NC}"
echo ""
echo "2. Login with user: admin"
echo "   Password: [The one you entered]"
echo "----------------------------------------------------"
