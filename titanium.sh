#!/bin/bash
# MWCCDC 2026 - TITANIUM HYBRID LOCKDOWN (Merged w/ Last Year's Logic)
# FEATURES: OS User Locking, Splunk Nuking, Wayland Fix, Auditd
# RUN AS ROOT

echo "!!! STARTING TITANIUM HYBRID PROTOCOL !!!"

# ==========================================
# 1. INTERACTIVE INPUT
# ==========================================
while true; do
    read -p "Enter Blue Team Subnet (e.g., 172.20.240.0/24): " BLUE_SUBNET
    if [[ "$BLUE_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then break; fi
done

while true; do
    echo ""; read -s -p "Enter NEW Splunk/Root Password: " ADMIN_PASS; echo ""
    read -s -p "Confirm Password: " ADMIN_PASS_CONFIRM; echo ""
    if [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ] && [ ! -z "$ADMIN_PASS" ]; then break; fi
    echo "Mismatch. Try again."
done

# ==========================================
# 2. OS HARDENING (FROM YOUR OLD SCRIPT)
# ==========================================
echo "[1] SETTING ROOT PASSWORD..."
echo "root:$ADMIN_PASS" | chpasswd

echo "[2] KILLING HOSTILE CONNECTIONS..."
pkill -9 -u $(who | awk '{print $1}' | grep -v "root" | grep -v "$(whoami)")

echo "[3] FLUSHING PERSISTENCE..."
echo "" > /etc/crontab
rm -rf /var/spool/cron/*
echo "" > /root/.ssh/authorized_keys
echo "" > /home/*/.ssh/authorized_keys 2>/dev/null

# ==========================================
# 3. SPLUNK NUCLEAR RESET (FROM YOUR OLD SCRIPT)
# ==========================================
SPLUNK_HOME="/opt/splunk"
echo "[4] STOPPING & CLEANING SPLUNK (FACTORY RESET)..."
$SPLUNK_HOME/bin/splunk stop
# This wipes ALL malicious apps/data Red Team might have hid
$SPLUNK_HOME/bin/splunk clean all -f

echo "[5] SEEDING ADMIN USER..."
mkdir -p $SPLUNK_HOME/etc/system/local
rm -f $SPLUNK_HOME/etc/passwd # Force reset
cat > $SPLUNK_HOME/etc/system/local/user-seed.conf <<EOF
[user_info]
USERNAME = admin
PASSWORD = $ADMIN_PASS
EOF

echo "[6] SECURING SPLUNK CONFIGS..."
# Web Hardening
cat > $SPLUNK_HOME/etc/system/local/web.conf <<EOF
[settings]
enableSplunkWebSSL = true
httpport = 8000
startwebserver = 1
enable_upload_apps = false
allow_remote_login = false
EOF
# Server Hardening
cat > $SPLUNK_HOME/etc/system/local/server.conf <<EOF
[general]
serverName = MWCCDC-Splunk
pass4SymmKey = changeme
[sslConfig]
enableSplunkdSSL = true
EOF

# ==========================================
# 4. IMMUTABILITY LOCK (THE "KEY" TO VICTORY)
# ==========================================
echo "[7] LOCKING SYSTEM ACCOUNTS (PREVENTS RED TEAM BACKDOOR USERS)..."
# This was in your old script - VERY GOOD MOVE.
chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /opt/splunk/etc/passwd
chattr +i $SPLUNK_HOME/etc/system/local/web.conf

# ==========================================
# 5. FIREWALL (WHITELIST MODE)
# ==========================================
echo "[8] CONFIGURING FIREWALL..."
systemctl enable --now firewalld
firewall-cmd --set-default-zone=drop
ACTIVE=$(ip route | grep default | awk '{print $5}')
firewall-cmd --zone=drop --change-interface=$ACTIVE
firewall-cmd --zone=drop --add-port=8000/tcp --permanent
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='9997' protocol='tcp' accept" --permanent
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='22' protocol='tcp' accept" --permanent
firewall-cmd --reload

# ==========================================
# 6. STARTUP & AUDIT
# ==========================================
echo "[9] STARTING SPLUNK..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --run-as-root

echo "[10] ENABLING AUDITD..."
auditctl -D
auditctl -a always,exit -F arch=b64 -S execve -k active_monitoring
auditctl -e 2

# ==========================================
# 7. GUI INSTALL (THE FIX FOR BLACK SCREEN)
# ==========================================
echo "[11] INSTALLING GUI (FIXED MODE)..."
# We do NOT run yum update. We ONLY install the GUI.
dnf config-manager --enable ol9_appstream ol9_baseos
dnf groupinstall -y "Server with GUI"

# THE DRIVER FIX (Prevents Black Screen)
echo "Disabling Wayland to prevent black screen..."
sed -i 's/#WaylandEnable=false/WaylandEnable=false/' /etc/gdm/custom.conf

systemctl set-default graphical.target

echo "!!! DONE. REBOOT MANUALLY ONLY WHEN DNF FINISHES !!!"
