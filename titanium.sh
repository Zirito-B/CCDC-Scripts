#!/bin/bash
# MWCCDC 2026 - TITANIUM LOCKDOWN (INTERACTIVE MODE)
# RUN AS ROOT

echo "!!! STARTING TITANIUM LOCKDOWN PROTOCOL !!!"

# ==========================================
# 1. INTERACTIVE INPUT (NO HARDCODING)
# ==========================================

# 1. Get Subnet
while true; do
    read -p "Enter your Blue Team Subnet (e.g., 172.20.240.0/24): " BLUE_SUBNET
    if [[ "$BLUE_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        break
    else
        echo "[!] Invalid CIDR format. Please try again."
    fi
done

# 2. Get Password (Hidden & Verified)
while true; do
    echo ""
    read -s -p "Enter NEW Splunk Admin Password: " ADMIN_PASS
    echo ""
    read -s -p "Confirm Password: " ADMIN_PASS_CONFIRM
    echo ""
    
    if [ -z "$ADMIN_PASS" ]; then
        echo "[!] Password cannot be empty."
    elif [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
        echo "[!] Passwords do not match! Try again."
    else
        echo "[+] Password confirmed."
        break
    fi
done

echo "----------------------------------------------------"
echo "Subnet:   $BLUE_SUBNET"
echo "Password: [HIDDEN]"
echo "----------------------------------------------------"
read -p "Press [Enter] to BEGIN LOCKDOWN or Ctrl+C to abort..."

# ==========================================
# 2. SCORCHED EARTH
# ==========================================
echo "[1] KILLING HOSTILE CONNECTIONS..."
pkill -9 -u $(who | awk '{print $1}' | grep -v "root" | grep -v "$(whoami)")

echo "[2] FLUSHING PERSISTENCE..."
systemctl stop crond; systemctl mask crond
rm -rf /var/spool/cron/*
systemctl stop atd; systemctl mask atd

echo "[3] WIPING SSH KEYS..."
echo > /root/.ssh/authorized_keys
echo > /home/*/.ssh/authorized_keys 2>/dev/null

# ==========================================
# 3. SPLUNK HARDENING
# ==========================================
SPLUNK_HOME="/opt/splunk"

echo "[4] STOPPING SPLUNK SERVICE..."
$SPLUNK_HOME/bin/splunk stop

echo "[5] APPLYING SPLUNK CONFIGURATION..."
mkdir -p $SPLUNK_HOME/etc/system/local

# Nuke old password file if exists (Anti-Race Condition)
rm -f $SPLUNK_HOME/etc/passwd

# User Seeding
cat > $SPLUNK_HOME/etc/system/local/user-seed.conf <<EOF
[user_info]
USERNAME = admin
PASSWORD = $ADMIN_PASS
EOF

# Web Hardening
cat > $SPLUNK_HOME/etc/system/local/web.conf <<EOF
[settings]
enableSplunkWebSSL = true
httpport = 8000
startwebserver = 1
# Security Kill Switches
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

echo "[6] LOCKING FILES (IMMUTABLE)..."
# Unlock first just in case
chattr -i $SPLUNK_HOME/etc/system/local/web.conf 2>/dev/null
chattr -i $SPLUNK_HOME/etc/system/local/user-seed.conf 2>/dev/null

# Lock
chattr +i $SPLUNK_HOME/etc/system/local/web.conf
chattr +i $SPLUNK_HOME/etc/system/local/user-seed.conf

# ==========================================
# 4. FIREWALL DOMINANCE
# ==========================================
echo "[7] CONFIGURING FIREWALL..."
systemctl enable --now firewalld
firewall-cmd --reload
firewall-cmd --set-default-zone=drop
ACTIVE_IFACE=$(ip route | grep default | awk '{print $5}')
firewall-cmd --zone=drop --change-interface=$ACTIVE_IFACE

# ALLOW SCORING (World Open)
firewall-cmd --zone=drop --add-port=8000/tcp --permanent
# ALLOW INTERNAL
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='9997' protocol='tcp' accept" --permanent
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='514' protocol='udp' accept" --permanent
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='22' protocol='tcp' accept" --permanent
# ALLOW LOCAL MGMT
firewall-cmd --zone=drop --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='8089' protocol='tcp' accept" --permanent

firewall-cmd --reload

# ==========================================
# 5. RESTART & AUDIT
# ==========================================
echo "[8] RESTARTING SPLUNK..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --run-as-root

echo "[9] ENABLING AUDIT LOGGING..."
systemctl enable auditd --now
auditctl -D
auditctl -a always,exit -F arch=b64 -S execve -k active_monitoring
auditctl -a always,exit -F arch=b32 -S execve -k active_monitoring
auditctl -e 2

echo "[10] INSTALLING GUI (BACKGROUND)..."
(
    dnf config-manager --enable ol9_appstream ol9_baseos
    dnf groupinstall -y "Server with GUI"
    systemctl set-default graphical.target
    systemctl isolate graphical.target
) &

echo "!!! LOCKDOWN COMPLETE !!!"
echo "Admin Password set. GUI installing in background."