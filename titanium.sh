#!/bin/bash
# TITANIUM ULTRA - Red Team Resistant Splunk Hardening
# ZERO HARDCODED SECRETS - Everything prompted interactively

set -euo pipefail
IFS=$'\n\t'

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG_FILE="/root/titanium_ultra_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/splunk_fortress_backup_$(date +%Y%m%d_%H%M%S)"

# ====================================================================
# INTERACTIVE CONFIGURATION
# ====================================================================
clear
echo "========================================="
echo "   TITANIUM ULTRA - CONFIGURATION"
echo "========================================="
echo ""
echo "Red Team can see GitHub scripts."
echo "We need to collect sensitive info interactively."
echo ""
echo "Press ENTER after each response."
echo "Passwords will NOT be visible as you type."
echo ""
read -p "Press ENTER to continue..."
echo ""

# ====================================================================
# 1. COLLECT PASSWORDS
# ====================================================================
echo "=== STEP 1: PASSWORDS ==="
echo ""

# Root password
while true; do
    read -sp "New ROOT password: " NEW_ROOT_PASS
    echo ""
    read -sp "Confirm ROOT password: " NEW_ROOT_PASS_CONFIRM
    echo ""
    if [ "$NEW_ROOT_PASS" = "$NEW_ROOT_PASS_CONFIRM" ] && [ -n "$NEW_ROOT_PASS" ]; then
        break
    else
        echo "ERROR: Passwords don't match or empty. Try again."
        echo ""
    fi
done

# Sysadmin password
while true; do
    read -sp "New SYSADMIN password: " NEW_SYSADMIN_PASS
    echo ""
    read -sp "Confirm SYSADMIN password: " NEW_SYSADMIN_PASS_CONFIRM
    echo ""
    if [ "$NEW_SYSADMIN_PASS" = "$NEW_SYSADMIN_PASS_CONFIRM" ] && [ -n "$NEW_SYSADMIN_PASS" ]; then
        break
    else
        echo "ERROR: Passwords don't match or empty. Try again."
        echo ""
    fi
done

# Current Splunk password (what it is NOW before we change it)
echo ""
read -sp "CURRENT Splunk admin password (default is 'changeme'): " DEFAULT_SPLUNK_PASS
echo ""
if [ -z "$DEFAULT_SPLUNK_PASS" ]; then
    DEFAULT_SPLUNK_PASS="changeme"
    echo "Using default: changeme"
fi

# New Splunk password
while true; do
    read -sp "NEW Splunk admin password: " NEW_SPLUNK_ADMIN_PASS
    echo ""
    read -sp "Confirm NEW Splunk admin password: " NEW_SPLUNK_ADMIN_PASS_CONFIRM
    echo ""
    if [ "$NEW_SPLUNK_ADMIN_PASS" = "$NEW_SPLUNK_ADMIN_PASS_CONFIRM" ] && [ -n "$NEW_SPLUNK_ADMIN_PASS" ]; then
        break
    else
        echo "ERROR: Passwords don't match or empty. Try again."
        echo ""
    fi
done

DEFAULT_SPLUNK_USER="admin"

# ====================================================================
# 2. COLLECT NETWORK INFO
# ====================================================================
echo ""
echo "=== STEP 2: NETWORK CONFIGURATION ==="
echo ""
echo "Internal network subnets (for SSH whitelist)"
echo "Example: 172.20.242.0/24"
echo ""

read -p "Internal network subnet 1: " INSIDE_NET_1
if [ -z "$INSIDE_NET_1" ]; then
    INSIDE_NET_1="172.20.242.0/24"
    echo "Using default: 172.20.242.0/24"
fi

read -p "Internal network subnet 2: " INSIDE_NET_2
if [ -z "$INSIDE_NET_2" ]; then
    INSIDE_NET_2="172.20.240.0/24"
    echo "Using default: 172.20.240.0/24"
fi

# ====================================================================
# 3. RANDOMIZE GUARDIAN TIMING (MAKE IT UNPREDICTABLE)
# ====================================================================
echo ""
echo "=== STEP 3: GUARDIAN TIMING ==="
echo ""
echo "Guardian checks Splunk health periodically."
echo "We'll randomize the timing so Red Team can't predict it."
echo ""

# Random interval between 1-3 minutes
GUARDIAN_INTERVAL=$((RANDOM % 3 + 1))
echo "Guardian will check every $GUARDIAN_INTERVAL minute(s)"

# Random offset (0-59 seconds) so not always at :00
GUARDIAN_OFFSET=$((RANDOM % 60))

# ====================================================================
# CONFIRMATION
# ====================================================================
echo ""
echo "=== CONFIGURATION SUMMARY ==="
echo "Root password: [SET]"
echo "Sysadmin password: [SET]"
echo "Splunk admin password: [SET]"
echo "Internal subnet 1: $INSIDE_NET_1"
echo "Internal subnet 2: $INSIDE_NET_2"
echo "Guardian interval: Every $GUARDIAN_INTERVAL minute(s)"
echo "Backup location: $BACKUP_DIR"
echo "Log file: $LOG_FILE"
echo ""
read -p "Proceed with hardening? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted by user"
    exit 0
fi

# ====================================================================
# START HARDENING
# ====================================================================
clear

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo "[$(date '+%H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE" >&2
}

log "=== TITANIUM ULTRA - ANTI RED TEAM HARDENING ==="

if [ "$EUID" -ne 0 ]; then
    error "Must run as root"
    exit 1
fi

if [ ! -d "$SPLUNK_HOME" ]; then
    error "Splunk not found at $SPLUNK_HOME"
    exit 1
fi

# ====================================================================
# 1. NUCLEAR BACKUP - EVERYTHING CRITICAL
# ====================================================================
log "[1/15] Creating comprehensive backup..."
mkdir -p "$BACKUP_DIR"

tar -czf "$BACKUP_DIR/splunk_etc.tar.gz" "$SPLUNK_HOME/etc" 2>/dev/null || true
cp -p /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/group "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/systemd/system/Splunkd.service "$BACKUP_DIR/" 2>/dev/null || true

id "$SPLUNK_USER" > "$BACKUP_DIR/splunk_user_id.txt" 2>/dev/null || true
grep "^$SPLUNK_USER:" /etc/passwd > "$BACKUP_DIR/splunk_passwd_entry.txt" 2>/dev/null || true

log "[+] Backup saved to $BACKUP_DIR"

# ====================================================================
# 2. FIX SPLUNK USER (RED TEAM LOVES TO BREAK THIS)
# ====================================================================
log "[2/15] Hardening Splunk user account..."

if ! id "$SPLUNK_USER" &>/dev/null; then
    error "Splunk user doesn't exist - creating it"
    useradd -r -d "$SPLUNK_HOME" -s /bin/bash "$SPLUNK_USER"
fi

usermod -s /bin/bash "$SPLUNK_USER" 2>/dev/null || true
usermod -d "$SPLUNK_HOME" "$SPLUNK_USER" 2>/dev/null || true
passwd -l "$SPLUNK_USER" 2>/dev/null || true

log "[+] Splunk user hardened (home: $SPLUNK_HOME, shell: /bin/bash)"

# ====================================================================
# 3. OWNERSHIP FORTRESS
# ====================================================================
log "[3/15] Securing Splunk ownership..."

chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME" 2>/dev/null || log "Warning: Some files couldn't be chowned"

chmod 755 "$SPLUNK_HOME"
chmod 755 "$SPLUNK_HOME/bin"
chmod 755 "$SPLUNK_HOME/etc"
chmod 700 "$SPLUNK_HOME/var" 2>/dev/null || true
chmod 755 "$SPLUNK_HOME/bin/splunk"

log "[+] Ownership secured"

# ====================================================================
# 4. DETECT AND REMOVE SYMLINK ATTACKS
# ====================================================================
log "[4/15] Checking for symlink attacks..."

SYMLINK_COUNT=0
while IFS= read -r -d '' symlink; do
    target=$(readlink "$symlink")
    if [[ "$target" == "/dev/null" ]] || [[ "$target" == "/dev/random" ]] || [[ "$target" == "/dev/zero" ]]; then
        log "[!] Removing malicious symlink: $symlink -> $target"
        rm -f "$symlink"
        ((SYMLINK_COUNT++))
    fi
done < <(find "$SPLUNK_HOME" -type l -print0 2>/dev/null || true)

log "[+] Removed $SYMLINK_COUNT malicious symlinks"

# ====================================================================
# 5. PROTECT CRITICAL SPLUNK FILES
# ====================================================================
log "[5/15] Protecting critical Splunk files..."

CRITICAL_FILES=(
    "$SPLUNK_HOME/bin/splunk"
    "$SPLUNK_HOME/etc/splunk-launch.conf"
    "$SPLUNK_HOME/etc/myinstall/splunkd.xml"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        chattr -i "$file" 2>/dev/null || true
        chown "$SPLUNK_USER:$SPLUNK_USER" "$file" 2>/dev/null || true
    fi
done

log "[+] Critical files protected"

# ====================================================================
# 6. FIX SPLUNK_HOME ENVIRONMENT VARIABLE POISONING
# ====================================================================
log "[6/15] Securing SPLUNK_HOME environment..."

if [ -f "$SPLUNK_HOME/etc/splunk-launch.conf" ]; then
    cp -p "$SPLUNK_HOME/etc/splunk-launch.conf" "$BACKUP_DIR/" 2>/dev/null || true
    
    sed -i "s|^SPLUNK_HOME=.*|SPLUNK_HOME=$SPLUNK_HOME|" "$SPLUNK_HOME/etc/splunk-launch.conf"
    sed -i '/^LD_LIBRARY_PATH=/d' "$SPLUNK_HOME/etc/splunk-launch.conf"
    
    log "[+] splunk-launch.conf secured"
fi

# ====================================================================
# 7. SYSTEMD SERVICE FILE HARDENING
# ====================================================================
log "[7/15] Hardening systemd service..."

SYSTEMD_FILE="/etc/systemd/system/Splunkd.service"
if [ -f "$SYSTEMD_FILE" ]; then
    cp -p "$SYSTEMD_FILE" "$BACKUP_DIR/" 2>/dev/null || true
    
    sed -i "s|^User=.*|User=$SPLUNK_USER|" "$SYSTEMD_FILE"
    sed -i "s|^Group=.*|Group=$SPLUNK_USER|" "$SYSTEMD_FILE"
    sed -i "s|^ExecStart=.*|ExecStart=$SPLUNK_HOME/bin/splunk _internal_launch_under_systemd|" "$SYSTEMD_FILE"
    
    systemctl daemon-reload
    log "[+] Systemd service hardened"
fi

# ====================================================================
# 8. CHANGE OS PASSWORDS
# ====================================================================
log "[8/15] Changing system passwords..."
echo "root:$NEW_ROOT_PASS" | chpasswd
echo "sysadmin:$NEW_SYSADMIN_PASS" | chpasswd
log "[+] OS passwords changed"

# ====================================================================
# 9. NUCLEAR PERSISTENCE REMOVAL
# ====================================================================
log "[9/15] Nuking all persistence mechanisms..."

echo "" > /etc/crontab
rm -rf /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null || true

for user in $(cut -f1,7 -d: /etc/passwd | grep -v -E '(/bin/false|/sbin/nologin|/usr/sbin/nologin)$' | cut -f1 -d:); do
    crontab -u "$user" -r 2>/dev/null || true
done

for homedir in /root /home/*; do
    if [ -d "$homedir/.ssh" ]; then
        echo "" > "$homedir/.ssh/authorized_keys" 2>/dev/null || true
        chmod 600 "$homedir/.ssh/authorized_keys" 2>/dev/null || true
    fi
done

rm -f /tmp/.* /var/tmp/.* 2>/dev/null || true
rm -f /dev/shm/.* 2>/dev/null || true
rm -rf /var/spool/at/* 2>/dev/null || true

systemctl list-timers --all --no-pager | grep -v "NEXT\|^$" | awk '{print $NF}' | while read timer; do
    if [[ ! "$timer" =~ ^(systemd|dnf|fwupd) ]]; then
        systemctl disable "$timer" 2>/dev/null || true
    fi
done

log "[+] Persistence nuked"

# ====================================================================
# 10. VERIFY SPLUNK BINARY INTEGRITY
# ====================================================================
log "[10/15] Verifying Splunk binary..."

if [ ! -x "$SPLUNK_HOME/bin/splunk" ]; then
    error "Splunk binary is not executable or missing"
    chmod 755 "$SPLUNK_HOME/bin/splunk"
fi

if ! "$SPLUNK_HOME/bin/splunk" version &>/dev/null; then
    error "Splunk binary is corrupted"
    log "[!] You may need to request VM reset"
else
    VERSION=$("$SPLUNK_HOME/bin/splunk" version 2>/dev/null | head -1)
    log "[+] Splunk binary OK: $VERSION"
fi

# ====================================================================
# 11. START SPLUNK AND CHANGE PASSWORD
# ====================================================================
log "[11/15] Starting Splunk..."

"$SPLUNK_HOME/bin/splunk" stop 2>/dev/null || true
sleep 5

pkill -9 splunkd 2>/dev/null || true
sleep 2

su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt" 2>&1 | tee -a "$LOG_FILE"

sleep 20

if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    error "Splunk failed to start"
    log "[!] Check: $SPLUNK_HOME/var/log/splunk/splunkd.log"
    exit 1
fi

log "[+] Splunk started"

log "[*] Changing Splunk admin password..."
"$SPLUNK_HOME/bin/splunk" edit user "$DEFAULT_SPLUNK_USER" \
    -password "$NEW_SPLUNK_ADMIN_PASS" \
    -auth "$DEFAULT_SPLUNK_USER:$DEFAULT_SPLUNK_PASS" 2>&1 | tee -a "$LOG_FILE" || \
    log "[!] Password change failed - may need manual intervention"

# ====================================================================
# 12. FIREWALL CONFIGURATION
# ====================================================================
log "[12/15] Configuring firewall..."

systemctl enable --now firewalld 2>&1 | tee -a "$LOG_FILE"
sleep 3

firewall-cmd --permanent --zone=public --remove-service=cockpit 2>/dev/null || true
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client 2>/dev/null || true

firewall-cmd --permanent --zone=trusted --add-interface=lo

firewall-cmd --permanent --zone=public --add-port=8000/tcp
firewall-cmd --permanent --zone=public --add-port=8089/tcp
firewall-cmd --permanent --zone=public --add-port=9997/tcp

firewall-cmd --permanent --zone=public --add-protocol=icmp

firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true
firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='$INSIDE_NET_1' service name='ssh' accept"
firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='$INSIDE_NET_2' service name='ssh' accept"

firewall-cmd --reload
log "[+] Firewall secured"

# ====================================================================
# 13. SSH HARDENING
# ====================================================================
log "[13/15] Hardening SSH..."

cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
    systemctl restart sshd
    log "[+] SSH hardened"
else
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    systemctl restart sshd
    log "[!] SSH config test failed, reverted"
fi

# ====================================================================
# 14. ADVANCED BABYSITTER - SELF-HEALING SPLUNK
# ====================================================================
log "[14/15] Creating advanced babysitter with randomized timing..."

cat > /root/splunk_guardian.sh << 'GUARDIAN_EOF'
#!/bin/bash
# Advanced Splunk Guardian - Detects and fixes common Red Team attacks

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG="/var/log/splunk_guardian.log"

log_msg() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"
}

# Check 1: Is splunkd running?
if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log_msg "ALERT: Splunk is down, attempting restart"
    
    # Check 2: Is splunk user's shell valid?
    SHELL=$(getent passwd "$SPLUNK_USER" | cut -d: -f7)
    if [[ "$SHELL" != "/bin/bash" ]]; then
        log_msg "FIX: Restoring splunk user shell to /bin/bash"
        usermod -s /bin/bash "$SPLUNK_USER"
    fi
    
    # Check 3: Is splunk user's home correct?
    HOME=$(getent passwd "$SPLUNK_USER" | cut -d: -f6)
    if [[ "$HOME" != "$SPLUNK_HOME" ]]; then
        log_msg "FIX: Restoring splunk user home to $SPLUNK_HOME"
        usermod -d "$SPLUNK_HOME" "$SPLUNK_USER"
    fi
    
    # Check 4: Are permissions correct?
    if [ ! -x "$SPLUNK_HOME/bin/splunk" ]; then
        log_msg "FIX: Restoring execute permission on splunk binary"
        chmod 755 "$SPLUNK_HOME/bin/splunk"
    fi
    
    # Check 5: Is ownership correct?
    OWNER=$(stat -c '%U' "$SPLUNK_HOME/bin/splunk")
    if [[ "$OWNER" != "$SPLUNK_USER" ]]; then
        log_msg "FIX: Restoring ownership on $SPLUNK_HOME"
        chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
    fi
    
    # Check 6: Port hijacking - is something else on 8000?
    if netstat -tuln | grep -q ":8000.*LISTEN"; then
        HIJACKER=$(netstat -tulpn | grep ":8000.*LISTEN" | awk '{print $7}' | cut -d/ -f1)
        if [[ "$HIJACKER" != *"splunkd"* ]]; then
            log_msg "ALERT: Port 8000 hijacked by PID $HIJACKER, killing it"
            kill -9 "$HIJACKER" 2>/dev/null
        fi
    fi
    
    # Now try to start Splunk
    log_msg "Attempting to start Splunk..."
    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start" >> "$LOG" 2>&1
    
    sleep 10
    
    if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        log_msg "SUCCESS: Splunk restarted"
    else
        log_msg "CRITICAL: Splunk failed to restart - manual intervention needed"
    fi
fi

# Check web UI is responding
if ! curl -k -s --max-time 5 https://localhost:8000 | grep -q "Splunk"; then
    log_msg "WARNING: Web UI not responding properly"
fi
GUARDIAN_EOF

chmod +x /root/splunk_guardian.sh

# Calculate cron schedule with randomization
# If interval is 1: */1 * * * *
# If interval is 2: */2 * * * *
# If interval is 3: */3 * * * *
CRON_SCHEDULE="*/$GUARDIAN_INTERVAL * * * *"

# Add to cron with randomized timing
(crontab -l 2>/dev/null | grep -v "splunk_guardian"; echo "$CRON_SCHEDULE sleep $GUARDIAN_OFFSET; /root/splunk_guardian.sh") | crontab -

log "[+] Advanced guardian deployed (runs every $GUARDIAN_INTERVAL min, ${GUARDIAN_OFFSET}s offset)"

# ====================================================================
# 15. FINAL VERIFICATION
# ====================================================================
log "[15/15] Final verification..."

sleep 5

if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log "[+] Splunk: RUNNING"
else
    error "Splunk: NOT RUNNING"
fi

if curl -k -s --max-time 10 https://localhost:8000 | grep -q "Splunk"; then
    log "[+] Web UI: RESPONDING"
else
    log "[!] Web UI: NOT RESPONDING"
fi

for port in 8000 8089 9997; do
    if netstat -tuln | grep -q ":$port.*LISTEN"; then
        log "[+] Port $port: LISTENING"
    else
        log "[!] Port $port: NOT LISTENING"
    fi
done

if firewall-cmd --list-ports | grep -q "8000/tcp"; then
    log "[+] Firewall: CONFIGURED"
else
    log "[!] Firewall: MISSING RULES"
fi

if crontab -l | grep -q "splunk_guardian"; then
    log "[+] Guardian: ACTIVE"
else
    log "[!] Guardian: NOT IN CRON"
fi

log ""
log "=== TITANIUM ULTRA COMPLETE ==="
log "Backup: $BACKUP_DIR"
log "Log: $LOG_FILE"
log "Guardian log: /var/log/splunk_guardian.log"
log "Guardian runs: Every $GUARDIAN_INTERVAL minute(s) with ${GUARDIAN_OFFSET}s offset"
log ""
log "PASSWORDS CHANGED:"
log "  - root (changed)"
log "  - sysadmin (changed)"
log "  - Splunk admin (changed)"
log ""
log "SSH RESTRICTED TO:"
log "  - $INSIDE_NET_1"
log "  - $INSIDE_NET_2"
log ""
log "NEXT: Run splunk_diamond_ultra.sh to harden the UI"
log ""

# Clear sensitive variables from memory
unset NEW_ROOT_PASS
unset NEW_SYSADMIN_PASS
unset NEW_SPLUNK_ADMIN_PASS
unset DEFAULT_SPLUNK_PASS
unset NEW_ROOT_PASS_CONFIRM
unset NEW_SYSADMIN_PASS_CONFIRM
unset NEW_SPLUNK_ADMIN_PASS_CONFIRM

echo ""
echo "========================================="
echo "   TITANIUM ULTRA COMPLETE"
echo "========================================="
echo ""
echo "Check the log: $LOG_FILE"
echo "Monitor Guardian: tail -f /var/log/splunk_guardian.log"
echo ""
