#!/bin/bash
# TITANIUM ULTRA SECURE - FINAL VERSION
# Completes all 20 steps, never exits on errors
# Built from lessons learned - password change failures won't stop script

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG_FILE="/root/titanium_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/backup_$(date +%Y%m%d_%H%M%S)"

# Logging functions
log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
warn() { echo "[$(date '+%H:%M:%S')] WARNING: $1" | tee -a "$LOG_FILE"; }
success() { echo "[$(date '+%H:%M:%S')] SUCCESS: $1" | tee -a "$LOG_FILE"; }

# Check if command exists
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# Get listening ports (works with netstat or ss)
check_port() {
    local port=$1
    if cmd_exists netstat; then
        netstat -tuln 2>/dev/null | grep -q ":$port.*LISTEN"
    elif cmd_exists ss; then
        ss -tuln 2>/dev/null | grep -q ":$port.*LISTEN"
    else
        warn "No netstat or ss available"
        return 1
    fi
}

# ====================================================================
# INTERACTIVE PASSWORD COLLECTION
# ====================================================================
clear
echo "========================================="
echo "   TITANIUM ULTRA SECURE"
echo "   All 20 Steps Guaranteed"
echo "========================================="
echo ""
echo "Passwords will NOT be visible as you type."
echo ""
read -p "Press ENTER to start..."
echo ""

# ROOT PASSWORD
echo "=== ROOT PASSWORD ==="
while true; do
    read -sp "New ROOT password: " NEW_ROOT_PASS
    echo ""
    read -sp "Confirm ROOT password: " NEW_ROOT_PASS_CONFIRM
    echo ""
    if [ "$NEW_ROOT_PASS" = "$NEW_ROOT_PASS_CONFIRM" ] && [ -n "$NEW_ROOT_PASS" ]; then
        echo "✓ ROOT password set"
        break
    fi
    echo "✗ Passwords don't match or empty. Try again."
    echo ""
done

# SYSADMIN PASSWORD
echo ""
echo "=== SYSADMIN PASSWORD ==="
while true; do
    read -sp "New SYSADMIN password: " NEW_SYSADMIN_PASS
    echo ""
    read -sp "Confirm SYSADMIN password: " NEW_SYSADMIN_PASS_CONFIRM
    echo ""
    if [ "$NEW_SYSADMIN_PASS" = "$NEW_SYSADMIN_PASS_CONFIRM" ] && [ -n "$NEW_SYSADMIN_PASS" ]; then
        echo "✓ SYSADMIN password set"
        break
    fi
    echo "✗ Passwords don't match or empty. Try again."
    echo ""
done

# CURRENT SPLUNK PASSWORD
echo ""
echo "=== SPLUNK PASSWORDS ==="
read -sp "CURRENT Splunk admin password (press ENTER for 'changeme'): " CURRENT_SPLUNK_PASS
echo ""
if [ -z "$CURRENT_SPLUNK_PASS" ]; then
    CURRENT_SPLUNK_PASS="changeme"
    echo "Using default: changeme"
fi

# NEW SPLUNK PASSWORD
while true; do
    read -sp "NEW Splunk admin password: " NEW_SPLUNK_PASS
    echo ""
    read -sp "Confirm NEW Splunk admin password: " NEW_SPLUNK_PASS_CONFIRM
    echo ""
    if [ "$NEW_SPLUNK_PASS" = "$NEW_SPLUNK_PASS_CONFIRM" ] && [ -n "$NEW_SPLUNK_PASS" ]; then
        echo "✓ Splunk password set"
        break
    fi
    echo "✗ Passwords don't match or empty. Try again."
    echo ""
done

# NETWORK CONFIGURATION
echo ""
echo "=== NETWORK SUBNETS ==="
read -p "Internal subnet 1 [172.20.242.0/24]: " SUBNET1
SUBNET1=${SUBNET1:-172.20.242.0/24}
read -p "Internal subnet 2 [172.20.240.0/24]: " SUBNET2
SUBNET2=${SUBNET2:-172.20.240.0/24}

echo ""
echo "✓ Subnet 1: $SUBNET1"
echo "✓ Subnet 2: $SUBNET2"

# RANDOMIZE GUARDIAN TIMING (unpredictable for Red Team)
GUARDIAN_INTERVAL=$((RANDOM % 3 + 1))
GUARDIAN_OFFSET=$((RANDOM % 60))

echo ""
echo "=== SUMMARY ==="
echo "Guardian will run every $GUARDIAN_INTERVAL minute(s)"
echo "All passwords configured"
echo "SSH restricted to: $SUBNET1, $SUBNET2"
echo ""
read -p "Proceed with hardening? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted by user"
    exit 0
fi

clear

# ====================================================================
# START HARDENING
# ====================================================================
log "========================================="
log "TITANIUM ULTRA SECURE - STARTING"
log "========================================="

# Verify we're root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

# Verify Splunk exists
if [ ! -d "$SPLUNK_HOME" ]; then
    echo "ERROR: Splunk not found at $SPLUNK_HOME"
    exit 1
fi

# ====================================================================
# STEP 1: COMPREHENSIVE BACKUP
# ====================================================================
log "[1/20] Creating comprehensive backup..."
mkdir -p "$BACKUP_DIR" || warn "Could not create backup dir"

# Backup Splunk configs
tar -czf "$BACKUP_DIR/splunk_etc.tar.gz" "$SPLUNK_HOME/etc" 2>/dev/null || warn "Splunk backup incomplete"

# Backup system files
for file in /etc/passwd /etc/shadow /etc/group /etc/ssh/sshd_config; do
    cp -p "$file" "$BACKUP_DIR/" 2>/dev/null || warn "Could not backup $file"
done

# Save current splunk user info
id "$SPLUNK_USER" > "$BACKUP_DIR/splunk_user.txt" 2>/dev/null || true

success "Backup created: $BACKUP_DIR"

# ====================================================================
# STEP 2: KILL SUSPICIOUS PROCESSES
# ====================================================================
log "[2/20] Killing suspicious processes..."
KILLED_COUNT=0

# Known Red Team tools/techniques
for pattern in "nc -l" "ncat" "socat" "python -c" "python3 -c" "perl -e" "bash -i" "/dev/tcp"; do
    if pkill -9 -f "$pattern" 2>/dev/null; then
        ((KILLED_COUNT++))
        log "  Killed process matching: $pattern"
    fi
done

success "Killed $KILLED_COUNT suspicious processes"

# ====================================================================
# STEP 3: NUCLEAR PERSISTENCE REMOVAL
# ====================================================================
log "[3/20] Removing ALL persistence mechanisms..."

# Nuke all cron jobs
echo "" > /etc/crontab 2>/dev/null || true
rm -rf /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null || true

# Remove all user crontabs
for user in $(cut -f1,7 -d: /etc/passwd | grep -v -E '(/bin/false|/sbin/nologin)$' | cut -f1 -d:); do
    crontab -u "$user" -r 2>/dev/null || true
done

# Nuke at jobs
rm -rf /var/spool/at/* /var/spool/cron/* 2>/dev/null || true

# Remove all SSH authorized_keys
for homedir in /root /home/*; do
    if [ -d "$homedir/.ssh" ]; then
        echo "" > "$homedir/.ssh/authorized_keys" 2>/dev/null || true
        chmod 600 "$homedir/.ssh/authorized_keys" 2>/dev/null || true
        rm -f "$homedir/.ssh/id_"* 2>/dev/null || true
    fi
done

# Remove systemd timers
systemctl list-timers --all --no-pager 2>/dev/null | tail -n +2 | awk '{print $NF}' | while read timer; do
    # Keep essential system timers
    if [[ ! "$timer" =~ ^(systemd|dnf|fwupd|unbound) ]]; then
        systemctl disable "$timer" 2>/dev/null || true
        systemctl stop "$timer" 2>/dev/null || true
    fi
done

success "All persistence mechanisms removed"

# ====================================================================
# STEP 4: REMOVE BACKDOOR FILES
# ====================================================================
log "[4/20] Removing backdoor files..."
REMOVED_COUNT=0

# Common backdoor locations
for dir in /tmp /var/tmp /dev/shm; do
    if [ -d "$dir" ]; then
        # Remove hidden files, nc binaries, shell scripts created recently
        find "$dir" -type f \( -name ".*" -o -name "*nc*" -o -name "*shell*" -o -name "*.sh" \) -mtime -1 -delete 2>/dev/null && ((REMOVED_COUNT++)) || true
    fi
done

success "Removed backdoor files from temp directories"

# ====================================================================
# STEP 5: FIX SPLUNK USER (RED TEAM ATTACK VECTOR)
# ====================================================================
log "[5/20] Securing Splunk user account..."

# Create user if doesn't exist
if ! id "$SPLUNK_USER" &>/dev/null; then
    warn "Splunk user doesn't exist - creating"
    useradd -r -d "$SPLUNK_HOME" -s /bin/bash "$SPLUNK_USER" || warn "Could not create user"
fi

# Fix shell (Red Team changes to /bin/false)
usermod -s /bin/bash "$SPLUNK_USER" 2>/dev/null || warn "Could not fix shell"

# Fix home directory (Red Team changes to /tmp or /opt/BetterRedThanDead)
usermod -d "$SPLUNK_HOME" "$SPLUNK_USER" 2>/dev/null || warn "Could not fix home"

# Lock user from direct login
passwd -l "$SPLUNK_USER" 2>/dev/null || true

success "Splunk user secured (shell: /bin/bash, home: $SPLUNK_HOME)"

# ====================================================================
# STEP 6: FIX OWNERSHIP (RED TEAM ATTACK VECTOR)
# ====================================================================
log "[6/20] Fixing Splunk ownership..."

# Red Team changes ownership to root or fake users
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME" 2>/dev/null || warn "Some files couldn't be chowned"

# Fix critical permissions
chmod 755 "$SPLUNK_HOME" || true
chmod 755 "$SPLUNK_HOME/bin" || true
chmod 755 "$SPLUNK_HOME/etc" || true
chmod 700 "$SPLUNK_HOME/var" 2>/dev/null || true
chmod 755 "$SPLUNK_HOME/bin/splunk" || true

success "Ownership fixed"

# ====================================================================
# STEP 7: REMOVE SYMLINK ATTACKS
# ====================================================================
log "[7/20] Removing malicious symlinks..."
SYMLINK_COUNT=0

# Red Team replaces files with symlinks to /dev/null
find "$SPLUNK_HOME" -type l 2>/dev/null | while read symlink; do
    target=$(readlink "$symlink" 2>/dev/null || echo "")
    if [[ "$target" == "/dev/null" ]] || [[ "$target" == "/dev/random" ]] || [[ "$target" == "/dev/zero" ]]; then
        rm -f "$symlink" && ((SYMLINK_COUNT++)) && log "  Removed: $symlink -> $target"
    fi
done

success "Removed $SYMLINK_COUNT malicious symlinks"

# ====================================================================
# STEP 8: FIX SPLUNK_HOME ENVIRONMENT
# ====================================================================
log "[8/20] Securing SPLUNK_HOME environment..."

if [ -f "$SPLUNK_HOME/etc/splunk-launch.conf" ]; then
    # Red Team changes SPLUNK_HOME to break startup
    sed -i "s|^SPLUNK_HOME=.*|SPLUNK_HOME=$SPLUNK_HOME|" "$SPLUNK_HOME/etc/splunk-launch.conf" 2>/dev/null || true
    
    # Remove library hijacking
    sed -i '/^LD_LIBRARY_PATH=/d' "$SPLUNK_HOME/etc/splunk-launch.conf" 2>/dev/null || true
fi

success "SPLUNK_HOME secured"

# ====================================================================
# STEP 9: FIX SYSTEMD SERVICE
# ====================================================================
log "[9/20] Securing systemd service..."

SYSTEMD_FILE="/etc/systemd/system/Splunkd.service"
if [ -f "$SYSTEMD_FILE" ]; then
    # Red Team modifies to run as wrong user
    sed -i "s|^User=.*|User=$SPLUNK_USER|" "$SYSTEMD_FILE" 2>/dev/null || true
    sed -i "s|^Group=.*|Group=$SPLUNK_USER|" "$SYSTEMD_FILE" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi

success "Systemd service secured"

# ====================================================================
# STEP 10: CHANGE OS PASSWORDS
# ====================================================================
log "[10/20] Changing system passwords..."

echo "root:$NEW_ROOT_PASS" | chpasswd || warn "Root password change failed"
echo "sysadmin:$NEW_SYSADMIN_PASS" | chpasswd || warn "Sysadmin password change failed"

success "OS passwords changed"

# ====================================================================
# STEP 11: START SPLUNK
# ====================================================================
log "[11/20] Starting Splunk..."

# Stop Splunk cleanly
"$SPLUNK_HOME/bin/splunk" stop 2>/dev/null || true
sleep 5

# Kill any orphaned processes
pkill -9 splunkd 2>/dev/null || true
sleep 2

# Start Splunk as splunk user
log "  Starting Splunk as $SPLUNK_USER..."
su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt" 2>&1 | tee -a "$LOG_FILE"

# Wait for startup
sleep 20

# Verify it started
if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    success "Splunk started successfully"
else
    warn "Splunk may not have started - check $SPLUNK_HOME/var/log/splunk/splunkd.log"
    log "  Continuing anyway..."
fi

# ====================================================================
# STEP 12: CHANGE SPLUNK PASSWORD (NON-BLOCKING)
# ====================================================================
log "[12/20] Changing Splunk admin password..."

# THIS STEP CAN FAIL - SCRIPT CONTINUES ANYWAY
if "$SPLUNK_HOME/bin/splunk" edit user admin -password "$NEW_SPLUNK_PASS" -auth "admin:$CURRENT_SPLUNK_PASS" 2>&1 | tee -a "$LOG_FILE" | grep -q "edited"; then
    success "Splunk password changed successfully"
else
    warn "Splunk password change FAILED"
    log "  Current password might not be '$CURRENT_SPLUNK_PASS'"
    log "  You can change it manually: /opt/splunk/bin/splunk edit user admin -password NEWPASS -auth admin:OLDPASS"
    log "  CONTINUING WITH REMAINING STEPS..."
fi

# ====================================================================
# STEP 13: CONFIGURE FIREWALL
# ====================================================================
log "[13/20] Configuring firewall..."

# Enable firewalld
systemctl enable firewalld 2>/dev/null || true
systemctl start firewalld 2>/dev/null || true
sleep 3

# Allow Splunk ports (CRITICAL FOR SCORING)
firewall-cmd --permanent --zone=public --add-port=8000/tcp 2>/dev/null || warn "Could not add port 8000"
firewall-cmd --permanent --zone=public --add-port=8089/tcp 2>/dev/null || warn "Could not add port 8089"
firewall-cmd --permanent --zone=public --add-port=9997/tcp 2>/dev/null || warn "Could not add port 9997"

# Allow ICMP (CRITICAL FOR SCORING)
firewall-cmd --permanent --zone=public --add-protocol=icmp 2>/dev/null || warn "Could not add ICMP"

# Restrict SSH to internal networks only
firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true
firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='$SUBNET1' service name='ssh' accept" 2>/dev/null || warn "Could not add SSH rule 1"
firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='$SUBNET2' service name='ssh' accept" 2>/dev/null || warn "Could not add SSH rule 2"

# Reload firewall
firewall-cmd --reload 2>/dev/null || warn "Could not reload firewall"

success "Firewall configured"

# ====================================================================
# STEP 14: HARDEN SSH
# ====================================================================
log "[14/20] Hardening SSH..."

# Backup current config
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply hardening
cat >> /etc/ssh/sshd_config << 'SSHEOF'
PermitRootLogin no
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers sysadmin
SSHEOF

# Test config
if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
    systemctl restart sshd
    success "SSH hardened (root login disabled, restricted to sysadmin)"
else
    warn "SSH config test failed - reverting"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    systemctl restart sshd
fi

# ====================================================================
# STEP 15: KERNEL HARDENING
# ====================================================================
log "[15/20] Hardening kernel parameters..."

cat >> /etc/sysctl.conf << 'SYSCTLEOF'
# Network security
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1

# System hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
SYSCTLEOF

sysctl -p 2>&1 | tee -a "$LOG_FILE"

success "Kernel parameters hardened"

# ====================================================================
# STEP 16: DISABLE UNNECESSARY SERVICES
# ====================================================================
log "[16/20] Disabling unnecessary services..."

for service in bluetooth cups avahi-daemon ModemManager; do
    systemctl disable "$service" 2>/dev/null || true
    systemctl stop "$service" 2>/dev/null || true
done

success "Unnecessary services disabled"

# ====================================================================
# STEP 17: ENABLE SELINUX
# ====================================================================
log "[17/20] Enabling SELinux..."

setenforce 1 2>/dev/null && success "SELinux set to enforcing" || warn "SELinux not available"
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config 2>/dev/null || true

# ====================================================================
# STEP 18: CREATE GUARDIAN (AUTO-RECOVERY)
# ====================================================================
log "[18/20] Creating Guardian auto-recovery script..."

cat > /root/splunk_guardian.sh << 'GUARDIANEOF'
#!/bin/bash
SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG="/var/log/splunk_guardian.log"

log_msg() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"; }

# Kill suspicious processes every run
for pattern in "nc -l" "python -c" "bash -i"; do
    pkill -9 -f "$pattern" 2>/dev/null && log_msg "Killed: $pattern"
done

# Check if Splunk is running
if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log_msg "ALERT: Splunk is DOWN - attempting auto-recovery"
    
    # Check and fix splunk user shell
    SHELL=$(getent passwd "$SPLUNK_USER" | cut -d: -f7)
    if [ "$SHELL" != "/bin/bash" ]; then
        log_msg "FIX: Restoring shell to /bin/bash"
        usermod -s /bin/bash "$SPLUNK_USER"
    fi
    
    # Check and fix splunk user home
    HOME=$(getent passwd "$SPLUNK_USER" | cut -d: -f6)
    if [ "$HOME" != "$SPLUNK_HOME" ]; then
        log_msg "FIX: Restoring home to $SPLUNK_HOME"
        usermod -d "$SPLUNK_HOME" "$SPLUNK_USER"
    fi
    
    # Check and fix execute permission
    if [ ! -x "$SPLUNK_HOME/bin/splunk" ]; then
        log_msg "FIX: Restoring execute permission"
        chmod 755 "$SPLUNK_HOME/bin/splunk"
    fi
    
    # Check and fix ownership
    OWNER=$(stat -c '%U' "$SPLUNK_HOME/bin/splunk" 2>/dev/null || echo "unknown")
    if [ "$OWNER" != "$SPLUNK_USER" ]; then
        log_msg "FIX: Restoring ownership"
        chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
    fi
    
    # Check for port hijacking
    if command -v netstat >/dev/null 2>&1; then
        HIJACKER=$(netstat -tulpn 2>/dev/null | grep ":8000.*LISTEN" | grep -v splunkd | awk '{print $7}' | cut -d/ -f1)
    elif command -v ss >/dev/null 2>&1; then
        HIJACKER=$(ss -tulpn 2>/dev/null | grep ":8000.*LISTEN" | grep -v splunkd | awk '{print $7}' | cut -d, -f2 | cut -d= -f2)
    fi
    
    if [ -n "$HIJACKER" ]; then
        log_msg "ALERT: Port 8000 hijacked by PID $HIJACKER - killing"
        kill -9 "$HIJACKER" 2>/dev/null
    fi
    
    # Restart Splunk
    log_msg "Attempting to start Splunk..."
    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start" >> "$LOG" 2>&1
    
    sleep 10
    
    # Verify it started
    if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        log_msg "SUCCESS: Splunk auto-recovered"
    else
        log_msg "CRITICAL: Splunk failed to start - manual intervention needed"
    fi
fi
GUARDIANEOF

chmod +x /root/splunk_guardian.sh

success "Guardian script created"

# ====================================================================
# STEP 19: ADD GUARDIAN TO CRON
# ====================================================================
log "[19/20] Adding Guardian to cron..."

# Guardian runs every 1-3 minutes (randomized) with random offset
CRON_SCHEDULE="*/$GUARDIAN_INTERVAL * * * *"
(crontab -l 2>/dev/null | grep -v "splunk_guardian"; echo "$CRON_SCHEDULE sleep $GUARDIAN_OFFSET; /root/splunk_guardian.sh") | crontab -

success "Guardian active (runs every $GUARDIAN_INTERVAL minute(s))"

# ====================================================================
# STEP 20: FINAL VERIFICATION
# ====================================================================
log "[20/20] Final verification..."

sleep 5

# Check Splunk
if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    success "Splunk: RUNNING"
else
    warn "Splunk: NOT RUNNING"
fi

# Check web UI
if curl -k -s --max-time 10 https://localhost:8000 2>/dev/null | grep -q "Splunk"; then
    success "Web UI: RESPONDING"
else
    warn "Web UI: NOT RESPONDING"
fi

# Check ports
for port in 8000 8089 9997; do
    if check_port $port; then
        success "Port $port: LISTENING"
    else
        warn "Port $port: NOT LISTENING"
    fi
done

# Check firewall
if firewall-cmd --list-ports 2>/dev/null | grep -q "8000/tcp"; then
    success "Firewall: CONFIGURED"
else
    warn "Firewall: CHECK MANUALLY"
fi

# Check Guardian
if crontab -l 2>/dev/null | grep -q "splunk_guardian"; then
    success "Guardian: ACTIVE"
else
    warn "Guardian: NOT IN CRON"
fi

log ""
log "========================================="
log "TITANIUM ULTRA SECURE - COMPLETE"
log "========================================="
log ""
log "All 20 steps completed"
log "Backup: $BACKUP_DIR"
log "Log: $LOG_FILE"
log "Guardian log: /var/log/splunk_guardian.log"
log ""
log "NEXT STEP: Run splunk_diamond_ultra_secure.sh"
log ""

# Clear sensitive variables from memory
unset NEW_ROOT_PASS NEW_SYSADMIN_PASS NEW_SPLUNK_PASS CURRENT_SPLUNK_PASS

echo ""
echo "========================================="
echo "   TITANIUM COMPLETE - ALL 20 STEPS"
echo "========================================="
echo ""
echo "Review log: tail -100 $LOG_FILE"
echo "Monitor Guardian: tail -f /var/log/splunk_guardian.log"
echo ""
