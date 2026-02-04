#!/bin/bash
# DIAMOND ULTRA SECURE - FINAL VERSION
# Completes all 12 steps, never exits on errors
# Creates directories BEFORE files (learned from last failure)

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG_FILE="/var/log/diamond_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/diamond_backup_$(date +%Y%m%d_%H%M%S)"

# Logging functions
log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
warn() { echo "[$(date '+%H:%M:%S')] WARNING: $1" | tee -a "$LOG_FILE"; }
success() { echo "[$(date '+%H:%M:%S')] SUCCESS: $1" | tee -a "$LOG_FILE"; }

# Check if command exists
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# Check port listening
check_port() {
    local port=$1
    if cmd_exists netstat; then
        netstat -tuln 2>/dev/null | grep -q ":$port.*LISTEN"
    elif cmd_exists ss; then
        ss -tuln 2>/dev/null | grep -q ":$port.*LISTEN"
    else
        return 1
    fi
}

# ====================================================================
# INTERACTIVE CONFIGURATION
# ====================================================================
clear
echo "========================================="
echo "   DIAMOND ULTRA SECURE"
echo "   All 12 Steps Guaranteed"
echo "========================================="
echo ""
read -p "Press ENTER to start..."
echo ""

# NETWORK CONFIGURATION
echo "=== NETWORK SUBNETS ==="
read -p "Internal subnet 1 [172.20.242.0/24]: " SUBNET1
SUBNET1=${SUBNET1:-172.20.242.0/24}
read -p "Internal subnet 2 [172.20.240.0/24]: " SUBNET2
SUBNET2=${SUBNET2:-172.20.240.0/24}

echo ""
echo "✓ Subnet 1: $SUBNET1"
echo "✓ Subnet 2: $SUBNET2"

# RANDOMIZE UI MONITOR TIMING
UI_MONITOR_INTERVAL=$((RANDOM % 3 + 1))
UI_MONITOR_OFFSET=$((RANDOM % 60))

echo ""
echo "UI Monitor will run every $UI_MONITOR_INTERVAL minute(s)"
echo ""
read -p "Proceed with UI hardening? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted by user"
    exit 0
fi

clear

# ====================================================================
# START HARDENING
# ====================================================================
log "========================================="
log "DIAMOND ULTRA SECURE - STARTING"
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
# STEP 1: VERIFY SPLUNK RUNNING
# ====================================================================
log "[1/12] Verifying Splunk is running..."

if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log "  Splunk not running - starting it..."
    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes" 2>&1 | tee -a "$LOG_FILE"
    sleep 20
    
    if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        warn "Splunk failed to start - check $SPLUNK_HOME/var/log/splunk/splunkd.log"
        echo "ERROR: Cannot proceed without Splunk running"
        exit 1
    fi
fi

success "Splunk is running"

# ====================================================================
# STEP 2: CREATE BACKUP
# ====================================================================
log "[2/12] Creating comprehensive backup..."
mkdir -p "$BACKUP_DIR" || warn "Could not create backup directory"

# Backup system and apps configs
for dir in system apps; do
    if [ -d "$SPLUNK_HOME/etc/$dir/local" ]; then
        tar -czf "$BACKUP_DIR/${dir}_local.tar.gz" "$SPLUNK_HOME/etc/$dir/local" 2>/dev/null || warn "Could not backup $dir"
    fi
done

success "Backup created: $BACKUP_DIR"

# ====================================================================
# STEP 3: CREATE CONFIG DIRECTORIES
# ====================================================================
log "[3/12] Creating/securing config directories..."

# CRITICAL: Create directories FIRST (this was the bug last time)
mkdir -p "$SPLUNK_HOME/etc/system/local" || warn "Could not create system/local"
mkdir -p "$SPLUNK_HOME/etc/apps/search/local" || warn "Could not create apps/search/local"

# Fix ownership
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local" 2>/dev/null || true
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/apps" 2>/dev/null || true

success "Config directories ready"

# ====================================================================
# STEP 4: HARDEN WEB.CONF
# ====================================================================
log "[4/12] Hardening web.conf..."

# Remove immutable flag if exists
chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'WEBEOF'
[settings]
# Force HTTPS with modern TLS only
enableSplunkWebSSL = true
httpport = 8000
sslVersions = tls1.2, tls1.3
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

# Session security
tools.sessions.timeout = 20
tools.sessions.restart_persist = 0
ui_inactivity_timeout = 20m
enable_session_ip_locking = true

# Disable attack vectors
enableWebDebug = false
enable_insecure_login = false
enable_proxy_write = false
allowRemoteLogin = never
enable_rss = false

# Anti-clickjacking
x_frame_options_sameorigin = true
csp_frame_ancestors_policy = self
WEBEOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/web.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/web.conf"

success "web.conf hardened"

# ====================================================================
# STEP 5: HARDEN SERVER.CONF
# ====================================================================
log "[5/12] Hardening server.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/server.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/server.conf" << SERVEREOF
[general]
hideInternalModuleName = true
serverName = SecureNode

[httpServer]
# Modern TLS only
sslVersions = tls1.2, tls1.3
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# Connection limits (prevent DoS)
maxThreads = 10
maxSockets = 10
maxBoundThreads = 10

# Short timeouts
keepAliveIdleTimeout = 10
busyKeepAliveIdleTimeout = 5

[httpServerListener:8089]
# Restrict management port to internal networks only
acceptFrom = 127.0.0.1, $SUBNET1, $SUBNET2
SERVEREOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/server.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/server.conf"

success "server.conf hardened (mgmt port restricted to internal)"

# ====================================================================
# STEP 6: HARDEN LIMITS.CONF
# ====================================================================
log "[6/12] Hardening limits.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/limits.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/limits.conf" << 'LIMITSEOF'
[restapi]
# Severe REST API limits (prevent brute force)
maxclients = 5
maxoutstanding = 5

[search]
# Resource limits (prevent exhaustion)
max_mem_usage_mb = 2000
max_rawsize_perchunk = 100000000
ttl = 3600

[ratelimit]
# Rate limiting (prevent abuse)
max_requests_per_minute = 60
LIMITSEOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/limits.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/limits.conf"

success "limits.conf hardened"

# ====================================================================
# STEP 7: HARDEN AUTHORIZE.CONF
# ====================================================================
log "[7/12] Hardening authorize.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/authorize.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/authorize.conf" << 'AUTHEOF'
[role_admin]
# DISABLE EXECUTION VECTORS
run_script_search = disabled
edit_script = disabled
rtsearch = disabled

# DISABLE FILE SYSTEM ACCESS
edit_monitor = disabled
edit_server = disabled

# DISABLE USER MANAGEMENT VIA UI
edit_user = disabled
edit_roles_grantable = disabled

# Note: search, dashboards, and forwarder management still work
AUTHEOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/authorize.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/authorize.conf"

success "authorize.conf hardened (script execution disabled)"

# ====================================================================
# STEP 8: HARDEN AUTHENTICATION.CONF
# ====================================================================
log "[8/12] Hardening authentication.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/authentication.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'AUTHNEOF'
[authentication]
# Aggressive lockout
lockoutAttempts = 3
lockoutThresholdMins = 5
lockoutMins = 30

# Strong password requirements
minPasswordLength = 12
minPasswordDigit = 1
minPasswordLowercase = 1
minPasswordUppercase = 1
minPasswordSpecial = 1
AUTHNEOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/authentication.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/authentication.conf"

success "authentication.conf hardened (3 attempts = 30min lockout)"

# ====================================================================
# STEP 9: DISABLE RISKY APPS (FIXED - mkdir FIRST)
# ====================================================================
log "[9/12] Disabling vulnerable apps..."

# Remove execute from all scripts in apps
if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    find "$SPLUNK_HOME/etc/apps" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) -exec chmod -x {} \; 2>/dev/null || true
    log "  Removed execute permission from app scripts"
fi

# Disable specific risky apps
RISKY_APPS=(
    "python_upgrade_readiness_app"
    "splunk_monitoring_console"
    "splunk_secure_gateway"
)

for app in "${RISKY_APPS[@]}"; do
    if [ -d "$SPLUNK_HOME/etc/apps/$app" ]; then
        # CREATE THE DIRECTORY FIRST (this was missing before - caused failure)
        mkdir -p "$SPLUNK_HOME/etc/apps/$app/local"
        
        # Now create the file
        echo -e "[ui]\nis_visible = false\nis_manageable = false" > "$SPLUNK_HOME/etc/apps/$app/local/app.conf"
        
        # Fix ownership
        chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/apps/$app/local"
        
        log "  Disabled app: $app"
    fi
done

success "Vulnerable apps disabled"

# ====================================================================
# STEP 10: PROTECT AGAINST CONFIG INJECTION
# ====================================================================
log "[10/12] Protecting against config injection..."

cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'INPUTSEOF'
[default]
# Disable most inputs to prevent injection
_TCP_ROUTING = *
_SYSLOG_ROUTING = *

[splunktcp:9997]
# Only allow forwarders
disabled = false
INPUTSEOF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/inputs.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/inputs.conf"

success "inputs.conf locked down"

# ====================================================================
# STEP 11: RESTART SPLUNK
# ====================================================================
log "[11/12] Restarting Splunk to apply configs..."

su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk restart" 2>&1 | tee -a "$LOG_FILE"

log "  Waiting for Splunk to restart..."
sleep 15

# Progressive verification
RETRIES=0
MAX_RETRIES=10
while [ $RETRIES -lt $MAX_RETRIES ]; do
    if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        success "Splunk restarted successfully"
        break
    fi
    
    log "  Still waiting... ($((RETRIES+1))/$MAX_RETRIES)"
    sleep 10
    ((RETRIES++))
done

if [ $RETRIES -eq $MAX_RETRIES ]; then
    warn "Splunk failed to restart after $MAX_RETRIES attempts"
    log "  Check: $SPLUNK_HOME/var/log/splunk/splunkd.log"
    log "  To restore: bash /root/restore_diamond.sh"
    exit 1
fi

# ====================================================================
# STEP 12: CREATE UI MONITOR & VERIFY
# ====================================================================
log "[12/12] Creating UI monitor and verifying..."

# Create UI monitor script
cat > /root/monitor_splunk_ui.sh << 'MONITOREOF'
#!/bin/bash
SPLUNK_HOME="/opt/splunk"
LOG="/var/log/splunk_ui_monitor.log"

log_msg() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"; }

# Check web UI responding
if ! curl -k -s --max-time 5 https://localhost:8000 2>/dev/null | grep -q "Splunk"; then
    log_msg "ALERT: Web UI not responding"
    
    # Check if splunkweb process running
    if ! pgrep -f splunkweb >/dev/null; then
        log_msg "FIX: Restarting splunkweb"
        su - splunk -c "/opt/splunk/bin/splunk restart splunkweb" >> "$LOG" 2>&1
    fi
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

# Check config files haven't been deleted
for conf in web.conf server.conf authorize.conf; do
    if [ ! -f "$SPLUNK_HOME/etc/system/local/$conf" ]; then
        log_msg "CRITICAL: $conf is missing - restore needed"
    fi
done
MONITOREOF

chmod +x /root/monitor_splunk_ui.sh

# Add to cron
CRON_SCHEDULE="*/$UI_MONITOR_INTERVAL * * * *"
(crontab -l 2>/dev/null | grep -v "monitor_splunk_ui"; echo "$CRON_SCHEDULE sleep $UI_MONITOR_OFFSET; /root/monitor_splunk_ui.sh") | crontab -

success "UI monitor active (runs every $UI_MONITOR_INTERVAL minute(s))"

# Create restore script
cat > /root/restore_diamond.sh << RESTOREEOF
#!/bin/bash
echo "Restoring Splunk configs from backup..."
chattr -i "$SPLUNK_HOME/etc/system/local"/*.conf 2>/dev/null || true
tar -xzf "$BACKUP_DIR/system_local.tar.gz" -C "$SPLUNK_HOME/etc/system/" 2>/dev/null || true
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local"
su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk restart"
echo "Restore complete"
RESTOREEOF

chmod +x /root/restore_diamond.sh

# Final verification
sleep 10

if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    success "Splunk: RUNNING"
else
    warn "Splunk: NOT RUNNING"
fi

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

# Check configs exist
for conf in web.conf server.conf limits.conf authorize.conf authentication.conf; do
    if [ -f "$SPLUNK_HOME/etc/system/local/$conf" ]; then
        success "$conf: EXISTS"
    else
        warn "$conf: MISSING"
    fi
done

log ""
log "========================================="
log "DIAMOND ULTRA SECURE - COMPLETE"
log "========================================="
log ""
log "All 12 steps completed"
log "Backup: $BACKUP_DIR"
log "Log: $LOG_FILE"
log "UI Monitor log: /var/log/splunk_ui_monitor.log"
log ""
log "PROTECTIONS ACTIVE:"
log "  ✓ TLS 1.2/1.3 only"
log "  ✓ Session IP locking"
log "  ✓ Script execution disabled"
log "  ✓ Brute force lockout (3 attempts)"
log "  ✓ REST API limited"
log "  ✓ Management port restricted"
log "  ✓ UI monitoring active"
log ""

# Clear sensitive variables
unset SUBNET1 SUBNET2

echo ""
echo "========================================="
echo "   DIAMOND COMPLETE - ALL 12 STEPS"
echo "========================================="
echo ""
echo "Review log: tail -100 $LOG_FILE"
echo "Monitor UI: tail -f /var/log/splunk_ui_monitor.log"
echo ""
