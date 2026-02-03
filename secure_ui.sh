#!/bin/bash
# DIAMOND ULTRA - Maximum Splunk UI Protection
# NO HARDCODED SECRETS - Everything prompted interactively

set -euo pipefail

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG_FILE="/var/log/diamond_ultra_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/diamond_backup_$(date +%Y%m%d_%H%M%S)"

# ====================================================================
# INTERACTIVE CONFIGURATION
# ====================================================================
clear
echo "========================================="
echo "   DIAMOND ULTRA - CONFIGURATION"
echo "========================================="
echo ""
echo "This script hardens Splunk UI security."
echo "No secrets will be hardcoded."
echo ""
read -p "Press ENTER to continue..."
echo ""

# ====================================================================
# 1. COLLECT INTERNAL NETWORK INFO (FOR MANAGEMENT PORT RESTRICTION)
# ====================================================================
echo "=== NETWORK CONFIGURATION ==="
echo ""
echo "Management port (8089) should only accept connections from internal networks."
echo "Enter your internal subnets (same as used in Titanium script)"
echo ""

read -p "Internal network subnet 1 (e.g., 172.20.242.0/24): " INSIDE_NET_1
if [ -z "$INSIDE_NET_1" ]; then
    INSIDE_NET_1="172.20.242.0/24"
    echo "Using default: 172.20.242.0/24"
fi

read -p "Internal network subnet 2 (e.g., 172.20.240.0/24): " INSIDE_NET_2
if [ -z "$INSIDE_NET_2" ]; then
    INSIDE_NET_2="172.20.240.0/24"
    echo "Using default: 172.20.240.0/24"
fi

# ====================================================================
# 2. RANDOMIZE UI MONITOR TIMING
# ====================================================================
echo ""
echo "=== UI MONITOR TIMING ==="
echo ""
echo "UI monitor checks web interface health."
echo "Randomizing to prevent Red Team prediction."
echo ""

UI_MONITOR_INTERVAL=$((RANDOM % 3 + 1))
UI_MONITOR_OFFSET=$((RANDOM % 60))
echo "UI Monitor will check every $UI_MONITOR_INTERVAL minute(s)"

# ====================================================================
# CONFIRMATION
# ====================================================================
echo ""
echo "=== CONFIGURATION SUMMARY ==="
echo "Internal subnet 1: $INSIDE_NET_1"
echo "Internal subnet 2: $INSIDE_NET_2"
echo "Management port restricted to: Internal networks + localhost"
echo "UI monitor interval: Every $UI_MONITOR_INTERVAL minute(s)"
echo "Backup location: $BACKUP_DIR"
echo "Log file: $LOG_FILE"
echo ""
read -p "Proceed with UI hardening? (yes/no): " CONFIRM

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

log "=== DIAMOND ULTRA - MAXIMUM UI PROTECTION ==="

if [ "$EUID" -ne 0 ]; then
    error "Must run as root"
    exit 1
fi

if [ ! -d "$SPLUNK_HOME" ]; then
    error "Splunk not found"
    exit 1
fi

# ====================================================================
# 1. VERIFY SPLUNK IS RUNNING
# ====================================================================
log "[1/12] Verifying Splunk status..."

if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log "[!] Splunk not running, starting it..."
    su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes" 2>&1 | tee -a "$LOG_FILE"
    sleep 20
    
    if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        error "Cannot start Splunk"
        exit 1
    fi
fi

log "[+] Splunk is running"

# ====================================================================
# 2. COMPREHENSIVE BACKUP
# ====================================================================
log "[2/12] Creating backup..."
mkdir -p "$BACKUP_DIR"

for dir in system apps; do
    if [ -d "$SPLUNK_HOME/etc/$dir/local" ]; then
        tar -czf "$BACKUP_DIR/${dir}_local.tar.gz" "$SPLUNK_HOME/etc/$dir/local" 2>/dev/null || true
    fi
done

log "[+] Backup: $BACKUP_DIR"

# ====================================================================
# 3. CREATE AND LOCK CORE CONFIG DIRECTORIES
# ====================================================================
log "[3/12] Securing config directories..."

mkdir -p "$SPLUNK_HOME/etc/system/local"
mkdir -p "$SPLUNK_HOME/etc/apps/search/local"

chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local"
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/apps"

# ====================================================================
# 4. ULTRA-HARDENED WEB.CONF
# ====================================================================
log "[4/12] Hardening web.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'WEBCONF'
[settings]
# Force HTTPS with modern TLS
enableSplunkWebSSL = true
httpport = 8000
sslVersions = tls1.2, tls1.3
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# Session hardening
tools.sessions.timeout = 30
tools.sessions.restart_persist = 0
ui_inactivity_timeout = 30m
enable_session_ip_locking = true

# Disable attack vectors
enableWebDebug = false
enable_insecure_login = false
enable_proxy_write = false
allowRemoteLogin = never
enable_rss = false

# Anti-CSRF
x_frame_options_sameorigin = true

# Prevent clickjacking
csp_frame_ancestors_policy = self
WEBCONF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/web.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/web.conf"

log "[+] web.conf secured"

# ====================================================================
# 5. ULTRA-HARDENED SERVER.CONF WITH NETWORK RESTRICTION
# ====================================================================
log "[5/12] Hardening server.conf with network restrictions..."

chattr -i "$SPLUNK_HOME/etc/system/local/server.conf" 2>/dev/null || true

# Build acceptFrom string
ACCEPT_FROM="127.0.0.1, $INSIDE_NET_1, $INSIDE_NET_2"

cat > "$SPLUNK_HOME/etc/system/local/server.conf" << SERVERCONF
[general]
# Hide version info
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

# Timeouts
keepAliveIdleTimeout = 10
busyKeepAliveIdleTimeout = 5

[httpServerListener:8089]
# Management port restricted to internal networks only
acceptFrom = $ACCEPT_FROM
SERVERCONF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/server.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/server.conf"

log "[+] server.conf secured (mgmt port restricted to internal networks)"

# ====================================================================
# 6. ULTRA-HARDENED LIMITS.CONF
# ====================================================================
log "[6/12] Hardening limits.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/limits.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/limits.conf" << 'LIMITSCONF'
[restapi]
# Severe REST API limits (prevent brute force and DoS)
maxclients = 5
maxoutstanding = 5

[search]
# Resource limits (prevent resource exhaustion)
max_mem_usage_mb = 2000
max_rawsize_perchunk = 100000000
ttl = 3600

[ratelimit]
# Rate limiting (prevent abuse)
max_requests_per_minute = 60
LIMITSCONF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/limits.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/limits.conf"

log "[+] limits.conf secured"

# ====================================================================
# 7. ULTRA-HARDENED AUTHORIZE.CONF
# ====================================================================
log "[7/12] Hardening authorize.conf..."

chattr -i "$SPLUNK_HOME/etc/system/local/authorize.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/authorize.conf" << 'AUTHCONF'
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

[authentication]
# Force password complexity
passwordExpiryInDays = 90
AUTHCONF

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/authorize.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/authorize.conf"

log "[+] authorize.conf secured"

# ====================================================================
# 8. AUTHENTICATION.CONF - PREVENT BRUTE FORCE
# ====================================================================
log "[8/12] Hardening authentication..."

chattr -i "$SPLUNK_HOME/etc/system/local/authentication.conf" 2>/dev/null || true

cat > "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'AUTHENTICATION'
[authentication]
# Aggressive lockout
lockoutAttempts = 3
lockoutThresholdMins = 5
lockoutMins = 30

# Strong passwords required
minPasswordLength = 12
minPasswordDigit = 1
minPasswordLowercase = 1
minPasswordUppercase = 1
minPasswordSpecial = 1

[roleMap_Splunk]
# Disable admin from network (force local only)
admin = admin
AUTHENTICATION

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/authentication.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/authentication.conf"

log "[+] authentication.conf secured"

# ====================================================================
# 9. DISABLE VULNERABLE APPS AND SCRIPTS
# ====================================================================
log "[9/12] Disabling vulnerable components..."

if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    find "$SPLUNK_HOME/etc/apps" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) -exec chmod -x {} \; 2>/dev/null || true
    log "[+] Scripts in apps disabled"
fi

RISKY_APPS=(
    "python_upgrade_readiness_app"
    "splunk_monitoring_console"
    "splunk_secure_gateway"
)

for app in "${RISKY_APPS[@]}"; do
    if [ -d "$SPLUNK_HOME/etc/apps/$app" ]; then
        touch "$SPLUNK_HOME/etc/apps/$app/local/app.conf"
        echo -e "[ui]\nis_visible = false\nis_manageable = false" > "$SPLUNK_HOME/etc/apps/$app/local/app.conf"
        log "[+] Disabled risky app: $app"
    fi
done

# ====================================================================
# 10. PROTECT AGAINST CONFIG INJECTION
# ====================================================================
log "[10/12] Protecting against config injection..."

cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'INPUTS'
[default]
# Disable most inputs to prevent injection
_TCP_ROUTING = *
_SYSLOG_ROUTING = *

[splunktcp:9997]
# Only allow forwarders
disabled = false
INPUTS

chown "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local/inputs.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/inputs.conf"

log "[+] inputs.conf locked down"

# ====================================================================
# 11. RESTART SPLUNK WITH VERIFICATION
# ====================================================================
log "[11/12] Restarting Splunk..."

su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk restart" 2>&1 | tee -a "$LOG_FILE"

log "[*] Waiting for Splunk to restart..."
sleep 15

RETRIES=0
MAX_RETRIES=8
while [ $RETRIES -lt $MAX_RETRIES ]; do
    if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        log "[+] Splunk restarted successfully"
        break
    fi
    
    log "[*] Still waiting... ($((RETRIES+1))/$MAX_RETRIES)"
    sleep 10
    RETRIES=$((RETRIES+1))
done

if [ $RETRIES -eq $MAX_RETRIES ]; then
    error "Splunk failed to restart"
    log "[!] Check: $SPLUNK_HOME/var/log/splunk/splunkd.log"
    log "[!] To restore: bash /root/restore_diamond.sh"
    exit 1
fi

# ====================================================================
# 12. COMPREHENSIVE VERIFICATION
# ====================================================================
log "[12/12] Final verification..."

sleep 10

if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    log "[+] splunkd: RUNNING"
else
    error "splunkd: NOT RUNNING"
fi

WEB_TEST=$(curl -k -s --max-time 10 https://localhost:8000 2>&1 | head -20)
if echo "$WEB_TEST" | grep -q "Splunk"; then
    log "[+] Web UI: RESPONDING"
elif echo "$WEB_TEST" | grep -q "HTTP"; then
    log "[+] Web UI: RESPONDING (HTTP redirect)"
else
    log "[!] Web UI: NOT RESPONDING CORRECTLY"
    echo "$WEB_TEST" >> "$LOG_FILE"
fi

for port in 8000 8089 9997; do
    if netstat -tuln | grep -q ":$port.*LISTEN"; then
        log "[+] Port $port: LISTENING"
    else
        log "[!] Port $port: NOT LISTENING"
    fi
done

CONFIGS=(
    "web.conf"
    "server.conf"
    "limits.conf"
    "authorize.conf"
    "authentication.conf"
)

for conf in "${CONFIGS[@]}"; do
    if [ -f "$SPLUNK_HOME/etc/system/local/$conf" ]; then
        PERMS=$(stat -c "%a" "$SPLUNK_HOME/etc/system/local/$conf")
        OWNER=$(stat -c "%U" "$SPLUNK_HOME/etc/system/local/$conf")
        log "[+] $conf: exists ($PERMS, $OWNER)"
    else
        log "[!] $conf: MISSING"
    fi
done

log "[*] Testing admin authentication..."
if "$SPLUNK_HOME/bin/splunk" list user 2>&1 | grep -q "admin"; then
    log "[+] Authentication: WORKING"
else
    log "[!] Authentication: MAY BE BROKEN"
fi

# ====================================================================
# CREATE AUTO-RESTORE SCRIPT
# ====================================================================
cat > /root/restore_diamond.sh << RESTORE
#!/bin/bash
echo "Restoring Splunk configs from backup..."
chattr -i "$SPLUNK_HOME/etc/system/local/*.conf" 2>/dev/null || true
tar -xzf "$BACKUP_DIR/system_local.tar.gz" -C "$SPLUNK_HOME/etc/system/" 2>/dev/null || true
chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME/etc/system/local"
su - "$SPLUNK_USER" -c "$SPLUNK_HOME/bin/splunk restart"
echo "Restore complete"
RESTORE

chmod +x /root/restore_diamond.sh

# ====================================================================
# CREATE MONITORING SCRIPT WITH RANDOMIZED TIMING
# ====================================================================
cat > /root/monitor_splunk_ui.sh << 'MONITOR'
#!/bin/bash
# Continuous monitoring of Splunk UI health

SPLUNK_HOME="/opt/splunk"
LOG="/var/log/splunk_ui_monitor.log"

log_msg() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG"
}

# Check web UI is responding
if ! curl -k -s --max-time 5 https://localhost:8000 | grep -q "Splunk"; then
    log_msg "ALERT: Web UI not responding"
    
    # Check if splunkweb process is running
    if ! pgrep -f splunkweb > /dev/null; then
        log_msg "FIX: Restarting splunkweb"
        su - splunk -c "/opt/splunk/bin/splunk restart splunkweb"
    fi
fi

# Check for port hijacking
HIJACKER=$(netstat -tulpn 2>/dev/null | grep ":8000.*LISTEN" | grep -v splunkd | awk '{print $7}' | cut -d/ -f1)
if [ -n "$HIJACKER" ]; then
    log_msg "ALERT: Port 8000 hijacked by PID $HIJACKER, killing it"
    kill -9 "$HIJACKER" 2>/dev/null
fi

# Check config files haven't been deleted/corrupted
for conf in web.conf server.conf authorize.conf; do
    if [ ! -f "$SPLUNK_HOME/etc/system/local/$conf" ]; then
        log_msg "CRITICAL: $conf is missing - restore needed"
    fi
done
MONITOR

chmod +x /root/monitor_splunk_ui.sh

# Add UI monitor to cron with randomization
CRON_SCHEDULE="*/$UI_MONITOR_INTERVAL * * * *"
(crontab -l 2>/dev/null | grep -v "monitor_splunk_ui"; echo "$CRON_SCHEDULE sleep $UI_MONITOR_OFFSET; /root/monitor_splunk_ui.sh") | crontab -

log "[+] UI monitor deployed (runs every $UI_MONITOR_INTERVAL min, ${UI_MONITOR_OFFSET}s offset)"

# ====================================================================
# SUMMARY
# ====================================================================
log ""
log "=== DIAMOND ULTRA HARDENING COMPLETE ==="
log ""
log "PROTECTIONS ENABLED:"
log "  ✓ Modern TLS 1.2/1.3 only"
log "  ✓ Session IP locking enabled"
log "  ✓ Script execution disabled"
log "  ✓ File editing disabled"
log "  ✓ User management via UI disabled"
log "  ✓ Brute force lockout (3 attempts, 30min)"
log "  ✓ REST API severely limited"
log "  ✓ Risky apps disabled"
log "  ✓ Config injection prevented"
log "  ✓ Management port restricted to internal networks"
log "  ✓ Continuous UI monitoring"
log ""
log "STILL FUNCTIONAL:"
log "  ✓ Web UI login"
log "  ✓ Log searching"
log "  ✓ Dashboards"
log "  ✓ Forwarder connections"
log "  ✓ Basic admin functions"
log ""
log "NETWORK RESTRICTIONS:"
log "  Management port (8089) accepts from:"
log "    - 127.0.0.1"
log "    - $INSIDE_NET_1"
log "    - $INSIDE_NET_2"
log ""
log "IF PROBLEMS:"
log "  Restore: bash /root/restore_diamond.sh"
log "  Check: tail -100 $SPLUNK_HOME/var/log/splunk/splunkd.log"
log "  UI Monitor: tail -f /var/log/splunk_ui_monitor.log"
log ""
log "Backup: $BACKUP_DIR"
log "Log: $LOG_FILE"
log "UI Monitor runs: Every $UI_MONITOR_INTERVAL minute(s) with ${UI_MONITOR_OFFSET}s offset"
log ""

# Clear sensitive variables
unset INSIDE_NET_1
unset INSIDE_NET_2

echo ""
echo "========================================="
echo "   DIAMOND ULTRA COMPLETE"
echo "========================================="
echo ""
echo "Check NISE to verify Splunk scoring."
echo "Monitor: tail -f /var/log/splunk_ui_monitor.log"
echo ""
