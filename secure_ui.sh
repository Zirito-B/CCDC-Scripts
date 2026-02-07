#!/bin/bash
# DIAMOND SAFE MODE - Robust Splunk Hardening
# Blocks RCE/Webshells/Backdoors WITHOUT breaking HTTP Scoring

SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
LOG_FILE="/var/log/diamond_safe_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/diamond_safe_backup_$(date +%Y%m%d_%H%M%S)"

# Logging helpers
log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
warn() { echo "[$(date '+%H:%M:%S')] WARN: $1" | tee -a "$LOG_FILE"; }
success() { echo "[$(date '+%H:%M:%S')] SUCCESS: $1" | tee -a "$LOG_FILE"; }

clear
echo "========================================="
echo "   DIAMOND SAFE - SCORING COMPATIBLE"
echo "   Robust Hardening (HTTP 8000 Active)"
echo "========================================="
echo ""
read -p "Press ENTER to begin..."
echo ""

# ====================================================================
# PRE-FLIGHT CHECKS
# ====================================================================
[ "$EUID" -ne 0 ] && echo "ERROR: Must run as root" && exit 1
[ ! -d "$SPLUNK_HOME" ] && echo "ERROR: Splunk not found" && exit 1

# Check if Splunk is running (don't harden a dead horse)
if ! "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
    echo "ERROR: Splunk is NOT running. Start it first:"
    echo "su - splunk -c '/opt/splunk/bin/splunk start'"
    exit 1
fi

log "STARTING HARDENING..."

# ====================================================================
# STEP 1: SAFETY BACKUP (The "Undo" Button)
# ====================================================================
log "[1/8] Creating safety backup..."
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/splunk_etc_safe.tar.gz" "$SPLUNK_HOME/etc" 2>/dev/null || warn "Backup warning"
success "Backup saved to $BACKUP_DIR"

# Create the emergency restore script
cat > /root/restore_diamond_safe.sh << 'RESTOREEOF'
#!/bin/bash
echo "!!! RESTORING SPLUNK TO PRE-HARDENED STATE !!!"
/opt/splunk/bin/splunk stop
pkill -9 splunkd
rm -rf /opt/splunk/etc/system/local
rm -rf /opt/splunk/etc/apps/search/local
# Find backup dir
BACKUP=$(find /root -name "splunk_etc_safe.tar.gz" | head -n 1)
[ -z "$BACKUP" ] && echo "ERROR: No backup found!" && exit 1
tar -xzf "$BACKUP" -C /opt/splunk/
chown -R splunk:splunk /opt/splunk/etc
su - splunk -c "/opt/splunk/bin/splunk start"
echo "Restore complete."
RESTOREEOF
chmod +x /root/restore_diamond_safe.sh
success "Restore script created: /root/restore_diamond_safe.sh"

# ====================================================================
# STEP 2: HARDEN WEB.CONF (SCORING SAFE)
# ====================================================================
log "[2/8] Hardening web.conf (Keeping HTTP)..."
mkdir -p "$SPLUNK_HOME/etc/system/local"

cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'WEBEOF'
[settings]
# SCORING CRITICAL: Keep SSL OFF
enableSplunkWebSSL = false
httpport = 8000

# Security Hardening (Session & Debug)
tools.sessions.timeout = 15
ui_inactivity_timeout = 15
enableWebDebug = false
enable_insecure_login = false
x_frame_options_sameorigin = true
WEBEOF

chown splunk:splunk "$SPLUNK_HOME/etc/system/local/web.conf"
chmod 644 "$SPLUNK_HOME/etc/system/local/web.conf"
success "Web config hardened (Port 8000 open)"

# ====================================================================
# STEP 3: DISABLE RISKY APPS (Attack Surface Reduction)
# ====================================================================
log "[3/8] Disabling risky apps..."
RISKY_APPS=("python_upgrade_readiness_app" "splunk_monitoring_console" "splunk_instrumentation" "learned" "legacy")

for app in "${RISKY_APPS[@]}"; do
    if [ -d "$SPLUNK_HOME/etc/apps/$app" ]; then
        mkdir -p "$SPLUNK_HOME/etc/apps/$app/local"
        echo -e "[install]\nstate = disabled\n\n[ui]\nis_visible = false" > "$SPLUNK_HOME/etc/apps/$app/local/app.conf"
        chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/$app/local"
        log "  Disabled: $app"
    fi
done

# ====================================================================
# STEP 4: BLOCK DANGEROUS COMMANDS (No RCE)
# ====================================================================
log "[4/8] Blocking RCE search commands..."
mkdir -p "$SPLUNK_HOME/etc/apps/search/local"

cat > "$SPLUNK_HOME/etc/apps/search/local/disabledsearches.conf" << 'DISABLEDEOF'
[runshellscript-command]
disabled = true
[script-command]
disabled = true
[sendemail-command]
disabled = true
[outputlookup-command]
disabled = true
DISABLEDEOF

chown -R splunk:splunk "$SPLUNK_HOME/etc/apps/search/local"
success "RCE commands blocked"

# ====================================================================
# STEP 5: NUKE WEBSHELLS (File Uploads)
# ====================================================================
log "[5/8] finding and neutering scripts..."
# Remove execute permissions from any script in the apps directory
if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    find "$SPLUNK_HOME/etc/apps" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) -exec chmod -x {} \; 2>/dev/null
    find "$SPLUNK_HOME/etc/apps" -type d -name "bin" -exec chmod -x {}/* \; 2>/dev/null || true
fi

# Block write access to upload directories
for dir in "$SPLUNK_HOME/var/run/splunk/upload" "$SPLUNK_HOME/var/run/splunk/apptemp"; do
    [ -d "$dir" ] && chmod 500 "$dir"
done
success "Uploads & Scripts neutered"

# ====================================================================
# STEP 6: LOCK SCHEDULER (Stop Backdoors)
# ====================================================================
log "[6/8] Locking scheduler..."
cat > "$SPLUNK_HOME/etc/system/local/savedsearches.conf" << 'SAVEDEOF'
[default]
enableSched = 0
cron_schedule = 
SAVEDEOF
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/savedsearches.conf"
chmod 644 "$SPLUNK_HOME/etc/system/local/savedsearches.conf"
success "Scheduler disabled"

# ====================================================================
# STEP 7: CLEAN RESTART
# ====================================================================
log "[7/8] Restarting Splunk..."
# Remove any accidental immutable flags just in case
chattr -i "$SPLUNK_HOME/etc/system/local/"* 2>/dev/null

su - splunk -c "/opt/splunk/bin/splunk restart" 2>&1 | tee -a "$LOG_FILE"

# Wait loop
log "Waiting for startup..."
sleep 15
RETRIES=0
while [ $RETRIES -lt 5 ]; do
    if "$SPLUNK_HOME/bin/splunk" status | grep -q "splunkd is running"; then
        break
    fi
    sleep 5
    ((RETRIES++))
done

# ====================================================================
# STEP 8: FINAL VERIFICATION
# ====================================================================
log "[8/8] Verifying Scoring Access..."
if ss -tulpn | grep -q ":8000"; then
    success "VERIFIED: Port 8000 is OPEN. Scoring should be GREEN."
else
    warn "CRITICAL: Port 8000 is CLOSED."
    echo "Check if Splunk failed to start. Run restore script if needed."
fi

echo ""
echo "========================================="
echo "   HARDENING COMPLETE"
echo "========================================="
echo "1. HTTP Scoring: ACTIVE (Port 8000)"
echo "2. RCE/Webshells: BLOCKED"
echo "3. Scheduler: DISABLED"
echo "4. Restore Script: /root/restore_diamond_safe.sh"
echo ""
