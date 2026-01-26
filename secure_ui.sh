#!/bin/bash
set -u

# ==============================================================================
# CCDC 2026: SPLUNK WEB UI "DIAMOND" HARDENING
# FOCUS: NEUTERING ADMIN & STERILIZING APPS
# ==============================================================================

SPLUNK_HOME="/opt/splunk"
LOG="/var/log/splunk_diamond.log"

echo "Applying DIAMOND Level UI Hardening..."

# 1. NEUTER THE ADMIN ROLE (Score but don't Execute)
# We modify authorize.conf to remove dangerous capabilities from 'admin'
# This prevents you (or a hacker with your creds) from running shell commands via Search.
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat >> "$SPLUNK_HOME/etc/system/local/authorize.conf" <<EOF
[role_admin]
# Remove ability to run script searches (RCE Vector)
run_script_search = disabled
# Remove ability to edit server configs via API
edit_server = disabled
edit_monitor = disabled
edit_script = disabled
EOF
echo "[+] Admin Role Neutered (Execution Disabled)."

# 2. APP STERILIZATION (Kill Executables)
# Recursively remove +x from ALL files in etc/apps.
# This stops binary backdoors from running.
if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    chmod -R -x "$SPLUNK_HOME/etc/apps"
    echo "[+] Removed executable permissions from all Splunk Apps."
fi

# 3. WEB CONF PERFECTION
# Unlock file first
chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null

cat >> "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
# STRICT SECURITY
force_https_to_transport = true
sslVersions = tls1.2, tls1.3
# PREVENT REMOTE LOGIN (If you are using SSH Tunneling)
# allow_remote_login = false 
EOF

# Lock it back up immediately
chattr +i "$SPLUNK_HOME/etc/system/local/web.conf"
echo "[+] Web Config Hyper-Hardened."

# 4. RESTART TO APPLY
echo "[+] Restarting Splunk..."
"$SPLUNK_HOME/bin/splunk" restart

echo "DIAMOND PROTOCOL COMPLETE."
