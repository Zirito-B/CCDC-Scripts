#!/bin/bash
set -u

SPLUNK_HOME="/opt/splunk"
LOG="/var/log/splunk_diamond.log"

echo "Applying DIAMOND Level UI Hardening..."

mkdir -p "$SPLUNK_HOME/etc/system/local"

cat >> "$SPLUNK_HOME/etc/system/local/authorize.conf" <<EOF
[role_admin]
run_script_search = disabled
edit_server = disabled
edit_monitor = disabled
edit_script = disabled
schedule_search = disabled
dispatch_rest_to_indexers = disabled
EOF

echo "[+] Admin Role Execution and Scheduling Disabled."

if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    chmod -R -x "$SPLUNK_HOME/etc/apps"
    echo "[+] Executable permissions removed from Splunk Apps."
fi

chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null

cat >> "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
force_https_to_transport = true
sslVersions = tls1.2, tls1.3
enableWebDebug = false
enable_rss = false
enable_session_ip_locking = true
EOF

chattr +i "$SPLUNK_HOME/etc/system/local/web.conf"

cat >> "$SPLUNK_HOME/etc/system/local/limits.conf" <<EOF
[restapi]
maxclients = 10
maxoutstanding = 10
EOF

echo "[+] Web UI and REST API Hardened."

echo "[+] Restarting Splunk..."
"$SPLUNK_HOME/bin/splunk" restart

sleep 10

chattr +i "$SPLUNK_HOME/etc/system/local/authorize.conf"

echo "DIAMOND PROTOCOL COMPLETE."
