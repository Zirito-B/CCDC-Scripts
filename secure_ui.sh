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
EOF
echo "[+] Admin Role Neutered (Execution Disabled)."

if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    chmod -R -x "$SPLUNK_HOME/etc/apps"
    echo "[+] Removed executable permissions from all Splunk Apps."
fi

chattr -i "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null

cat >> "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
force_https_to_transport = true
sslVersions = tls1.2, tls1.3
EOF

chattr +i "$SPLUNK_HOME/etc/system/local/web.conf"
echo "[+] Web Config Hyper-Hardened."

echo "[+] Restarting Splunk..."
"$SPLUNK_HOME/bin/splunk" restart

echo "DIAMOND PROTOCOL COMPLETE."
