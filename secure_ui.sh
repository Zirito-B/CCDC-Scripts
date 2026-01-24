#!/bin/bash
# MWCCDC 2026 - SPLUNK UI HARDENING (NSA STANDARDS)
# OBJECTIVE: DISABLE RCE VECTORS, STRIP PRIVILEGES, HUNT BACKDOORS
# RUN AS ROOT

SPLUNK_HOME="/opt/splunk"

echo "!!! INITIATING UI HARDENING PROTOCOL !!!"

# Check for Root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root."
  exit
fi

# ==========================================
# 1. WEB INTERFACE HARDENING (web.conf)
# ==========================================
echo "[1] SECURING WEB INTERFACE..."

# Create local directory if missing
mkdir -p $SPLUNK_HOME/etc/system/local

# Unlock file if it exists (in case you ran script 1 already)
chattr -i $SPLUNK_HOME/etc/system/local/web.conf 2>/dev/null

# Check if [settings] stanza exists, if not add it
if ! grep -q "\[settings\]" $SPLUNK_HOME/etc/system/local/web.conf; then
    echo "[settings]" >> $SPLUNK_HOME/etc/system/local/web.conf
fi

# Append NSA-Level Security Settings
# enable_upload_apps=false  -> STOPS RCE via App Upload
# tools.sessions.timeout=5  -> Kicks idle users after 5 mins
# updateCheckerBaseURL=0    -> Stops "Phone Home" leaks
# x_frame_options_sameorigin -> Prevents Clickjacking
cat >> $SPLUNK_HOME/etc/system/local/web.conf <<EOF

# --- SECURITY HARDENING ---
enable_upload_apps = false
allow_remote_login = false
enable_insecure_login = false
updateCheckerBaseURL = 0
tools.sessions.timeout = 5
x_frame_options_sameorigin = true
force_https_to_transport = true
EOF

echo "[-] Web RCE Vectors Disabled."

# ==========================================
# 2. PRIVILEGE STRIPPING (authorize.conf)
# ==========================================
echo "[2] NEUTERING ADMIN CAPABILITIES..."
# We are modifying the 'admin' role to remove destructive capabilities.
# Even with the password, they cannot install backdoors or stop the server.

# Unlock authorize.conf
chattr -i $SPLUNK_HOME/etc/system/local/authorize.conf 2>/dev/null

cat >> $SPLUNK_HOME/etc/system/local/authorize.conf <<EOF
[role_admin]
# DISABLING DESTRUCTIVE CAPABILITIES
install_apps = disabled
run_script_search = disabled
restart_splunkd = disabled
edit_server = disabled
edit_monitor = disabled
edit_script = disabled
EOF

echo "[-] Admin Role Neutered (Cannot Install Apps/Scripts)."

# ==========================================
# 3. BACKDOOR HUNTING
# ==========================================
echo "[3] HUNTING FOR PRE-PLANTED SHELLS..."
echo "Scanning /etc/apps/ for suspicious Python/Shell scripts..."

# Create a log of findings
HUNT_LOG="/root/splunk_backdoor_scan.log"
echo "Scan started at $(date)" > $HUNT_LOG

# Find .py, .sh, .php, .pl files in the apps directory
# Exclude standard Splunk python files if possible, but listing them is safer
find $SPLUNK_HOME/etc/apps -type f \( -name "*.py" -o -name "*.sh" -o -name "*.php" -o -name "*.pl" \) -exec ls -la {} \; >> $HUNT_LOG

# Check for "subprocess" or "socket" usage in those files (Signs of reverse shells)
grep -rnE "subprocess|socket|os.system|/bin/sh|nc |ncat " $SPLUNK_HOME/etc/apps >> $HUNT_LOG

echo "[-] Scan Complete. REVIEW FILE: $HUNT_LOG"
echo "[-] If you see files in 'apps/search/bin' that you didn't put there, DELETE THEM."

# ==========================================
# 4. LOCKDOWN & RESTART
# ==========================================
echo "[4] APPLYING IMMUTABLE LOCKS..."

# Lock Configs so they cannot be edited
chattr +i $SPLUNK_HOME/etc/system/local/web.conf
chattr +i $SPLUNK_HOME/etc/system/local/authorize.conf

echo "[5] RESTARTING SPLUNK TO APPLY CHANGES..."
$SPLUNK_HOME/bin/splunk restart --accept-license --answer-yes --run-as-root

echo "!!! UI HARDENING COMPLETE !!!"
echo "1. App Uploads: DISABLED"
echo "2. Admin Permissions: RESTRICTED"
echo "3. Session Timeout: 5 MINUTES"
echo "4. Config Files: IMMUTABLE"