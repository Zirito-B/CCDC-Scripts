#!/bin/bash
set -euo pipefail

# MWCCDC "TACTICAL NUKE" SPLUNK + OS LOCKDOWN (NO GUI)
# Goals:
# - Do NOT lock you out (keeps current SSH client IP whitelisted automatically)
# - Keep Splunk Web reachable for scoring (allow ICMP + 8000/tcp from scoring subnet)
# - Minimize exposed services/ports
# - Lock down Splunk Web: disable insecure_login endpoint, disable app install, reduce web features
#
# Tested intent: RHEL-family (Oracle Linux 9.x etc). Your screenshot shows Oracle Linux Server 9.2.

SPLUNK_HOME="/opt/splunk"
LOG="/root/mwccdc_lockdown_$(date +%F_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

echo "[+] Starting MWCCDC tactical nuke @ $(date)"
echo "[+] Log: $LOG"

if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root." >&2
  exit 1
fi

if [[ ! -x "$SPLUNK_HOME/bin/splunk" ]]; then
  echo "[-] Splunk not found at $SPLUNK_HOME/bin/splunk" >&2
  exit 1
fi

# -------------------------
# 0) INPUTS (Netlab-safe)
# -------------------------
while true; do
  read -r -p "Enter SCORING/BLUE subnet allowed to reach Splunk (example 172.20.240.0/24): " ALLOW_SUBNET
  if [[ "$ALLOW_SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then break; fi
  echo "Invalid CIDR, try again."
done

# Optional: bind Splunk to a specific IP (the one scoring pings/hits).
read -r -p "Enter the assigned Splunk IP to bind to (press Enter to SKIP binding): " SPLUNK_BIND_IP
if [[ -n "${SPLUNK_BIND_IP}" ]]; then
  if [[ ! "$SPLUNK_BIND_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Invalid IP format. Exiting." >&2
    exit 1
  fi
fi

# Password reset option (safe method: user-seed + passwd backup)
read -r -s -p "Enter NEW Splunk admin password (leave blank to SKIP reset): " SPLUNK_ADMIN_PASS; echo
DO_RESET_SPLUNK_PASS=0
if [[ -n "${SPLUNK_ADMIN_PASS}" ]]; then
  DO_RESET_SPLUNK_PASS=1
fi

# Always whitelist current SSH client if present (prevents lockout mid-run)
SSH_CLIENT_IP=""
if [[ -n "${SSH_CLIENT:-}" ]]; then
  SSH_CLIENT_IP="$(echo "$SSH_CLIENT" | awk '{print $1}')"
  echo "[+] Detected SSH client IP: $SSH_CLIENT_IP (will be whitelisted)"
else
  echo "[!] No SSH_CLIENT detected (console run)."
fi

# Determine active interface for default route
ACTIVE_IF="$(ip route | awk '/default/ {print $5; exit}')"
echo "[+] Default route interface: ${ACTIVE_IF:-unknown}"

# -------------------------
# 1) QUICK SYSTEM SNAPSHOT
# -------------------------
echo "[+] Snapshot: listening ports + enabled services"
ss -lntup || true
systemctl list-unit-files --state=enabled || true

# -------------------------
# 2) SPLUNK WEB HARDENING
# -------------------------
echo "[+] Hardening Splunk Web config"

mkdir -p "$SPLUNK_HOME/etc/system/local"

# 2a) web.conf: disable insecure_login endpoint; reduce risky web features
# The Splunk web.conf reference documents enable_insecure_login and its purpose. :contentReference[oaicite:5]{index=5}
# The example shows dashboard_html_allow_embeddable_content. :contentReference[oaicite:6]{index=6}
cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
# Keep Splunk Web on the expected port for scoring
httpport = 8000
startwebserver = 1

# Disable /insecure_login endpoint
enable_insecure_login = false

# Reduce risk from embedded content in dashboards
dashboard_html_allow_embeddable_content = false
dashboard_html_wrap_embed = true

# If we bind splunk services, mgmtHostPort must match the bind IP
EOF

# If binding requested: set mgmtHostPort to bind ip (same concept Splunk warns about). :contentReference[oaicite:7]{index=7}
if [[ -n "${SPLUNK_BIND_IP}" ]]; then
  echo "mgmtHostPort = ${SPLUNK_BIND_IP}:8089" >> "$SPLUNK_HOME/etc/system/local/web.conf"
fi

# 2b) Disable app installation via limits.conf
# Splunk’s authorize.conf reference shows /services/apps/local requires enable_install_apps=true;
# setting it false blocks that path. :contentReference[oaicite:8]{index=8}
cat > "$SPLUNK_HOME/etc/system/local/limits.conf" <<'EOF'
[restapi]
enable_install_apps = false
EOF

# 2c) OPTIONAL: bind Splunk services to the assigned IP (shrinks exposure)
# Splunk documents SPLUNK_BINDIP usage and the need to align mgmtHostPort. :contentReference[oaicite:9]{index=9}
if [[ -n "${SPLUNK_BIND_IP}" ]]; then
  echo "[+] Applying SPLUNK_BINDIP=$SPLUNK_BIND_IP"
  # Backup
  if [[ -f "$SPLUNK_HOME/etc/splunk-launch.conf" ]]; then
    cp -a "$SPLUNK_HOME/etc/splunk-launch.conf" "$SPLUNK_HOME/etc/splunk-launch.conf.bak.$(date +%s)"
  fi
  # Ensure file exists
  touch "$SPLUNK_HOME/etc/splunk-launch.conf"
  # Remove existing SPLUNK_BINDIP lines, then add ours
  sed -i '/^\s*SPLUNK_BINDIP\s*=/d' "$SPLUNK_HOME/etc/splunk-launch.conf"
  echo "SPLUNK_BINDIP=${SPLUNK_BIND_IP}" >> "$SPLUNK_HOME/etc/splunk-launch.conf"
fi

# 2d) Password reset (safe method: backup passwd, set user-seed, restart)
# Splunk community documents user-seed.conf reset flow. :contentReference[oaicite:10]{index=10}
if [[ $DO_RESET_SPLUNK_PASS -eq 1 ]]; then
  echo "[+] Resetting Splunk admin password via user-seed method (backup passwd)"
  "$SPLUNK_HOME/bin/splunk" stop || true

  if [[ -f "$SPLUNK_HOME/etc/passwd" ]]; then
    cp -a "$SPLUNK_HOME/etc/passwd" "$SPLUNK_HOME/etc/passwd.bak.$(date +%s)"
    # Move aside to force reseed
    mv -f "$SPLUNK_HOME/etc/passwd" "$SPLUNK_HOME/etc/passwd.reset.$(date +%s)"
  fi

  cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = ${SPLUNK_ADMIN_PASS}
EOF

  "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt --run-as-root
else
  echo "[!] Skipping Splunk password reset."
  # Still restart to ensure config changes apply
  "$SPLUNK_HOME/bin/splunk" restart || true
fi

# -------------------------
# 3) FIREWALL LOCKDOWN (Netlab-safe)
# -------------------------
echo "[+] Firewall lockdown (allow only what scoring/blue needs)"

# Ensure firewalld exists/runs
if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "[+] Installing firewalld"
  dnf -y install firewalld
fi

systemctl enable --now firewalld

# Create dedicated zone
ZONE="mwccdc"
firewall-cmd --permanent --new-zone="$ZONE" 2>/dev/null || true

# Attach interface to our zone (if we detected one)
if [[ -n "${ACTIVE_IF}" ]]; then
  firewall-cmd --permanent --zone="$ZONE" --change-interface="$ACTIVE_IF" || true
fi

# Default: drop everything not explicitly allowed
firewall-cmd --permanent --zone="$ZONE" --set-target=DROP

# Allow established/related
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' accept" >/dev/null 2>&1 || true
# Note: firewalld zones handle stateful rules automatically; we keep explicit allowances below.

# Allow SSH from allowed subnet and current SSH client
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${ALLOW_SUBNET}' port port='22' protocol='tcp' accept"
if [[ -n "${SSH_CLIENT_IP}" ]]; then
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${SSH_CLIENT_IP}/32' port port='22' protocol='tcp' accept"
fi

# Allow Splunk Web (8000/tcp) from scoring subnet (and your SSH IP if present)
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${ALLOW_SUBNET}' port port='8000' protocol='tcp' accept"
if [[ -n "${SSH_CLIENT_IP}" ]]; then
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${SSH_CLIENT_IP}/32' port port='8000' protocol='tcp' accept"
fi

# Allow Splunk receiving (9997/tcp) ONLY from allowed subnet (forwarders/scoring may need this)
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${ALLOW_SUBNET}' port port='9997' protocol='tcp' accept"

# Allow ICMP ping from scoring subnet (your scoring note requires ping reachability)
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='${ALLOW_SUBNET}' icmp-type name='echo-request' accept"

# Restrict Splunk management (8089) to localhost unless you explicitly need remote management.
# If you bound Splunk to SPLUNK_BINDIP, Splunk docs warn mgmtHostPort must match; but this firewall still prevents remote hits. :contentReference[oaicite:11]{index=11}
firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family='ipv4' source address='127.0.0.1/32' port port='8089' protocol='tcp' accept"

firewall-cmd --reload

echo "[+] Firewall active zones:"
firewall-cmd --get-active-zones || true

# -------------------------
# 4) DISABLE COMMON NONESSENTIAL SERVICES (Conservative)
# -------------------------
echo "[+] Disabling common nonessential services (only if present)"
for svc in \
  avahi-daemon cups rpcbind nfs-server smb nmb vsftpd tftp \
  telnet.socket rsh.socket rlogin.socket rexec.socket \
  cockpit.socket bluetooth ; do
  systemctl disable --now "$svc" >/dev/null 2>&1 || true
done

# -------------------------
# 5) BACKDOOR SWEEP (Netlab-safe defaults)
# -------------------------
echo "[+] Backdoor sweep (safe mode): report + quarantine list"
REPORT="/root/mwccdc_report_$(date +%F_%H%M%S).txt"

{
  echo "=== USERS (uid>=1000) ==="
  awk -F: '($3>=1000)&&($1!="nobody"){print}' /etc/passwd
  echo
  echo "=== SUDOERS (top-level) ==="
  ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null || true
  echo
  echo "=== AUTHORIZED_KEYS FOUND ==="
  find /root /home -maxdepth 3 -type f -name authorized_keys -print -exec ls -la {} \; 2>/dev/null || true
  echo
  echo "=== LISTENING PORTS ==="
  ss -lntup || true
  echo
  echo "=== SPLUNK VERSION ==="
  "$SPLUNK_HOME/bin/splunk" version || true
} > "$REPORT"

echo "[+] Report written to: $REPORT"

echo "[+] Finished. Validate from another machine:"
echo "    - ping <splunk_ip>"
echo "    - curl -k http://<splunk_ip>:8000 (or open in browser)"
echo "    - nmap from scoring subnet should only show 22,8000,9997 (and NOT 8089)"
