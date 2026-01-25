#!/bin/bash
# MWCCDC 2026 - TITANIUM HYBRID LOCKDOWN (Oracle Linux 9.x / Splunk in /opt/splunk)
# RUN AS ROOT
#
# Goals:
# - Reset root + splunk admin password
# - Clear common persistence (cron + ssh authorized_keys)
# - Reset Splunk (clean all) + seed admin
# - Configure firewalld to default DROP and only allow SSH + Splunk from your Blue subnet
# - Install GNOME GUI via DNF group "Server with GUI" and boot to graphical.target
# - Disable kdump + remove crashkernel boot arg to avoid the “Crash recovery kernel arming…” boot hang
# - Enable persistent audit rules (auditctl rules alone are not persistent across reboot)
#
# Notes backed by docs:
# - Oracle: DNF group “Server with GUI” installs GNOME. :contentReference[oaicite:0]{index=0}
# - systemd default target uses target units like graphical.target. :contentReference[oaicite:1]{index=1}
# - auditctl rules are not persistent unless put into audit rules files. :contentReference[oaicite:2]{index=2}
# - chattr immutable prevents modification until removed. :contentReference[oaicite:3]{index=3}
# - firewalld rich rules syntax supports source address + accept. :contentReference[oaicite:4]{index=4}

set -Eeuo pipefail

LOG="/var/log/titanium_lockdown_$(date +%F_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

die() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

need_cmd bash
need_cmd awk
need_cmd sed
need_cmd ip
need_cmd systemctl

echo "!!! STARTING TITANIUM HYBRID PROTOCOL !!!"
echo "Log: $LOG"

# --------------------------
# 0) Environment checks
# --------------------------
SPLUNK_HOME="/opt/splunk"
if [[ ! -x "$SPLUNK_HOME/bin/splunk" ]]; then
  die "Splunk not found at $SPLUNK_HOME/bin/splunk"
fi

# Prefer dnf on OL9 (yum may exist as wrapper)
if command -v dnf >/dev/null 2>&1; then
  PM="dnf"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"
else
  die "Neither dnf nor yum found"
fi

echo "[0] Package manager: $PM"
echo "[0] OS fingerprint:"
cat /etc/os-release || true
uname -r || true

# --------------------------
# 1) Interactive input
# --------------------------
while true; do
  read -r -p "Enter Blue Team Subnet (e.g., 172.20.240.0/24): " BLUE_SUBNET
  if [[ "$BLUE_SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then break; fi
  echo "Invalid format. Try again."
done

while true; do
  echo ""
  read -r -s -p "Enter NEW Root + Splunk admin password: " ADMIN_PASS; echo ""
  read -r -s -p "Confirm password: " ADMIN_PASS_CONFIRM; echo ""
  if [[ -n "$ADMIN_PASS" && "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]]; then break; fi
  echo "Mismatch. Try again."
done

# Optional: immutable lock at end (default NO because it can lock you out if misused)
read -r -p "Enable immutable lock at the END (y/N)? " IMMUTABLE_CHOICE || true
IMMUTABLE_CHOICE="${IMMUTABLE_CHOICE:-N}"

# --------------------------
# 2) OS hardening: passwords, persistence
# --------------------------
echo "[1] Setting root password..."
echo "root:$ADMIN_PASS" | chpasswd

echo "[2] Flushing common persistence..."
# Crontab + per-user crons
: > /etc/crontab
rm -rf /var/spool/cron/* || true

# Remove SSH authorized_keys for root + any home dirs that exist
if [[ -d /root/.ssh ]]; then : > /root/.ssh/authorized_keys || true; fi
for d in /home/*; do
  [[ -d "$d/.ssh" ]] || continue
  : > "$d/.ssh/authorized_keys" || true
done

# DO NOT blindly pkill everyone; it can kill your own management session.
# If you want to kill non-root user processes, do it carefully:
echo "[3] Optionally killing non-root interactive user processes (safe loop)..."
while read -r u _; do
  [[ "$u" == "root" ]] && continue
  [[ -z "$u" ]] && continue
  echo " - pkill -KILL -u $u (if any)"
  pkill -KILL -u "$u" 2>/dev/null || true
done < <(who | awk '{print $1}' | sort -u)

# --------------------------
# 3) Splunk reset + seed admin
# --------------------------
echo "[4] Stopping Splunk..."
"$SPLUNK_HOME/bin/splunk" stop || true

echo "[5] Splunk clean all (factory reset)..."
"$SPLUNK_HOME/bin/splunk" clean all -f

echo "[6] Seeding Splunk admin user..."
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = $ADMIN_PASS
EOF

# Minimal hardening that is unlikely to break startup
echo "[7] Writing Splunk web.conf (disable app uploads)..."
cat > "$SPLUNK_HOME/etc/system/local/web.conf" <<EOF
[settings]
httpport = 8000
startwebserver = 1
enable_upload_apps = false
EOF

echo "[8] Starting Splunk..."
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt --run-as-root

# --------------------------
# 4) Firewall: default DROP + allow only from Blue subnet
# --------------------------
echo "[9] Configuring firewalld whitelist..."
$PM -y install firewalld >/dev/null 2>&1 || true
systemctl enable --now firewalld

# Identify active interface for default route
ACTIVE_IF="$(ip route | awk '/default/ {print $5; exit}')"
if [[ -z "$ACTIVE_IF" ]]; then
  die "Could not determine active interface from default route"
fi
echo "Active interface: $ACTIVE_IF"

# Drop everything by default on that interface
firewall-cmd --set-default-zone=drop
firewall-cmd --zone=drop --change-interface="$ACTIVE_IF"

# Allow SSH + Splunk Web + Splunk Forwarder port only from Blue subnet
# Use rich rules so 8000 is NOT open to the whole world.
firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='22' protocol='tcp' accept"
firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='8000' protocol='tcp' accept"
firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='$BLUE_SUBNET' port port='9997' protocol='tcp' accept"
firewall-cmd --reload

# --------------------------
# 5) Auditd: persistent rules
# --------------------------
echo "[10] Enabling auditd with persistent rules..."
$PM -y install audit >/dev/null 2>&1 || true
systemctl enable --now auditd

# Persistent rules file (auditctl rules alone do not persist across reboot) :contentReference[oaicite:5]{index=5}
cat > /etc/audit/rules.d/99-titanium.rules <<'EOF'
-D
-b 8192
--backlog_wait_time 60000
# Monitor process execution (b64). Add b32 too if you run 32-bit binaries.
-a always,exit -F arch=b64 -S execve -k exec_monitoring
EOF

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load || true
else
  # Fallback: load directly via auditctl from a file (still loads now; persistence is via rules file)
  auditctl -R /etc/audit/rules.d/99-titanium.rules || true
fi

# --------------------------
# 6) GUI install + boot fix (kdump/crashkernel + Wayland)
# --------------------------
echo "[11] Installing GUI (GNOME) via DNF group 'Server with GUI'..."
# Oracle documents group usage and that “Server with GUI” installs GNOME. :contentReference[oaicite:6]{index=6}
$PM -y install dnf-plugins-core >/dev/null 2>&1 || true

# Enabling repos may fail in netlab/offline mirrors; do not hard-fail.
if command -v dnf >/dev/null 2>&1; then
  dnf config-manager --set-enabled ol9_appstream ol9_baseos 2>/dev/null || true
fi

# DO NOT run a full update here if you want competition reproducibility.
$PM -y groupinstall "Server with GUI" || $PM -y group install "Server with GUI"

echo "[12] Preventing boot hang: disabling kdump + removing crashkernel boot arg..."
systemctl disable --now kdump 2>/dev/null || true
systemctl mask kdump 2>/dev/null || true

# grubby may not exist in some minimal images; only run if present.
if command -v grubby >/dev/null 2>&1; then
  grubby --update-kernel=ALL --remove-args="crashkernel" || true
fi

echo "[13] Disabling Wayland in GDM (forces Xorg login path)..."
# Make this idempotent and safe even if the line is missing.
GDM_CONF="/etc/gdm/custom.conf"
mkdir -p "$(dirname "$GDM_CONF")"
touch "$GDM_CONF"
if ! grep -q '^\[daemon\]' "$GDM_CONF"; then
  printf "[daemon]\n" >> "$GDM_CONF"
fi

if grep -q '^WaylandEnable=' "$GDM_CONF"; then
  sed -i 's/^WaylandEnable=.*/WaylandEnable=false/' "$GDM_CONF"
else
  # Insert under [daemon] if possible; else append.
  awk '
    BEGIN{done=0}
    /^\[daemon\]/{print; print "WaylandEnable=false"; done=1; next}
    {print}
    END{if(!done) print "WaylandEnable=false"}
  ' "$GDM_CONF" > "${GDM_CONF}.tmp" && mv "${GDM_CONF}.tmp" "$GDM_CONF"
fi

echo "[14] Setting default target to graphical.target and enabling display manager..."
# Default target is a target unit such as graphical.target. :contentReference[oaicite:7]{index=7}
systemctl set-default graphical.target
systemctl enable --now gdm 2>/dev/null || true

# --------------------------
# 7) Immutable lock (optional, at END only)
# --------------------------
if [[ "$IMMUTABLE_CHOICE" =~ ^[Yy]$ ]]; then
  echo "[15] Creating emergency unlock script before immutable lock..."
  cat > /root/unlock_immutable.sh <<'EOF'
#!/bin/bash
set -e
chattr -i /etc/passwd || true
chattr -i /etc/shadow || true
chattr -i /opt/splunk/etc/passwd || true
chattr -i /opt/splunk/etc/system/local/web.conf || true
echo "Immutable flags removed (where present)."
EOF
  chmod 700 /root/unlock_immutable.sh

  echo "[16] Applying immutable flags (can block future changes until removed)..."
  # Immutable prevents modification until removed. :contentReference[oaicite:8]{index=8}
  chattr +i /etc/passwd || true
  chattr +i /etc/shadow || true
  chattr +i /opt/splunk/etc/passwd 2>/dev/null || true
  chattr +i /opt/splunk/etc/system/local/web.conf 2>/dev/null || true
  echo "Immutable lock applied. Emergency unlock: /root/unlock_immutable.sh"
else
  echo "[15] Immutable lock skipped (recommended for reliability)."
fi

echo "!!! DONE. Reboot when ready: reboot"
echo "Post-checks:"
echo "  systemctl get-default"
echo "  systemctl status gdm --no-pager"
echo "  systemctl status splunk --no-pager || $SPLUNK_HOME/bin/splunk status"
echo "  firewall-cmd --zone=drop --list-rich-rules"
echo "  auditctl -l"
