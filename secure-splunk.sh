#!/bin/bash

# ====================================================================
# === CONFIGURATION FROM Team_Password_Sheet.docx (Source 493) ===
# ====================================================================
# VM 3 - Splunk
NEW_ROOT_PASS='Malenia#24ER'
NEW_SYSADMIN_PASS='Hollows@DS3X'
NEW_SPLUNK_ADMIN_PASS='Siegward#7X!'
# ====================================================================

# Default credentials from 2025MWCCDCITeamPack_.pdf (Source 268)
DEFAULT_SPLUNK_USER='admin'
DEFAULT_SPLUNK_PASS='changeme'

# Your internal networks from 2025MWCCDCITeamPack_.pdf (Source 268)
INSIDE_NET_1="172.20.242.0/24"
INSIDE_NET_2="172.20.240.0/24"
# ====================================================================


echo "[*] Starting Splunk hardening script..."

# 1. Change OS User Passwords (Source 493)
echo "[*] Changing OS user passwords (root, sysadmin)..."
echo "root:$NEW_ROOT_PASS" | chpasswd
echo "sysadmin:$NEW_SYSADMIN_PASS" | chpasswd

# 2. NUKE ALL CRON JOBS & PERSISTENCE
echo "[*] Nuking all known cron job and persistence locations..."
# Clear system-wide crontab and cron directories
echo "" > /etc/crontab
rm -rf /etc/cron.d/*
rm -rf /etc/cron.hourly/*
rm -rf /etc/cron.daily/*
rm -rf /etc/cron.weekly/*
rm -rf /etc/cron.monthly/*

# Clear crontabs for ALL users with a valid shell
echo "[*] Wiping crontabs for all users..."
for user in $(cut -f1,7 -d: /etc/passwd | egrep -v '(/bin/false|/sbin/nologin)$' | cut -f1 -d:); do
    echo "  - Wiping cron for user: $user"
    crontab -u $user -r 2>/dev/null
done

# Clear authorized_keys for ALL users
echo "[*] Wiping authorized_keys for all users..."
for dir in $(cut -f6 -d: /etc/passwd); do
    if [ -f "$dir/.ssh/authorized_keys" ]; then
        echo "  - Wiping authorized_keys in $dir"
        echo "" > "$dir/.ssh/authorized_keys"
    fi
done
# Explicitly get root and sysadmin, just in case
echo "" > /root/.ssh/authorized_keys
echo "" > /home/sysadmin/.ssh/authorized_keys


# 3. Reset Splunk Admin Password (Source 268, 493)
echo "[*] Resetting Splunk 'admin' password to '$NEW_SPLUNK_ADMIN_PASS'..."
/opt/splunk/bin/splunk edit user "$DEFAULT_SPLUNK_USER" -password "$NEW_SPLUNK_ADMIN_PASS" -auth "$DEFAULT_SPLUNK_USER:$DEFAULT_SPLUNK_PASS"
echo "[*] Restarting Splunk service..."
/opt/splunk/bin/splunk restart

# 4. Configure Firewall (firewalld for Oracle Linux 9)
echo "[*] Configuring firewalld..."
systemctl enable --now firewalld
firewall-cmd --permanent --zone=public --set-target=DROP
firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="tcp" ct state is "ESTABLISHED,RELATED" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="udp" ct state is "ESTABLISHED,RELATED" accept'
firewall-cmd --permanent --zone=public --add-interface=lo --set-target=ACCEPT

# Allow ICMP (Ping) from ANY - CCDC Rule 12 (Source 413)
firewall-cmd --permanent --zone=public --add-protocol=icmp

# Allow Splunk services from ANY (for scoring engine) (Source 268)
firewall-cmd --permanent --zone=public --add-port=8000/tcp  # Splunk Web UI
firewall-cmd --permanent --zone=public --add-port=8089/tcp  # Splunk Management
firewall-cmd --permanent --zone=public --add-port=9997/tcp  # Splunk Indexing

# Allow SSH *only* from your internal networks (Source 268)
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="'"$INSIDE_NET_1"'" service name="ssh" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="'"$INSIDE_NET_2"'" service name="ssh" accept'

echo "[*] Reloading firewall..."
firewall-cmd --reload

# 5. Harden SSH Configuration
echo "[*] Hardening SSH configuration..."
# Disable root login over SSH
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
echo "[*] Restarting SSH service..."
systemctl restart sshd

# 6. Create Service 'Babysitter' for Uptime (Source 464)
echo "[*] Creating service 'babysitter' cron job for Splunk uptime..."
# Create a script for cron to run
echo '#!/bin/bash' > /root/check_splunk.sh
echo 'if ! /opt/splunk/bin/splunk status | grep -q "splunkd is running"; then' >> /root/check_splunk.sh
echo '  /opt/splunk/bin/splunk start' >> /root/check_splunk.sh
echo 'fi' >> /root/check_splunk.sh
chmod +x /root/check_splunk.sh

# Add *our* new cron job to root's crontab (after we just wiped it)
(crontab -l 2>/dev/null; echo "* * * * * /root/check_splunk.sh") | crontab -

echo ""
echo "[*] Splunk hardening script finished!"
echo "[*] All non-essential cron jobs have been nuked."
echo "[*] REMEMBER: You must now log in as 'sysadmin' and use 'sudo' for root commands."
echo ""
