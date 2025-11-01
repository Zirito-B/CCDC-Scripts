# 1. Remove the broken rules (it's OK if these say "error: NOT_ENABLED")
firewall-cmd --permanent --zone=public --remove-rich-rule='rule protocol value="tcp" ct state is "ESTABLISHED,RELATED" accept'
firewall-cmd --permanent --zone=public --remove-rich-rule='rule protocol value="udp" ct state is "ESTABLISHED,RELATED" accept'
firewall-cmd --permanent --zone=public --remove-rich-rule='rule state="ESTABLISHED,RELATED" accept'

# 2. This is the MAIN FIX.
# We are changing from a stateless DROP to a stateful BLOCK.
firewall-cmd --permanent --zone=public --set-target=default
firewall-cmd --permanent --zone=public --set-default-action=block

# 3. Re-apply all the correct rules to be safe
firewall-cmd --permanent --zone=trusted --add-interface=lo
firewall-cmd --permanent --zone=public --add-port=8000/tcp
firewall-cmd --permanent --zone=public --add-port=8089/tcp
firewall-cmd --permanent --zone=public --add-port=9997/tcp
firewall-cmd --permanent --zone=public --add-protocol=icmp
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="172.20.242.0/24" service name="ssh" accept'
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="172.20.240.0/24" service name="ssh" accept'

# 4. Apply all changes
firewall-cmd --reload

# 5. Check the final config
firewall-cmd --list-all
