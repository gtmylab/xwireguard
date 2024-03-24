#!/bin/bash

# Update package list
sudo apt update

# Install Wireguard
sudo apt install wireguard -y

# Generate Wireguard keys
private_key=$(wg genkey)
echo "$private_key" | sudo tee /etc/wireguard/private.key
public_key=$(echo "$private_key" | wg pubkey)
echo "PrivateKey = $private_key" | sudo tee -a /etc/wireguard/wg0.conf
echo "PublicKey = $public_key" | sudo tee -a /etc/wireguard/wg0.conf

# Enable IPv4 and IPv6 forwarding
sudo sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sudo sed -i '/^#net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf

# Apply changes
sudo sysctl -p

# Configure firewall (UFW)
sudo ufw disable
sudo ufw allow 10086/tcp
sudo ufw allow 3090/tcp
sudo ufw allow 30303/udp
sudo ufw allow 53/udp
sudo ufw allow OpenSSH
sudo ufw --force enable



# Add Wireguard configuration
cat <<EOF | sudo tee -a /etc/wireguard/wg0.conf
[Interface]
Address = 10.10.10.1/24, fdf2:de64:f67d:4add::/64
MTU = 1420
SaveConfig = true
PostUp = ufw route allow in on wg0 out on eth0
PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on eth0
PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = 30303
PrivateKey = $private_key
EOF

# Enable Wireguard service
sudo systemctl enable wg-quick@wg0.service
sudo systemctl start wg-quick@wg0.service


# Install WGDashboard
git clone -b v3.1-dev https://github.com/donaldzou/WGDashboard.git wgdashboard
cd wgdashboard/src
sudo apt install python3-pip -y && pip install gunicorn && pip install -r requirements.txt --ignore-installed
sudo chmod u+x wgd.sh
sudo ./wgd.sh install

# Set permissions
sudo chmod -R 755 /etc/wireguard

# Start WGDashboard
sudo ./wgd.sh start


# Autostart WGDashboard on boot
DASHBOARD_DIR=$(pwd)
SERVICE_FILE="$DASHBOARD_DIR/wg-dashboard.service"

# Update service file with the correct directory
sed -i "s|<your dashboard directory full path here>|$DASHBOARD_DIR|g" "$SERVICE_FILE"

# Copy the service file to systemd folder
sudo cp "$SERVICE_FILE" /etc/systemd/system/wg-dashboard.service

# Set permissions
sudo chmod 664 /etc/systemd/system/wg-dashboard.service

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable and start WGDashboard service
sudo systemctl enable wg-dashboard.service
sudo systemctl start wg-dashboard.service

# Check if WGDashboard service is running
sudo systemctl status wg-dashboard.service
