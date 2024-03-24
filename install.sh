#!/bin/bash

# Prompt the user to enter details
#read -p "Enter Hostname: " hostname
# Function to validate hostname
validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9\-\.]+$ ]]; then
        return 0  # Valid hostname
    else
        return 1  # Invalid hostname
    fi
}

# Prompt the user to enter hostname until a valid one is provided
while true; do
    read -p "Enter or set a Hostname: " hostname
    if validate_hostname "$hostname"; then
        break
    else
        echo "Invalid hostname. Please enter a valid hostname."
    fi
done
read -p "Specify new DNS (eg. 147.78.0.8,172.104.39.79): " dns
read -p "Enter Wireguard Port (eg. 51820): " wg_port
read -p "Enter Dashboard Port (eg. 8080): " dashboard_port
read -p "Enter Peer Endpoint Allowed IPs (eg. 0.0.0.0/0,::/0): " allowed_ip
read -p "Choose WireGuard Private IP Address (eg. 10.10.10.1/24, fdf2:de64:f67d:4add::/64): " wg_address



# Update hostname
echo "$hostname" | sudo tee /etc/hostname > /dev/null
sudo hostnamectl set-hostname "$hostname"

interface=$(ip route list default | awk '$1 == "default" {print $5}')

# Update package list
sudo apt update

# Install Wireguard
sudo apt install wireguard -y

# Generate Wireguard keys
private_key=$(wg genkey)
echo "$private_key" | sudo tee /etc/wireguard/private.key
public_key=$(echo "$private_key" | wg pubkey)
#echo "PrivateKey = $private_key" | sudo tee -a /etc/wireguard/wg0.conf
#echo "PublicKey = $public_key" | sudo tee -a /etc/wireguard/wg0.conf

# Enable IPv4 and IPv6 forwarding
sudo sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sudo sed -i '/^#net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf

# Apply changes
sudo sysctl -p

# Configure firewall (UFW)
sudo ufw disable
sudo ufw allow 10086/tcp
sudo ufw allow $dashboard_port/tcp
sudo ufw allow $wg_port/udp
sudo ufw allow 53/udp
sudo ufw allow OpenSSH
sudo ufw --force enable



# Add Wireguard configuration
cat <<EOF | sudo tee -a /etc/wireguard/wg0.conf
[Interface]
Address = $wg_address
MTU = 1420
SaveConfig = true
PostUp = ufw route allow in on wg0 out on $interface
PostUp = iptables -t nat -I POSTROUTING -o $interface -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o $interface -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on $interface
PreDown = iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o $interface -j MASQUERADE
ListenPort = $wg_port
PrivateKey = $private_key
EOF

#sed -i "s|^ListenPort =.*|ListenPort = $wg_port|g" /etc/wireguard/wg0.conf

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

# Get the absolute path of python3 interpreter
PYTHON_PATH=$(which python3)

# Update service file with the correct directory and python path
sed -i "s|{{APP_ROOT}}|$DASHBOARD_DIR|g" "$SERVICE_FILE"
sed -i "/Environment=\"VIRTUAL_ENV={{VIRTUAL_ENV}}\"/d" "$SERVICE_FILE"
sed -i "s|{{VIRTUAL_ENV}}/bin/python3|$PYTHON_PATH|g" "$SERVICE_FILE"

# Copy the service file to systemd folder
cp "$SERVICE_FILE" /etc/systemd/system/wg-dashboard.service

# Set permissions
chmod 664 /etc/systemd/system/wg-dashboard.service

# Reload systemd daemon
systemctl daemon-reload

# Enable and start WGDashboard service
systemctl enable wg-dashboard.service
systemctl restart wg-dashboard.service

# Seed to /root/wgdashboard/src/wg-dashboard.ini
sudo sed -i "s|^app_port =.*|app_port = $dashboard_port|g" /root/wgdashboard/src/wg-dashboard.ini
sudo sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" /root/wgdashboard/src/wg-dashboard.ini
sudo sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" /root/wgdashboard/src/wg-dashboard.ini

systemctl restart wg-dashboard.service


# Check if Wiregaurd service is running
#systemctl status wg-quick@wg0.service

# Check if WGDashboard service is running
#systemctl status wg-dashboard.service

# Display success message
#echo "Installation done successfully!"

# Check if the services restarted successfully
wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)

echo "Wireguard Status: $wg_status"
echo "WGDashboard Status: $dashboard_status"

if [ "$wg_status" = "active" ] && [ "$dashboard_status" = "active" ]; then
    # Get the server IP address
    server_ip=$(curl -s ifconfig.me)

    # Display success message in green font
    echo -e "\e[32mGreat! Installation was successful!"
    echo "You can access Wireguard Dashboard now:"
    echo "URL: http://$server_ip:$dashboard_port"
    echo "Username: admin"
    echo "Password: admin"
    echo ""
    echo "Go ahead and create your first peers and don't forget to change your password."
    echo -e "\e[0m" # Reset font color
else
    echo "Error: Installation failed. Please check the services and try again."
fi
