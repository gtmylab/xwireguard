#!/bin/bash

# Function to check if a package is installed
check_package_installed() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    else
        return 0
    fi
}
check_dpkg_package_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

# Clear screen
clear
interface=$(ip route list default | awk '$1 == "default" {print $5}')

# Display ASCII art and introduction
echo "  _|_|_|_|    _|_|_|      _|_|_|    _|_|_|_|    _|_|_|  _|    _|  _|_|_|_|"
echo "    _|      _|    _|      _|    _|  _|          _|            _|      _|"
echo "    _|    _|        _|    _|    _|    _|_|      _|_|_|    _|        _|"
echo "    _|  _|            _|  _|    _|        _|    _|            _|    _|"
echo "  _|_|_|              _|    _|_|_|  _|_|_|_|    _|_|_|  _|        _|"
echo ""
echo "                                  xWireGuard Management & Server"
echo ""
echo -e "\e[1;31mWARNING ! Install only in Ubuntu 20.10 & Debian 10 system ONLY\e[0m"
echo -e "\e[32mRECOMMENDED ==> Ubuntu 20.10 \e[0m"
echo ""
echo "The following software will be installed on your system:"
echo "   - Wire Guard Server"
echo "   - WireGuard-Tools"
echo "   - WGDashboard by donaldzou"
echo "   - Gunicorn WSGI Server"
echo "   - Python3-pip"
echo "   - Git"
echo "   - UFW - firewall"
echo ""


# Prompt the user to continue
read -p "Would you like to continue [y/n]: " choice

if [[ "$choice" =~ ^[Yy]$ ]]; then
# Prompt the user to enter hostname until a valid one is provided
# Function to validate hostname
validate_hostname() {
    local hostname="$1"
        if [[ "$hostname" =~ ^[a-zA-Z0-9\.\-_]+$ ]]; then
        return 0  # Valid hostname
    else
        return 1  # Invalid hostname
    fi
}

    # Prompt the user to enter hostname until a valid one is provided
    while true; do
        read -p "Please enter FQDN hostname [eg. localhost]: " hostname
        if [[ -z "$hostname" ]]; then
            hostname="localhost"  # Default hostname if user hits Enter
            break
        elif validate_hostname "$hostname"; then
            break
        else
            echo "Invalid hostname. Please enter a valid hostname."
        fi
    done

    # Prompt the user to enter a username
while true; do
    read -p "Specify a Username Login for WGDashboard: " username
    if [[ -n "$username" ]]; then
        break
    else
        echo "Username cannot be empty. Please specify a username."
    fi
done

while true; do
    # Prompt the user to enter a password (without showing the input)
    read -s -p "Specify a Password: " password
    echo ""

    # Prompt the user to confirm the password
    read -s -p "Confirm Password: " confirm_password
    echo ""

    # Check if the passwords match
    if [ "$password" != "$confirm_password" ]; then
        echo -e "\e[1;31mError: Passwords do not match. Please try again.\e[0m"
    elif [ -z "$password" ]; then
        echo "Password cannot be empty. Please specify a password."
    else
        # Hash the password using SHA-256
        hashed_password=$(echo -n "$password" | sha256sum | awk '{print $1}')
        break  # Exit the loop if passwords match
    fi
done


   # Prompt for other installation details with default values
    read -p "Please Specify new DNS [eg. 147.78.0.8,172.104.39.79]: " dns
    dns="${dns:-147.78.0.8,172.104.39.79}"  # Default DNS if user hits Enter

    read -p "Please enter Wireguard Port [eg. 51820]: " wg_port
    wg_port="${wg_port:-51820}"  # Default port if user hits Enter

    read -p "Please enter Admin Dashboard Port [eg. 8080]: " dashboard_port
    dashboard_port="${dashboard_port:-8080}"  # Default port if user hits Enter

    read -p "Enter enter Peer Endpoint Allowed IPs [eg. 0.0.0.0/0,::/0]: " allowed_ip
    allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"  # Default IPs if user hits Enter

    read -p "Enter WireGuard Private IP Address(s) [eg. 10.10.10.1/24,fdf2:de64:f67d:4add::/64]: " wg_address
    wg_address="${wg_address:-10.10.10.1/24,fdf2:de64:f67d:4add::/64}"  # Default address if user hits Enter

# Check if IPv6 is available
if ip -6 addr show $interface | grep -q inet6; then
    ipv6_available=true
else
    ipv6_available=false
fi

# Retrieve IPv4 addresses and join them with commas
ipv4_address=$(ip -o -4 addr show $interface | awk '{print $4}' | cut -d'/' -f1 | tr '\n' ',')

# Remove the trailing comma if there are multiple IPv4 addresses
ipv4_address=${ipv4_address%,}


# Display IPv6 addresses if available
if [ "$ipv6_available" = true ]; then
    # Retrieve IPv6 addresses and join them with commas
    ipv6_address=$(ip -o -6 addr show $interface | awk '{print $4}' | cut -d'/' -f1 | tr '\n' ',')

    # Remove the trailing comma if there are multiple IPv6 addresses
    ipv6_address=${ipv6_address%,}

    read -p "Enter the Ipv6 to use [$ipv6_address]: " chosen_ipv6
    ipv6_address="${chosen_ipv6:-$ipv6_address}"  # Default address if user hits Enter
fi

read -p "Enter the Public IPv4 to use [$ipv4_address]: " chosen_ipv4
ipv4_address="${chosen_ipv4:-$ipv4_address}"  # Default address if user hits Enter

echo "Selected IPv4 Address: $ipv4_address"
if [ "$ipv6_available" = true ]; then
    echo "Selected IPv6 Address: $ipv6_address"
fi


    # Continue with the rest of your installation script...
    echo "Satrting with installation..."
    # Your installation commands here...
# Update hostname
echo "$hostname" | tee /etc/hostname > /dev/null
hostnamectl set-hostname "$hostname"


# Check for WireGuard dependencies and install them if not present
if ! check_dpkg_package_installed wireguard-tools; then
    echo "Installing WireGuard dependencies..."
    apt install -y wireguard-tools
fi

# Install git if not installed
if ! check_package_installed git; then
    echo "Installing git..."
    apt-get update
    apt-get install -y git
fi

# Install ufw if not installed
if ! check_package_installed ufw; then
    echo "Installing ufw..."
    apt-get update
    apt-get install -y ufw
fi

# Now that dependencies are ensured to be installed, install WireGuard
echo "Installing WireGuard..."
apt install -y wireguard

# Generate Wireguard keys
private_key=$(wg genkey)
echo "$private_key" | tee /etc/wireguard/private.key
public_key=$(echo "$private_key" | wg pubkey)


# Enable IPv4 and IPv6 forwarding
sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sed -i '/^#net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf

# Apply changes
sysctl -p

# Configure firewall (UFW)
ufw disable
ufw allow 10086/tcp
ufw allow $dashboard_port/tcp
ufw allow $wg_port/udp
ufw allow 53/udp
ufw allow OpenSSH
ufw --force enable



# Add Wireguard configuration
cat <<EOF | tee -a /etc/wireguard/wg0.conf
[Interface]
Address = $wg_address
MTU = 1420
SaveConfig = true
ListenPort = $wg_port
PrivateKey = $private_key
EOF

#sed -i "s|^ListenPort =.*|ListenPort = $wg_port|g" /etc/wireguard/wg0.conf

mkdir /etc/wireguard/network

# Add Wireguard Network configuration

cat <<EOF | tee -a /etc/wireguard/network/iptables.sh
#!/bin/bash

# Wait for the network interface to be up
while ! ip link show dev $interface up; do
    sleep 1
done

# Set iptables rules for WireGuard
iptables -t nat -I POSTROUTING --source 0.0.0.0/0 -o $interface -j SNAT --to $ipv4_address
iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE

# Set ip6tables rules for WireGuard (IPv6)
ip6tables -t nat -I POSTROUTING --source ::/0 -o $interface -j SNAT --to $ipv6_address

# Add custom route for WireGuard interface
ip route add default dev wg0

# Add custom route for incoming traffic from WireGuard
ufw route allow in on wg0 out on $interface

EOF


cat <<EOF | tee -a /etc/systemd/system/wireguard-iptables.service
[Unit]
Description=Setup iptables rules for WireGuard
After=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/wireguard/network/iptables.sh

[Install]
WantedBy=multi-user.target
EOF

chmod +x /etc/wireguard/network/iptables.sh

systemctl enable wireguard-iptables.service

# Enable Wireguard service
systemctl enable wg-quick@wg0.service
systemctl start wg-quick@wg0.service


# Change directory to /etc
cd /etc || exit

# Create a directory xwireguard if it doesn't exist
if [ ! -d "xwireguard" ]; then
    mkdir xwireguard
fi

# Change directory to /etc/xwireguard
cd xwireguard || exit

# Install WGDashboard
git clone -b v3.1-dev https://github.com/donaldzou/WGDashboard.git wgdashboard
cd wgdashboard/src
apt install python3-pip -y && pip install gunicorn && pip install -r requirements.txt --ignore-installed
chmod u+x wgd.sh
./wgd.sh install

# Set permissions
chmod -R 755 /etc/wireguard

# Start WGDashboard
./wgd.sh start


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
systemctl restart wireguard-iptables.service


# Seed to wg-dashboard.ini
sed -i "s|^app_port =.*|app_port = $dashboard_port|g" $DASHBOARD_DIR/wg-dashboard.ini
sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" $DASHBOARD_DIR/wg-dashboard.ini
sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" $DASHBOARD_DIR/wg-dashboard.ini
sed -i "s|^password =.*|password = $hashed_password|g" $DASHBOARD_DIR/wg-dashboard.ini
sed -i "s|^username =.*|username = $username|g" $DASHBOARD_DIR/wg-dashboard.ini
sed -i "s|^dashboard_theme =.*|dashboard_theme = dark|g" $DASHBOARD_DIR/wg-dashboard.ini


systemctl restart wg-dashboard.service


# Check if the services restarted successfully
wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)

echo "Wireguard Status: $wg_status"
echo "WGDashboard Status: $dashboard_status"

if [ "$wg_status" = "active" ] && [ "$dashboard_status" = "active" ]; then
    # Get the server IPv4 address
    server_ip=$(curl -s4 ifconfig.me)

    # Display success message in green font
    echo -e "\e[32mGreat! Installation was successful!"
    echo "You can access Wireguard Dashboard now:"
    echo 'URL: http://'"$server_ip:$dashboard_port"
    echo "Username: $username"
    echo "Password: ***(hidden)***"
    echo ""
    echo "Go ahead and create your first peers and don't forget to change your password."
    echo -e "\e[0m" # Reset font color

    #reboot
else
    echo "Error: Installation failed. Please check the services and try again."
fi
else
    echo "Installation aborted."
    exit 0
fi
