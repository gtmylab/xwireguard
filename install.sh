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

# Check if curl is installed
if ! check_dpkg_package_installed curl; then
    echo "Installing curl..."
    apt update
    apt install -y curl
fi

# Check if wget is installed
if ! check_dpkg_package_installed wget; then
    echo "Installing wget..."
    apt update
    apt install -y wget
fi

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
echo -e "\e[1;31mWARNING ! Install only in Ubuntu 20.10, Ubuntu 22.04 & Debian 11 system ONLY\e[0m"
echo -e "\e[32mRECOMMENDED ==> Ubuntu 20.10 \e[0m"
echo ""
echo "The following software will be installed on your system:"
echo "   - Wire Guard Server"
echo "   - WireGuard-Tools"
echo "   - WGDashboard by donaldzou (v3.1-dev)"
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

  #  read -p "Enter WireGuard Private IP Address(s) [eg. 10.10.10.1/24,fdf2:de64:f67d:4add::/64]: " wg_address
 #   wg_address="${wg_address:-10.10.10.1/24,fdf2:de64:f67d:4add::/64}"  # Default address if user hits Enter
echo ""


# Check if IPv6 is available
#if ip -6 addr show $interface | grep -q inet6; then
if ip -6 addr show $interface | grep -q inet6 && ip -6 addr show $interface | grep -qv fe80; then
    ipv6_available=true
else
    ipv6_available=false
fi

# Function to check if IPv6 is available
ipv6_available() {
if ip -6 addr show $interface | grep -q inet6 && ip -6 addr show $interface | grep -qv fe80; then
        return 0
    else
        return 1
    fi
}

# Function to convert IPv4 address format
convert_ipv4_format() {
    local ipv4_address=$1
    local subnet_mask=$2

    # Extract the network portion of the IPv4 address
    local network=$(echo "$ipv4_address" | cut -d'/' -f1 | cut -d'.' -f1-3)

    # Append ".0" to the network portion and concatenate with the subnet mask
    local converted_ipv4="$network.0/24"

    echo "$converted_ipv4"
}

#!/bin/bash

# Function to check if an IPv6 address is global
is_global_ipv6() {
    local ipv6_address=$1
    # Check if the address is not link-local (starts with fe80) and contains '::'
    if [[ $ipv6_address != fe80:* && $ipv6_address == *::* ]]; then
        return 0
    else
        return 1
    fi
}

# Check if IPv6 is available on the default interface
ipv6_available=false
default_interface=$(ip route list default | awk '$1 == "default" {print $5}')
if ip -6 addr show $default_interface | grep -q inet6 && ip -6 addr show $default_interface | grep -v fe80 | grep -q "::"; then
    ipv6_available=true
fi

# Function to convert IPv4 address format
convert_ipv4_format() {
    local ipv4_address=$1
    local subnet_mask=$2

    # Extract the network portion of the IPv4 address
    local network=$(echo "$ipv4_address" | cut -d'/' -f1 | cut -d'.' -f1-3)

    # Append ".0" to the network portion and concatenate with the subnet mask
    local converted_ipv4="$network.0/24"

    echo "$converted_ipv4"
}

# Function to generate IPv4 addresses
generate_ipv4() {
    local range_type=$1
    case $range_type in
       1)
            ipv4_address_pvt="10.$((RANDOM%256)).$((RANDOM%256)).1/24"
            ;;
        2)
            ipv4_address_pvt="172.$((RANDOM%16+16)).$((RANDOM%256)).1/24"
            ;;
        3)
            ipv4_address_pvt="192.168.$((RANDOM%256)).1/24"
            ;;
        4)
            read -p "Enter custom Private IPv4 address: " ipv4_address_pvt
            ;;
        *)
            echo "Invalid option for IPv4 range."
            exit 1
            ;;
    esac
    echo "$ipv4_address_pvt"  # Return the generated IP address with subnet
}

# Function to generate IPv6 addresses
generate_ipv6() {
    local range_type=$1
    case $range_type in
        1)
            ipv6_address_pvt="FC00::$(printf '%02x%02x:%02x%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))/64"
            ;;
        2)
            ipv6_address_pvt="FD00::$(printf '%02x%02x:%02x%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))/64"
            ;;
        3)
            read -p "Enter custom Private IPv6 address: " ipv6_address_pvt
            ;;
        *)
            echo "Invalid option for IPv6 range."
            exit 1
            ;;
    esac
    echo "$ipv6_address_pvt"  # Return the generated IP address with subnet
}

# Function to validate user input within a range
validate_input() {
    local input=$1
    local min=$2
    local max=$3
    if (( input < min || input > max )); then
        echo "Invalid option. Please choose an option between $min and $max."
        return 1
    fi
    return 0
}

# Main script

while true; do
    echo "Choose IP range type for IPv4:"
    echo "1) Class A: 10.0.0.0 to 10.255.255.255"
    echo "2) Class B: 172.16.0.0 to 172.31.255.255"
    echo "3) Class C: 192.168.0.0 to 192.168.255.255"
    echo "4) Specify custom Private IPv4"
    read -p "Enter your choice (1-4): " ipv4_option

    case $ipv4_option in
        1|2|3|4)
            ipv4_address_pvt=$(generate_ipv4 $ipv4_option)
            break
            ;;
        *)
            echo "Invalid option for IPv4 range."
            ;;
    esac
done

ipv6_option=""
if $ipv6_available; then
    while true; do
        echo "Choose IP range type for IPv6:"
        echo "1) FC00::/7"
        echo "2) FD00::/7"
        echo "3) Specify custom Private IPv6"
        read -p "Enter your choice (1-3): " ipv6_option

        case $ipv6_option in
            1|2|3)
                ipv6_address_pvt=$(generate_ipv6 $ipv6_option)
                break
                ;;
            *)
                echo "Invalid option for IPv6 range."
                ;;
        esac
    done
fi
echo "IPv4 Address: $ipv4_address_pvt"
if [ -n "$ipv6_address_pvt" ]; then
    echo "IPv6 Address: $ipv6_address_pvt"
fi
echo ""


read -p "Specify a Peer Endpoint Allowed IPs OR [press enter to use - 0.0.0.0/0,::/0]: " allowed_ip
allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"  # Default IPs if user hits Enter


echo ""

# Function to retrieve IPv4 addresses (excluding loopback address)
get_ipv4_addresses() {
    ip -o -4 addr show $interface | awk '$4 !~ /^127\.0\.0\.1/ {print $4}' | cut -d'/' -f1
}

# Function to retrieve IPv6 addresses (excluding link-local and loopback addresses)
get_ipv6_addresses() {
    ip -o -6 addr show $interface | awk '$4 !~ /^fe80:/ && $4 !~ /^::1/ {print $4}' | cut -d'/' -f1
}

# Function to validate user input within a range
validate_input() {
    local input=$1
    local min=$2
    local max=$3
    if (( input < min || input > max )); then
        echo "Invalid option. Please choose an option between $min and $max."
        return 1
    fi
    return 0
}

# Main script

# Prompt for interface name
read -p "Enter the internet interface OR (press Enter for detected: $interface)" net_interface
#read -p "Enter the internet interface (detected is: $interface)" interface
interface="${net_interface:-$interface}"  # Default IPs if user hits Enter
echo ""

# Check if IPv6 is available
if ipv6_available; then
    ipv6_available=true
else
    ipv6_available=false
fi

# Prompt for IP version selection 
#PS3="Choose IP version: "
PS3="Select an option: "
options=("IPv4")
if [ "$ipv6_available" = true ]; then
    options+=("IPv6")
fi
select opt in "${options[@]}"; do
    case $REPLY in
        1)
            # Display IPv4 addresses as options
            echo "Available IPv4 addresses:"
            ipv4_addresses=$(get_ipv4_addresses)
            select ipv4_address in $ipv4_addresses; do
                if validate_input $REPLY 1 $(wc -w <<< "$ipv4_addresses"); then
                    break
                fi
            done
            echo "Selected IPv4 Address: $ipv4_address"

            # If IPv6 is available, present options to choose an IPv6 address
            if [ "$ipv6_available" = true ]; then
                echo "Choose an IPv6 address:"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                echo "Selected IPv6 Address: $ipv6_address"
            fi
            break
            ;;
        2)
            if [ "$ipv6_available" = true ]; then
                # Display IPv6 addresses as options
                echo "Available IPv6 addresses (excluding link-local addresses):"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                echo "Selected IPv6 Address: $ipv6_address"
            else
                echo "IPv6 is not available."
            fi
            break
            ;;
        *)
            echo "Invalid option. Please select again."
            ;;
    esac
done

echo ""

    # Continue with the rest of your installation script...
    echo "Starting with installation..."
    echo ""
    # Your installation commands here...
# Update hostname
echo "$hostname" | tee /etc/hostname > /dev/null
hostnamectl set-hostname "$hostname"

apt update


# Check if Python 3 is installed
if ! check_dpkg_package_installed python3; then
    echo "Python 3 is not installed. Installing Python 3..."

    # Install Python 3 system-wide
    apt install -y python3

    # Make Python 3 the default version
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1
fi

# Function to check the version of Python installed
get_python_version() {
    python3 --version | awk '{print $2}'
}

# Check the Python version
python_version=$(get_python_version)

# Compare the Python version
if [[ "$(echo "$python_version" | cut -d. -f1)" -lt 3 || "$(echo "$python_version" | cut -d. -f2)" -lt 7 ]]; then
    echo "Python version is below 3.7. Upgrading Python..."
    # Perform the system upgrade of Python
    apt update
    apt install -y python3
else
    echo "Python version is 3.7 or above."
fi

# Check for WireGuard dependencies and install them if not present
if ! check_dpkg_package_installed wireguard-tools; then
    echo "Installing WireGuard dependencies..."
    apt install -y wireguard-tools
fi


# Install git if not installed
if ! check_package_installed git; then
    echo "Installing git..."
    apt-get install -y git
fi

# Install ufw if not installed
if ! check_package_installed ufw; then
    echo "Installing ufw..."
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

if [[ -n $ipv6_address ]] && grep -q "#ip6tables" "$iptables_script"; then
WG_Address="$ipv4_address_pvt"
else
WG_Address="$ipv4_address_pvt,$ipv6_address_pvt"
fi

# Add Wireguard configuration
cat <<EOF | tee -a /etc/wireguard/wg0.conf
[Interface]
Address = $WG_Address
MTU = 1420
SaveConfig = true
ListenPort = $wg_port
PrivateKey = $private_key
EOF

#sed -i "s|^ListenPort =.*|ListenPort = $wg_port|g" /etc/wireguard/wg0.conf

mkdir /etc/wireguard/network

# Add Wireguard Network configuration
ipv4_address_pvt0=$(convert_ipv4_format "$ipv4_address_pvt")
# Define the path to the iptables.sh script
iptables_script="/etc/wireguard/network/iptables.sh"
cat <<EOF | tee -a "$iptables_script"
#!/bin/bash

# Wait for the network interface to be up
while ! ip link show dev $interface up; do
    sleep 1
done

# Set iptables rules for WireGuard
iptables -t nat -I POSTROUTING --source $ipv4_address_pvt0 -o $interface -j SNAT --to $ipv4_address
iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE

# Set ip6tables rules for WireGuard (IPv6)
#ip6tables -t nat -I POSTROUTING --source ::/0 -o $interface -j SNAT --to $ipv6_address

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
ExecStart=$iptables_script

[Install]
WantedBy=multi-user.target
EOF

chmod +x $iptables_script


# Uncomment the ip6tables command if IPv6 is available
#if $ipv6_address && grep -q "#ip6tables" "$iptables_script"; then
if [[ -n $ipv6_address ]] && grep -q "#ip6tables" "$iptables_script"; then
    sed -i 's/#ip6tables/ip6tables/' "$iptables_script"
    sed -i "s|::/0|$ipv6_address_pvt|" "$iptables_script"
    echo "Uncommented ip6tables command in $iptables_script"
fi

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
#apt install python3-pip -y >/dev/null 2>&1 && pip install gunicorn >/dev/null 2>&1 && pip install -r requirements.txt --ignore-installed >/dev/null 2>&1

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



# Enable and start WGDashboard service
systemctl enable wg-dashboard.service
systemctl restart wg-dashboard.service


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
    echo "Reboot system after that Go ahead and create your first peers and don't forget to change your password."
    echo -e "\e[0m" # Reset font color

# Reload systemd daemon
systemctl daemon-reload

    #reboot
systemctl restart wireguard-iptables.service
else
    echo "Error: Installation failed. Please check the services and try again."
fi
else
    echo "Installation aborted."
    exit 0
fi
