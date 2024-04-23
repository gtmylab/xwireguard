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
printf "  _|_|_|_|    _|_|_|      _|_|_|    _|_|_|_|    _|_|_|  _|    _|  _|_|_|\n"
printf "    _|      _|    _|      _|    _|  _|          _|            _|      _|\n"
printf "    _|    _|        _|    _|    _|    _|_|      _|_|_|    _|        _|\n"
printf "    _|  _|            _|  _|    _|        _|    _|            _|    _|\n"
printf "  _|_|_|              _|    _|_|_|  _|_|_|_|    _|_|_|  _|        _|\n\n"
printf "                                  xWireGuard Management & Server\n\n"
printf "\e[1;31mWARNING ! Install only in Ubuntu 20.10, Ubuntu 20.04, Ubuntu 22.04 & Debian 11 system ONLY\e[0m\n"
printf "\e[32mRECOMMENDED ==> Ubuntu 20.10 \e[0m\n\n"
printf "The following software will be installed on your system:\n"
printf "   - Wire Guard Server\n"
printf "   - WireGuard-Tools\n"
printf "   - WGDashboard by donaldzou (v3.1-dev)\n"
printf "   - Gunicorn WSGI Server\n"
printf "   - Python3-pip\n"
printf "   - Git\n"
printf "   - UFW - firewall\n"
printf "   - inotifywait\n\n"
printf "\n\n"

  # Check if the system is CentOS, Debian, or Ubuntu
    if [ -f "/etc/centos-release" ]; then
        printf "Detected CentOS...\n"
        pkg_manager="yum"
        ufw_package="firewalld"
    elif [ -f "/etc/debian_version" ]; then
        printf "Detected Debian or Ubuntu...\n"
        pkg_manager="apt"
        ufw_package="ufw"
    else
        printf "Unsupported distribution.\n"
        exit 1
    fi
# Prompt the user to continue
read -p "Would you like to continue now ? [y/n]: " choice

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
            printf "Invalid hostname. Please enter a valid hostname.\n"
        fi
    done

    # Prompt the user to enter a username
while true; do
    read -p "Specify a Username Login for WGDashboard: " username
    if [[ -n "$username" ]]; then
        break
    else
        printf "Username cannot be empty. Please specify a username.\n"
    fi
done

while true; do
    # Prompt the user to enter a password (without showing the input)
    read -s -p "Specify a Password: " password
    printf "\n"

    # Prompt the user to confirm the password
    read -s -p "Confirm Password: " confirm_password
    printf "\n"

    # Check if the passwords match
    if [ "$password" != "$confirm_password" ]; then
            printf "\e[1;31mError: Passwords do not match. Please try again.\e[0m\n"
    elif [ -z "$password" ]; then
            printf "Password cannot be empty. Please specify a password.\n"
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

 printf "\n"
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

    printf "$converted_ipv4\n"
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

    printf "$converted_ipv4\n"
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
            printf "Invalid option for IPv4 range.\n"
            exit 1
            ;;
    esac
    printf "$ipv4_address_pvt\n"  # Return the generated IP address with subnet
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
            printf "Invalid option for IPv6 range.\n"
            exit 1
            ;;
    esac
    printf "$ipv6_address_pvt\n"  # Return the generated IP address with subnet
}

# Function to validate user input within a range
validate_input() {
    local input=$1
    local min=$2
    local max=$3
    if (( input < min || input > max )); then
        printf "Invalid option. Please choose an option between $min and $max.\n"
        return 1
    fi
    return 0
}

# Main script

while true; do
    printf "Choose IP range type for IPv4:\n"
    printf "1) Class A: 10.0.0.0 to 10.255.255.255\n"
    printf "2) Class B: 172.16.0.0 to 172.31.255.255\n"
    printf "3) Class C: 192.168.0.0 to 192.168.255.255\n"
    printf "4) Specify custom Private IPv4\n"
    read -p "Enter your choice (1-4): " ipv4_option

    case $ipv4_option in
        1|2|3|4)
            ipv4_address_pvt=$(generate_ipv4 $ipv4_option)
            break
            ;;
        *)
            printf "Invalid option for IPv4 range.\n"
            ;;
    esac
done

ipv6_option=""
if $ipv6_available; then
    while true; do
        printf "Choose IP range type for IPv6:\n"
        printf "1) FC00::/7\n"
        printf "2) FD00::/7\n"
        printf "3) Specify custom Private IPv6\n"
        read -p "Enter your choice (1-3): " ipv6_option

        case $ipv6_option in
            1|2|3)
                ipv6_address_pvt=$(generate_ipv6 $ipv6_option)
                break
                ;;
            *)
                printf "Invalid option for IPv6 range.\n"
                ;;
        esac
    done
fi
printf "IPv4 Address: $ipv4_address_pvt\n"
if [ -n "$ipv6_address_pvt" ]; then
    printf "IPv6 Address: $ipv6_address_pvt\n"
fi
printf "\n"
read -p "Specify a Peer Endpoint Allowed IPs OR [press enter to use - 0.0.0.0/0,::/0]: " allowed_ip
allowed_ip="${allowed_ip:-0.0.0.0/0,::/0}"  # Default IPs if user hits Enter
printf "\n"
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
        printf "Invalid option. Please choose an option between $min and $max.\n"
        return 1
    fi
    return 0
}

# Main script

# Prompt for interface name
read -p "Enter the internet interface OR (press Enter for detected: $interface)" net_interface
#read -p "Enter the internet interface (detected is: $interface)" interface
interface="${net_interface:-$interface}"  # Default IPs if user hits Enter
printf "\n"

# Check if IPv6 is available
if ipv6_available; then
    ipv6_available=true
else
    ipv6_available=false
fi

# Prompt for IP version selection 
#PS3="Choose IP version: "
PS3="Select an option: "
options=("Public IPv4")
if [ "$ipv6_available" = true ]; then
    options+=("Public IPv6")
fi
select opt in "${options[@]}"; do
    case $REPLY in
        1)
            # Display IPv4 addresses as options
            printf "Available Public IPv4 addresses:\n"
            ipv4_addresses=$(get_ipv4_addresses)
            select ipv4_address in $ipv4_addresses; do
                if validate_input $REPLY 1 $(wc -w <<< "$ipv4_addresses"); then
                    break
                fi
            done
            printf "Selected Public IPv4 Address: $ipv4_address\n"

            # If IPv6 is available, present options to choose an IPv6 address
            if [ "$ipv6_available" = true ]; then
                printf "Choose a Public IPv6 address:\n"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                printf "Selected Public IPv6 Address: $ipv6_address\n"
            fi
            break
            ;;
        2)
            if [ "$ipv6_available" = true ]; then
                # Display IPv6 addresses as options
                printf "Available Public IPv6 addresses (excluding link-local addresses):\n"
                ipv6_addresses=$(get_ipv6_addresses)
                select ipv6_address in $ipv6_addresses; do
                    if validate_input $REPLY 1 $(wc -w <<< "$ipv6_addresses"); then
                        break
                    fi
                done
                printf "Selected Public IPv6 Address: $ipv6_address\n"
            else
                printf "Public IPv6 is not available.\n"
            fi
            break
            ;;
        *)
            printf "Invalid option. Please select again.\n"
            ;;
    esac
done

printf "\n"
clear
    # Continue with the rest of your installation script...
    printf "Starting with installation...\n"
    printf "\n"
    # Your installation commands here...
# Update hostname
echo "$hostname" | tee /etc/hostname > /dev/null
hostnamectl set-hostname "$hostname"

printf "Updating Repo & System...\n"
printf "Please wait to complete process...\n"
 $pkg_manager update -y  >/dev/null 2>&1


# Check if Python 3 is installed
if ! check_dpkg_package_installed python3; then
    printf "Python 3 is not installed. Installing Python 3...\n"

    # Install Python 3 system-wide
     $pkg_manager install -y python3 >/dev/null 2>&1

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
    printf "Python version is below 3.7. Upgrading Python...\n"
    # Perform the system upgrade of Python
     $pkg_manager update -y  >/dev/null 2>&1
     $pkg_manager install -y python3 >/dev/null 2>&1
else
    printf "Python version is 3.7 or above.\n"
fi

# Check for WireGuard dependencies and install them if not present
if ! check_dpkg_package_installed wireguard-tools; then
    printf "Installing WireGuard dependencies...\n"
     $pkg_manager install -y wireguard-tools >/dev/null 2>&1
fi


# Install git if not installed
if ! check_package_installed git; then
    printf "Installing git...\n"
     $pkg_manager install -y git >/dev/null 2>&1
fi

# Install ufw if not installed
if ! check_package_installed $ufw_package; then
    printf "Installing $ufw_package...\n"
     $pkg_manager install -y $ufw_package >/dev/null 2>&1
fi

# Install inotifywait if not installed
if ! check_package_installed inotifywait ; then
    printf "Installing inotifywait...\n"
     $pkg_manager install -y inotify-tools >/dev/null 2>&1
fi

# Install cron  if not installed
if ! check_package_installed cron ; then
    printf "Cron is not installed. Installing...\n"
     $pkg_manager install -y cron >/dev/null 2>&1
fi

# Now that dependencies are ensured to be installed, install WireGuard
printf "Installing WireGuard...\n"
 $pkg_manager install -y wireguard >/dev/null 2>&1

# Generate Wireguard keys
private_key=$(wg genkey 2>/dev/null)
echo "$private_key" | tee /etc/wireguard/private.key >/dev/null
public_key=$(echo "$private_key" | wg pubkey 2>/dev/null)


# Enable IPv4 and IPv6 forwarding
sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf >/dev/null
sed -i '/^#net.ipv6.conf.all.forwarding=1/s/^#//' /etc/sysctl.conf >/dev/null

# Apply changes
sysctl -p >/dev/null
ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F ':' '{print $NF}' | sort -u)

# Configure firewall (UFW or firewalld)
if [ "$pkg_manager" == "apt" ]; then
    # Configure UFW rules
printf "Configuring firewall (UFW) .....\n"
# Configure firewall (UFW)
printf "Stopping firewall (UFW) .....\n"
ufw disable
printf "Creating firewall rules .....\n"
ufw allow 10086/tcp
printf "Creating firewall rules .....\n"
ufw allow $ssh_port/tcp
printf "Creating firewall rules .....\n"
ufw allow $dashboard_port/tcp
printf "Creating firewall rules .....\n"
ufw allow $wg_port/udp
printf "Creating firewall rules .....\n"
ufw allow 53/udp
printf "Creating firewall rules .....\n"
ufw allow OpenSSH
printf "Creating firewall rules .....\n"
ufw --force enable
elif [ "$pkg_manager" == "yum" ]; then
    # Configure firewalld rules
    printf "Configuring firewall (IP rules) .....\n"
    firewall-cmd --zone=public --add-port=10086/tcp --permanent
    firewall-cmd --zone=public --add-port=$dashboard_port/tcp --permanent
    firewall-cmd --zone=public --add-port=$ssh_port/tcp --permanent
    firewall-cmd --zone=public --add-port=$wg_port/udp --permanent
    firewall-cmd --zone=public --add-port=53/udp --permanent
    firewall-cmd --zone=public --add-service=ssh --permanent
    firewall-cmd --reload
fi



#sed -i "s|^ListenPort =.*|ListenPort = $wg_port|g" /etc/wireguard/wg0.conf
if [[ -n $ipv6_address ]]; then
    WG_Address="$ipv6_address_pvt,$ipv4_address_pvt"
else
    WG_Address="$ipv4_address_pvt"
fi

printf "Setting up Wireguard configuration .....\n"
# Add Wireguard configuration
cat <<EOF | tee -a /etc/wireguard/wg0.conf >/dev/null
[Interface]
Address = $WG_Address
MTU = 1420
SaveConfig = true
ListenPort = $wg_port
PrivateKey = $private_key
EOF

# Define the path to the iptables.sh script
mkdir /etc/wireguard/network

# Add Wireguard Network configuration
printf "Setting up Wireguard Network .....\n"
ipv4_address_pvt0=$(convert_ipv4_format "$ipv4_address_pvt")

# Define the function for seeding iptables rules on CentOS
seed_centos_iptables() {
cat <<EOF | tee -a "/etc/wireguard/network/iptables.sh"
#!/bin/bash

# Wait for the network interface to be up
while ! ip link show dev $interface up; do
    sleep 1
done

# Set iptables rules for WireGuard (IPv4)
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="$ipv4_address_pvt0" masquerade'
firewall-cmd --add-rich-rule='rule family="ipv4" source address="$ipv4_address_pvt0" port protocol="udp" port="$wg_port" accept'

EOF

# Check if IPv6 is available
if [[ -n $ipv6_address ]]; then
    cat <<EOF | tee -a "/etc/wireguard/network/iptables.sh"
#ip6tables
firewall-cmd --zone=public --add-rich-rule='rule family="ipv6" source address="$ipv6_address_pvt0" masquerade'
firewall-cmd --add-rich-rule='rule family="ipv6" source address="$ipv6_address_pvt0" port protocol="udp" port="$wg_port" accept'

EOF
fi

# Add custom route for WireGuard interface
cat <<EOF | tee -a "/etc/wireguard/network/iptables.sh"
# Add custom route for WireGuard interface
ip route add default dev wg0

# Add custom route for incoming traffic from WireGuard
ufw route allow in on wg0 out on $interface

EOF
}

# Define the function for seeding firewall-cmd rules on Ubuntu
seed_ubuntu_firewallcmd() {
cat <<EOF | tee -a "/etc/wireguard/network/iptables.sh"
# Wait for the network interface to be up
while ! ip link show dev $interface up; do
    sleep 1
done

# Set iptables rules for WireGuard
iptables -t nat -I POSTROUTING --source $ipv4_address_pvt0 -o $interface -j SNAT --to $ipv4_address
iptables -t nat -D POSTROUTING -o $interface -j MASQUERADE

# Set ip6tables rules for WireGuard (IPv6)
#ip6tables -t nat -I POSTROUTING --source ::/0 -o $interface -j SNAT --to $ipv6_address

EOF
# Add custom route for WireGuard interface
cat <<EOF | tee -a "/etc/wireguard/network/iptables.sh"
# Add custom route for WireGuard interface
ip route add default dev wg0

# Add custom route for incoming traffic from WireGuard
ufw route allow in on wg0 out on $interface

EOF
}

# Determine the distribution to choose between iptables or firewall-cmd
if [ -f /etc/redhat-release ]; then
    # CentOS or RHEL
    seed_centos_iptables
elif [ -f /etc/lsb-release ]; then
    # Ubuntu or Debian
    seed_ubuntu_firewallcmd
else
    echo "Unsupported distribution."
    exit 1
fi

iptables_script="/etc/wireguard/network/iptables.sh"
# Uncomment the ip6tables command if IPv6 is available
#if $ipv6_address && grep -q "#ip6tables" "$iptables_script"; then
if [[ -n $ipv6_address ]] && grep -q "#ip6tables" "$iptables_script"; then
    sed -i 's/#ip6tables/ip6tables/' "$iptables_script" >/dev/null
    sed -i "s|::/0|$ipv6_address_pvt|" "$iptables_script" >/dev/null
fi

cat <<EOF | tee -a /etc/systemd/system/wireguard-iptables.service >/dev/null
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



systemctl enable wireguard-iptables.service --quiet

# Enable Wireguard service
printf "Enabling Wireguard Service .....\n"
systemctl enable wg-quick@wg0.service --quiet
systemctl start wg-quick@wg0.service


# Change directory to /etc
cd /etc || exit

# Create a directory xwireguard if it doesn't exist
if [ ! -d "xwireguard" ]; then
    mkdir xwireguard
    mkdir /etc/xwireguard/monitor
fi

# Change directory to /etc/xwireguard
cd xwireguard || exit

# Install WGDashboard
printf "Installing WGDashboard .....\n"
git clone -q -b v3.1-dev https://github.com/donaldzou/WGDashboard.git wgdashboard
cd wgdashboard/src
# $pkg_manager install python3-pip -y && pip install gunicorn && pip install -r requirements.txt --ignore-installed
 $pkg_manager install python3-pip -y >/dev/null 2>&1 && pip install gunicorn >/dev/null 2>&1 && pip install -r requirements.txt --ignore-installed >/dev/null 2>&1

chmod u+x wgd.sh
./wgd.sh install >/dev/null 2>&1

# Set permissions
chmod -R 755 /etc/wireguard

# Start WGDashboard
./wgd.sh start >/dev/null 2>&1

# Autostart WGDashboard on boot
DASHBOARD_DIR=$(pwd)
SERVICE_FILE="$DASHBOARD_DIR/wg-dashboard.service"

# Get the absolute path of python3 interpreter
PYTHON_PATH=$(which python3)

# Update service file with the correct directory and python path
sed -i "s|{{APP_ROOT}}|$DASHBOARD_DIR|g" "$SERVICE_FILE" >/dev/null
sed -i "/Environment=\"VIRTUAL_ENV={{VIRTUAL_ENV}}\"/d" "$SERVICE_FILE" >/dev/null
sed -i "s|{{VIRTUAL_ENV}}/bin/python3|$PYTHON_PATH|g" "$SERVICE_FILE" >/dev/null

# Copy the service file to systemd folder
cp "$SERVICE_FILE" /etc/systemd/system/wg-dashboard.service

# Set permissions
chmod 664 /etc/systemd/system/wg-dashboard.service


cat <<'EOF_SCRIPT' | sudo tee /etc/xwireguard/monitor/wg.sh >/dev/null
#!/bin/bash

# Define the path to the directory containing WireGuard config files
WG_CONFIG_DIR="/etc/wireguard/"

# Function to combine Address lines under the [Interface] section
combine_addresses() {
    for wg_config in "$WG_CONFIG_DIR"*.conf; do
        awk '
        $1 == "[Interface]" { print; iface=1; next }
        iface && $1 == "Address" {
            if (address == "") {
                address = $3
            } else {
                address = address "," $3
            }
            next
        }
        iface && address != "" {
            print "Address =", address
            address = ""
        }
        { print }
        END { if (address != "") print "Address =", address }
        ' "$wg_config" > "$wg_config.tmp" && mv "$wg_config.tmp" "$wg_config"
    done
}

# Monitor the directory containing WireGuard config files for modifications
while true; do
    inotifywait -e modify "$WG_CONFIG_DIR"
    combine_addresses
    print "WireGuard config files modified\n"
done
EOF_SCRIPT


cat <<'EOF_SCRIPT' | sudo tee /etc/xwireguard/monitor/check_wg_config.sh >/dev/null
#!/bin/bash

# Define the path to the directory containing WireGuard config files
WG_CONFIG_DIR="/etc/wireguard/"

# Function to check for double lines of "Address" and modify the file if necessary
check_and_modify_wg_config() {
    for wg_config in "$WG_CONFIG_DIR"*.conf; do
        if grep -q '^Address =' "$wg_config" && grep -q '^Address =' "$wg_config" <(tail -n +2 "$wg_config"); then
            # Double lines of "Address" found, perform modification
            sed -i '$a #Wireguard IPv6 Monitoring Active on this file' "$wg_config"
            print "Double lines of 'Address' found and modified in $wg_config\n"
            # Trigger inotifywait to detect the modification
            touch "$wg_config"
        else
            print "No double lines of 'Address' found in $wg_config\n"
        fi
    done
}

# Execute the function to check and modify all WireGuard config files
check_and_modify_wg_config
EOF_SCRIPT

cat <<EOF | tee -a /etc/systemd/system/wgmonitor.service >/dev/null
[Unit]
Description=WireGuard Conf Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/etc/xwireguard/monitor/wg.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF | tee -a /etc/systemd/system/check_wg_config.service >/dev/null
[Unit]
Description=Check and Modify WireGuard Config Service
After=wg-dashboard.service
Requires=wg-dashboard.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c '/bin/sleep 10 && /etc/xwireguard/monitor/check_wg_config.sh'

[Install]
WantedBy=multi-user.target
EOF

chmod +x /etc/xwireguard/monitor/wg.sh
chmod +x /etc/xwireguard/monitor/check_wg_config.sh

# Enable and start WGDashboard service
systemctl enable wg-dashboard.service --quiet
systemctl restart wg-dashboard.service

# Enable and start WG0 Monitor service
systemctl enable wgmonitor.service --quiet
systemctl start  wgmonitor.service

# Seed to wg-dashboard.ini
sed -i "s|^app_port =.*|app_port = $dashboard_port|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null
sed -i "s|^peer_global_dns =.*|peer_global_dns = $dns|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null
sed -i "s|^peer_endpoint_allowed_ip =.*|peer_endpoint_allowed_ip = $allowed_ip|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null
sed -i "s|^password =.*|password = $hashed_password|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null
sed -i "s|^username =.*|username = $username|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null
sed -i "s|^dashboard_theme =.*|dashboard_theme = dark|g" $DASHBOARD_DIR/wg-dashboard.ini >/dev/null


systemctl restart wg-dashboard.service

# Enable  WireGuard Config Service Trigerring
systemctl enable check_wg_config.service --quiet
systemctl start  check_wg_config.service

# Check if the services restarted successfully
printf "Restarting Wireguard,  WGDashboard &  WGConfig Monitoring services .....\n"
printf "\n"

# Define the cron commands
cron_command_reboot="@reboot root /etc/xwireguard/monitor/check_wg_config.sh"
cron_command_every_minute="* * * * * /etc/xwireguard/monitor/check_wg_config.sh"

# Add the cron commands to the root user's crontab
{ crontab -l -u root 2>/dev/null; echo "$cron_command_reboot"; echo "$cron_command_every_minute"; } | crontab -u root -

# Check if the cron commands were added successfully
if crontab -l -u root | grep -q "$cron_command_reboot" && crontab -l -u root | grep -q "$cron_command_every_minute"; then
    printf "Cron jobs created successfully WGConfig Monitoring services.\n"
else
    printf "Failed to add cron jobs for WGConfig Monitoring services.\n"
fi
printf "\n"

wg_status=$(systemctl is-active wg-quick@wg0.service)
dashboard_status=$(systemctl is-active wg-dashboard.service)
wgmonitor_status=$(systemctl is-active wgmonitor.service)
printf "\n"
printf "Wireguard Status: $wg_status\n"
printf "WGDashboard Status: $dashboard_status\n"
printf "WGConfig Monitor Status: $wgmonitor_status\n"
printf "\n"

if [ "$wg_status" = "active" ] && [ "$dashboard_status" = "active" ]; then
    # Get the server IPv4 address
    server_ip=$(curl -s4 ifconfig.me)

    # Display final setup instructions
    printf "\n\n\e[32mSetup is complete!\e[0m\n\n"
    printf "You can now access Wireguard from WGDashboard at http://%s\n" "$server_ip:$dashboard_port"
    printf "Default login details:\n"
    printf "Username: %s\n" "$username"
    printf "Password: [The one you specified during setup]\n\n"
    printf "Thank you for using xWireGuard Management & Server.\n"
    printf "Please consider supporting WGDashboard on GitHub: https://github.com/donaldzou/WGDashboard\n"
    printf "System will reboot now and after that Go ahead and create your first peers.\n"
printf "\n"
printf "\n"
printf "Rebooting system .......\n"
reboot
else
    printf "Error: Installation failed. Please check the services and try again.\n"
fi
else
    printf "Sorry! Installation cancelled.\n"
    exit 0
fi
