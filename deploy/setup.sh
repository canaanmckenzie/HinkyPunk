#!/bin/bash
#
# HinkyPunk VPN Deployment Setup Script
# ======================================
#
# This script generates keys and configuration files for a two-machine
# deployment (server and client).
#
# Usage:
#   ./setup.sh server 10.0.0.1 192.168.1.100   # Server IP: 10.0.0.1, External: 192.168.1.100
#   ./setup.sh client 10.0.0.2 192.168.1.100   # Client IP: 10.0.0.2, Server: 192.168.1.100
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BIN="${SCRIPT_DIR}/../bin/vpn"
CONFIG_DIR="${SCRIPT_DIR}/configs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 <server|client> <tunnel_ip> <endpoint_ip> [port]"
    echo ""
    echo "Examples:"
    echo "  Server setup: $0 server 10.0.0.1 192.168.1.100 51820"
    echo "  Client setup: $0 client 10.0.0.2 192.168.1.100 51820"
    echo ""
    echo "The endpoint_ip should be:"
    echo "  - For server: The server's public/reachable IP"
    echo "  - For client: The server's IP to connect to"
}

generate_keys() {
    local name=$1
    local keyfile="${CONFIG_DIR}/${name}.key"
    local pubfile="${CONFIG_DIR}/${name}.pub"

    if [[ -f "$keyfile" ]]; then
        echo -e "${YELLOW}Using existing key for ${name}${NC}"
    else
        echo -e "${GREEN}Generating new key for ${name}${NC}"
        "${VPN_BIN}" genkey > "$keyfile"
        chmod 600 "$keyfile"
    fi

    cat "$keyfile" | "${VPN_BIN}" pubkey > "$pubfile"
    echo "  Private key: $keyfile"
    echo "  Public key:  $(cat $pubfile)"
}

setup_server() {
    local tunnel_ip=$1
    local external_ip=$2
    local port=${3:-51820}

    echo -e "${GREEN}=== Setting up VPN Server ===${NC}"
    echo ""

    mkdir -p "$CONFIG_DIR"

    # Generate server keys
    generate_keys "server"

    local server_privkey=$(cat "${CONFIG_DIR}/server.key")
    local server_pubkey=$(cat "${CONFIG_DIR}/server.pub")

    # Create server configuration
    cat > "${CONFIG_DIR}/server.conf" << EOF
[Interface]
# Server configuration for HinkyPunk VPN
PrivateKey = ${server_privkey}
ListenPort = ${port}
Address = ${tunnel_ip}/24

# Add client peers below after running setup.sh on the client
# [Peer]
# PublicKey = <client_public_key>
# AllowedIPs = 10.0.0.2/32

EOF

    chmod 600 "${CONFIG_DIR}/server.conf"

    echo ""
    echo -e "${GREEN}Server configuration created: ${CONFIG_DIR}/server.conf${NC}"
    echo ""
    echo "Server public key (share this with clients):"
    echo -e "${YELLOW}${server_pubkey}${NC}"
    echo ""
    echo "Server endpoint for clients:"
    echo -e "${YELLOW}${external_ip}:${port}${NC}"
    echo ""
    echo "To start the server:"
    echo "  sudo ${VPN_BIN} -c ${CONFIG_DIR}/server.conf"
}

setup_client() {
    local tunnel_ip=$1
    local server_ip=$2
    local port=${3:-51820}

    echo -e "${GREEN}=== Setting up VPN Client ===${NC}"
    echo ""

    mkdir -p "$CONFIG_DIR"

    # Generate client keys
    generate_keys "client"

    local client_privkey=$(cat "${CONFIG_DIR}/client.key")
    local client_pubkey=$(cat "${CONFIG_DIR}/client.pub")

    # Check if server public key exists
    if [[ ! -f "${CONFIG_DIR}/server.pub" ]]; then
        echo -e "${YELLOW}Server public key not found.${NC}"
        echo "Enter the server's public key:"
        read -r server_pubkey
        echo "$server_pubkey" > "${CONFIG_DIR}/server.pub"
    else
        server_pubkey=$(cat "${CONFIG_DIR}/server.pub")
    fi

    # Create client configuration
    cat > "${CONFIG_DIR}/client.conf" << EOF
[Interface]
# Client configuration for HinkyPunk VPN
PrivateKey = ${client_privkey}
Address = ${tunnel_ip}/24

[Peer]
# Server peer
PublicKey = ${server_pubkey}
Endpoint = ${server_ip}:${port}
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25

EOF

    chmod 600 "${CONFIG_DIR}/client.conf"

    echo ""
    echo -e "${GREEN}Client configuration created: ${CONFIG_DIR}/client.conf${NC}"
    echo ""
    echo "Client public key (add this to server config):"
    echo -e "${YELLOW}${client_pubkey}${NC}"
    echo ""
    echo "Add this to your server's config file:"
    echo ""
    echo "[Peer]"
    echo "PublicKey = ${client_pubkey}"
    echo "AllowedIPs = ${tunnel_ip}/32"
    echo ""
    echo "To start the client:"
    echo "  sudo ${VPN_BIN} -c ${CONFIG_DIR}/client.conf"
}

# Main
if [[ $# -lt 3 ]]; then
    print_usage
    exit 1
fi

# Check if VPN binary exists
if [[ ! -x "$VPN_BIN" ]]; then
    echo -e "${RED}Error: VPN binary not found at $VPN_BIN${NC}"
    echo "Please build the VPN first with: make"
    exit 1
fi

case $1 in
    server)
        setup_server "$2" "$3" "${4:-51820}"
        ;;
    client)
        setup_client "$2" "$3" "${4:-51820}"
        ;;
    *)
        echo -e "${RED}Unknown mode: $1${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Setup complete!${NC}"
