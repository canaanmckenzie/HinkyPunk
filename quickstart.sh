#!/bin/bash
#
# HinkyPunk VPN - Quickstart Script
# ==================================
#
# A single script to clean, build, and configure HinkyPunk VPN.
#
# Usage:
#   ./quickstart.sh clean     - Remove all build artifacts
#   ./quickstart.sh build     - Compile the VPN from source
#   ./quickstart.sh setup     - Interactive guided configuration
#   ./quickstart.sh all       - Clean, build, and setup (full workflow)
#   ./quickstart.sh help      - Show this help message
#

set -e

# ===========================================================================
# Configuration
# ===========================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BIN="${SCRIPT_DIR}/bin/vpn"
CONFIG_DIR="${SCRIPT_DIR}/configs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ===========================================================================
# Helper Functions
# ===========================================================================

print_banner() {
    echo -e "${CYAN}"
    echo " _   _ _       _          ____             _    "
    echo "| | | (_)_ __ | | ___   _|  _ \ _   _ _ __ | | __"
    echo "| |_| | | '_ \| |/ / | | | |_) | | | | '_ \| |/ /"
    echo "|  _  | | | | |   <| |_| |  __/| |_| | | | |   < "
    echo "|_| |_|_|_| |_|_|\_\\\\__, |_|    \\__,_|_| |_|_|\\_\\"
    echo "                    |___/                        "
    echo -e "${NC}"
    echo -e "${BOLD}Secure VPN built from scratch in C${NC}"
    echo ""
}

print_help() {
    echo -e "${BOLD}Usage:${NC} $0 <command>"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo "  clean     Remove all build artifacts (bin/, obj/, configs/)"
    echo "  build     Compile the VPN binary"
    echo "  setup     Interactive guided configuration wizard"
    echo "  all       Run clean, build, and setup sequentially"
    echo "  help      Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 build          # Just compile"
    echo "  $0 setup          # Configure after building"
    echo "  $0 all            # Fresh start: clean, build, configure"
    echo ""
}

confirm() {
    local prompt="$1"
    local response
    echo -ne "${YELLOW}${prompt} [y/N]: ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

# ===========================================================================
# Clean Function
# ===========================================================================

do_clean() {
    echo -e "${BLUE}=== Cleaning Build Artifacts ===${NC}"
    echo ""

    local cleaned=0

    # Remove object files
    if [[ -d "${SCRIPT_DIR}/obj" ]]; then
        echo -e "  Removing ${YELLOW}obj/${NC} directory..."
        rm -rf "${SCRIPT_DIR}/obj"
        ((cleaned++))
    fi

    # Remove binary directory
    if [[ -d "${SCRIPT_DIR}/bin" ]]; then
        echo -e "  Removing ${YELLOW}bin/${NC} directory..."
        rm -rf "${SCRIPT_DIR}/bin"
        ((cleaned++))
    fi

    # Remove generated configs (optional)
    if [[ -d "${CONFIG_DIR}" ]]; then
        if confirm "  Remove generated configs in configs/?"; then
            rm -rf "${CONFIG_DIR}"
            ((cleaned++))
        fi
    fi

    # Remove deploy/configs (optional)
    if [[ -d "${SCRIPT_DIR}/deploy/configs" ]]; then
        if confirm "  Remove deploy/configs/?"; then
            rm -rf "${SCRIPT_DIR}/deploy/configs"
            ((cleaned++))
        fi
    fi

    # Remove any stray key files in root
    local keyfiles=$(find "${SCRIPT_DIR}" -maxdepth 1 -name "*.key" -o -name "*.pub" 2>/dev/null | head -5)
    if [[ -n "$keyfiles" ]]; then
        echo -e "  Found key files in root directory:"
        echo "$keyfiles" | while read f; do echo "    $f"; done
        if confirm "  Remove these key files?"; then
            find "${SCRIPT_DIR}" -maxdepth 1 \( -name "*.key" -o -name "*.pub" \) -delete
            ((cleaned++))
        fi
    fi

    # Remove debug files
    if [[ -f "${SCRIPT_DIR}/debug_chacha20.c" ]]; then
        rm -f "${SCRIPT_DIR}/debug_chacha20.c"
    fi

    echo ""
    if [[ $cleaned -gt 0 ]]; then
        echo -e "${GREEN}Clean complete.${NC} Removed $cleaned item(s)."
    else
        echo -e "${GREEN}Already clean.${NC} Nothing to remove."
    fi
    echo ""
}

# ===========================================================================
# Build Function
# ===========================================================================

do_build() {
    echo -e "${BLUE}=== Building HinkyPunk VPN ===${NC}"
    echo ""

    # Check for compiler
    if ! command -v gcc &> /dev/null && ! command -v cc &> /dev/null; then
        echo -e "${RED}Error: No C compiler found.${NC}"
        echo "Please install build-essential (Debian/Ubuntu) or base-devel (Arch)."
        exit 1
    fi

    # Check for make
    if ! command -v make &> /dev/null; then
        echo -e "${RED}Error: 'make' not found.${NC}"
        echo "Please install build-essential (Debian/Ubuntu) or base-devel (Arch)."
        exit 1
    fi

    echo -e "  Compiler: $(cc --version | head -1)"
    echo -e "  Building with: ${CYAN}make${NC}"
    echo ""

    # Run make
    cd "${SCRIPT_DIR}"
    if make; then
        echo ""
        echo -e "${GREEN}Build successful!${NC}"
        echo -e "  Binary: ${CYAN}${VPN_BIN}${NC}"
        echo ""

        # Verify binary
        if [[ -x "${VPN_BIN}" ]]; then
            echo -e "  Testing key generation..."
            local testkey=$("${VPN_BIN}" genkey 2>/dev/null)
            if [[ ${#testkey} -eq 44 ]]; then
                echo -e "  ${GREEN}Key generation works.${NC}"
            else
                echo -e "  ${YELLOW}Warning: Key generation may have issues.${NC}"
            fi
        fi
    else
        echo ""
        echo -e "${RED}Build failed.${NC} Check errors above."
        exit 1
    fi
    echo ""
}

# ===========================================================================
# Setup Function - Interactive Configuration Wizard
# ===========================================================================

do_setup() {
    echo -e "${BLUE}=== HinkyPunk Configuration Wizard ===${NC}"
    echo ""

    # Check if binary exists
    if [[ ! -x "${VPN_BIN}" ]]; then
        echo -e "${RED}Error: VPN binary not found.${NC}"
        echo "Run '$0 build' first."
        exit 1
    fi

    # Create config directory
    mkdir -p "${CONFIG_DIR}"

    # Step 1: Choose role
    echo -e "${BOLD}Step 1: Select Role${NC}"
    echo ""
    echo "  1) Server (accepts incoming connections)"
    echo "  2) Client (connects to a server)"
    echo ""

    local role
    while true; do
        echo -ne "${YELLOW}Select [1/2]: ${NC}"
        read -r choice
        case "$choice" in
            1) role="server"; break ;;
            2) role="client"; break ;;
            *) echo "  Please enter 1 or 2." ;;
        esac
    done
    echo ""

    # Step 2: Generate or load keys
    echo -e "${BOLD}Step 2: Key Management${NC}"
    echo ""

    local keyfile="${CONFIG_DIR}/${role}.key"
    local pubfile="${CONFIG_DIR}/${role}.pub"
    local privkey pubkey

    if [[ -f "$keyfile" ]]; then
        echo -e "  Found existing key: ${CYAN}${keyfile}${NC}"
        if confirm "  Use existing key?"; then
            privkey=$(cat "$keyfile")
            pubkey=$(echo "$privkey" | "${VPN_BIN}" pubkey)
        else
            echo -e "  Generating new key..."
            privkey=$("${VPN_BIN}" genkey)
            echo "$privkey" > "$keyfile"
            chmod 600 "$keyfile"
            pubkey=$(echo "$privkey" | "${VPN_BIN}" pubkey)
            echo "$pubkey" > "$pubfile"
        fi
    else
        echo -e "  Generating new key pair..."
        privkey=$("${VPN_BIN}" genkey)
        echo "$privkey" > "$keyfile"
        chmod 600 "$keyfile"
        pubkey=$(echo "$privkey" | "${VPN_BIN}" pubkey)
        echo "$pubkey" > "$pubfile"
    fi

    echo ""
    echo -e "  ${GREEN}Your public key:${NC}"
    echo -e "  ${CYAN}${pubkey}${NC}"
    echo ""
    echo -e "  ${YELLOW}Share this public key with your peer.${NC}"
    echo ""

    # Step 3: Network configuration
    echo -e "${BOLD}Step 3: Network Configuration${NC}"
    echo ""

    local tunnel_ip listen_port

    if [[ "$role" == "server" ]]; then
        echo -ne "  Tunnel IP address [${CYAN}10.0.0.1${NC}]: "
        read -r tunnel_ip
        tunnel_ip=${tunnel_ip:-10.0.0.1}

        echo -ne "  Listen port [${CYAN}51820${NC}]: "
        read -r listen_port
        listen_port=${listen_port:-51820}
    else
        echo -ne "  Tunnel IP address [${CYAN}10.0.0.2${NC}]: "
        read -r tunnel_ip
        tunnel_ip=${tunnel_ip:-10.0.0.2}

        listen_port=51820
    fi
    echo ""

    # Step 4: Peer configuration
    echo -e "${BOLD}Step 4: Peer Configuration${NC}"
    echo ""

    local peer_pubkey peer_endpoint peer_allowed_ips

    echo -ne "  Peer's public key: "
    read -r peer_pubkey

    if [[ -z "$peer_pubkey" ]]; then
        echo -e "  ${YELLOW}No peer configured. You can add peers later.${NC}"
        peer_pubkey=""
    else
        if [[ "$role" == "client" ]]; then
            echo -ne "  Server endpoint (IP:port): "
            read -r peer_endpoint

            echo -ne "  Allowed IPs [${CYAN}10.0.0.0/24${NC}]: "
            read -r peer_allowed_ips
            peer_allowed_ips=${peer_allowed_ips:-10.0.0.0/24}
        else
            echo -ne "  Client's allowed IP [${CYAN}10.0.0.2/32${NC}]: "
            read -r peer_allowed_ips
            peer_allowed_ips=${peer_allowed_ips:-10.0.0.2/32}
            peer_endpoint=""
        fi
    fi
    echo ""

    # Step 5: Generate configuration file
    echo -e "${BOLD}Step 5: Generating Configuration${NC}"
    echo ""

    local conffile="${CONFIG_DIR}/${role}.conf"

    {
        echo "[Interface]"
        echo "# HinkyPunk VPN - ${role^} Configuration"
        echo "# Generated: $(date)"
        echo "PrivateKey = ${privkey}"
        echo "Address = ${tunnel_ip}/24"

        if [[ "$role" == "server" ]]; then
            echo "ListenPort = ${listen_port}"
        fi

        if [[ -n "$peer_pubkey" ]]; then
            echo ""
            echo "[Peer]"
            echo "PublicKey = ${peer_pubkey}"

            if [[ -n "$peer_endpoint" ]]; then
                echo "Endpoint = ${peer_endpoint}"
            fi

            echo "AllowedIPs = ${peer_allowed_ips}"

            if [[ "$role" == "client" ]]; then
                echo "PersistentKeepalive = 25"
            fi
        fi
    } > "$conffile"

    chmod 600 "$conffile"

    echo -e "  Configuration saved to: ${CYAN}${conffile}${NC}"
    echo ""

    # Step 6: Summary and next steps
    echo -e "${BOLD}=== Setup Complete ===${NC}"
    echo ""
    echo -e "${GREEN}Your HinkyPunk VPN is configured!${NC}"
    echo ""
    echo -e "${BOLD}Files created:${NC}"
    echo "  Private key: ${keyfile}"
    echo "  Public key:  ${pubfile}"
    echo "  Config file: ${conffile}"
    echo ""
    echo -e "${BOLD}Your public key (share with peer):${NC}"
    echo -e "  ${CYAN}${pubkey}${NC}"
    echo ""
    echo -e "${BOLD}To start the VPN:${NC}"
    echo -e "  ${CYAN}sudo ${VPN_BIN} -c ${conffile}${NC}"
    echo ""

    if [[ "$role" == "server" ]]; then
        echo -e "${BOLD}Firewall:${NC}"
        echo "  sudo ufw allow ${listen_port}/udp"
        echo ""
    fi

    if [[ -z "$peer_pubkey" ]]; then
        echo -e "${YELLOW}Note: No peer configured yet.${NC}"
        echo "Edit ${conffile} to add [Peer] sections."
        echo ""
    fi
}

# ===========================================================================
# Main Entry Point
# ===========================================================================

main() {
    cd "${SCRIPT_DIR}"

    case "${1:-help}" in
        clean)
            print_banner
            do_clean
            ;;
        build|-build|--build)
            print_banner
            do_build
            ;;
        setup)
            print_banner
            do_setup
            ;;
        all)
            print_banner
            do_clean
            do_build
            do_setup
            ;;
        help|-h|--help)
            print_banner
            print_help
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            echo ""
            print_help
            exit 1
            ;;
    esac
}

main "$@"
