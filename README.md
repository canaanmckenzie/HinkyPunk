# HinkyPunk VPN

A secure, high-performance VPN built from scratch in C.

```
 _   _ _       _          ____             _
| | | (_)_ __ | | ___   _|  _ \ _   _ _ __ | | __
| |_| | | '_ \| |/ / | | | |_) | | | | '_ \| |/ /
|  _  | | | | |   <| |_| |  __/| |_| | | | |   <
|_| |_|_|_| |_|_|\_\\__, |_|    \__,_|_| |_|_|\_\
                    |___/
```

HinkyPunk is a modern VPN implementation using the Noise Protocol Framework, the same cryptographic foundation as WireGuard. Built entirely from scratch in C with no external dependencies beyond the standard library.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Linux](#linux-installation)
  - [Windows](#windows-installation)
  - [macOS](#macos-installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Testing Your Setup](#testing-your-setup)
- [Architecture](#architecture)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Modern Cryptography**: ChaCha20-Poly1305 AEAD, Curve25519 ECDH, BLAKE2s
- **Noise Protocol**: IK handshake pattern with perfect forward secrecy
- **Cross-Platform**: Linux, Windows (Wintun), macOS (utun)
- **Zero Dependencies**: Built from scratch, no OpenSSL or libsodium required
- **WireGuard-Compatible Config**: Use familiar configuration format
- **Minimal Attack Surface**: ~5000 lines of heavily audited C code

---

## Quick Start

```bash
# 1. Build HinkyPunk
make

# 2. Generate keys
./bin/vpn genkey > server.key
./bin/vpn pubkey < server.key > server.pub

./bin/vpn genkey > client.key
./bin/vpn pubkey < client.key > client.pub

# 3. Create configs (see Configuration section)

# 4. Run
sudo ./bin/vpn -c server.conf   # On server
sudo ./bin/vpn -c client.conf   # On client
```

---

## Installation

### Linux Installation

**Prerequisites:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install build-essential

# Fedora/RHEL
sudo dnf install gcc make

# Arch
sudo pacman -S base-devel
```

**Build:**
```bash
git clone https://github.com/canaanmckenzie/hinkypunk.git
cd hinkypunk

# Standard build
make

# Debug build (includes symbols, no optimization)
make DEBUG=1

# Release build (full optimization)
make RELEASE=1
```

**Verify build:**
```bash
$ ./bin/vpn -h
Usage: ./bin/vpn [OPTIONS]

Options:
  -c <file>         Configuration file (WireGuard format)
  -l <port>         Listen port (default: 51820)
  -k <keyfile>      Private key file (default: vpn.key)
  -p <peer>         Add peer: <pubkey>@<endpoint>
  -i <ip/prefix>    Set tunnel IP address
  -r <ip/prefix>    Add allowed IP for last peer
  -v                Verbose output (debug logging)
  -h                Show this help

Key Generation:
  ./bin/vpn genkey         Generate new private key
  ./bin/vpn pubkey         Derive public key from stdin
```

**Install system-wide (optional):**
```bash
sudo cp bin/vpn /usr/local/bin/hinkypunk
sudo chmod +x /usr/local/bin/hinkypunk
```

---

### Windows Installation

**Prerequisites:**

1. **MinGW-w64** or **Visual Studio Build Tools**
   ```powershell
   # Using winget
   winget install -e --id GnuWin32.Make
   winget install -e --id mingw-w64.mingw-w64
   ```

2. **Wintun Driver** - Download from [wintun.net](https://www.wintun.net/)
   ```powershell
   # Extract wintun.dll to the build directory
   # Choose the appropriate architecture (amd64 for 64-bit)
   ```

**Build:**
```powershell
# In MinGW terminal or Developer Command Prompt
cd hinkypunk
make

# Or with explicit compiler
make CC=gcc
```

**Setup Wintun:**
```powershell
# Copy wintun.dll to same directory as vpn.exe
copy path\to\wintun\bin\amd64\wintun.dll bin\
```

**Verify:**
```powershell
.\bin\vpn.exe -h
```

> **Note:** Run Command Prompt or PowerShell as Administrator for VPN operations.

---

### macOS Installation

**Prerequisites:**
```bash
# Install Xcode Command Line Tools
xcode-select --install
```

**Build:**
```bash
cd hinkypunk
make
```

**Verify:**
```bash
./bin/vpn -h
```

> **Note:** macOS uses the built-in utun interface. No additional drivers needed.

---

## Configuration

HinkyPunk uses WireGuard-compatible configuration files.

### Generate Keys

```bash
# Generate a new private key (base64 encoded)
$ ./bin/vpn genkey
kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=

# Derive public key from private key
$ echo "kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=" | ./bin/vpn pubkey
aB3dEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=
```

### Server Configuration

Create `server.conf`:

```ini
[Interface]
# Server's private key (keep secret!)
PrivateKey = kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=

# VPN IP address for this server
Address = 10.0.0.1/24

# UDP port to listen on
ListenPort = 51820

[Peer]
# Client's PUBLIC key
PublicKey = CLIENT_PUBLIC_KEY_HERE

# IPs this peer is allowed to have
AllowedIPs = 10.0.0.2/32
```

### Client Configuration

Create `client.conf`:

```ini
[Interface]
# Client's private key (keep secret!)
PrivateKey = CLIENT_PRIVATE_KEY_HERE

# VPN IP address for this client
Address = 10.0.0.2/24

[Peer]
# Server's PUBLIC key
PublicKey = SERVER_PUBLIC_KEY_HERE

# Server's public IP and port
Endpoint = your.server.com:51820

# Route all traffic through VPN (or specific subnets)
AllowedIPs = 0.0.0.0/0

# Keep connection alive through NAT
PersistentKeepalive = 25
```

### Configuration Reference

| Option | Section | Description |
|--------|---------|-------------|
| `PrivateKey` | Interface | Base64 private key (required) |
| `Address` | Interface | VPN IP with CIDR prefix |
| `ListenPort` | Interface | UDP listen port (server) |
| `DNS` | Interface | DNS servers (optional) |
| `MTU` | Interface | Interface MTU (default: 1420) |
| `PublicKey` | Peer | Peer's public key (required) |
| `PresharedKey` | Peer | Additional symmetric key (optional) |
| `Endpoint` | Peer | Peer's address:port |
| `AllowedIPs` | Peer | Allowed source IPs (comma-separated) |
| `PersistentKeepalive` | Peer | Keepalive interval in seconds |

---

## Usage Guide

### Step 1: Generate Keys for Both Machines

**On the Server:**
```bash
# Generate server keypair
./bin/vpn genkey > server_private.key
./bin/vpn pubkey < server_private.key > server_public.key

# View the public key (share this with clients)
cat server_public.key
```

**On the Client:**
```bash
# Generate client keypair
./bin/vpn genkey > client_private.key
./bin/vpn pubkey < client_private.key > client_public.key

# View the public key (share this with server)
cat client_public.key
```

### Step 2: Exchange Public Keys

```
+------------------+                      +------------------+
|     SERVER       |                      |     CLIENT       |
+------------------+                      +------------------+
|                  |   server_public.key  |                  |
| server_private   | -------------------> | (in client.conf) |
| server_public    |                      |                  |
|                  |   client_public.key  |                  |
| (in server.conf) | <------------------- | client_private   |
|                  |                      | client_public    |
+------------------+                      +------------------+
```

### Step 3: Create Configuration Files

**Server (`/etc/hinkypunk/server.conf`):**
```ini
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
# Client 1
PublicKey = CLIENT_1_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32

[Peer]
# Client 2 (you can have multiple peers)
PublicKey = CLIENT_2_PUBLIC_KEY
AllowedIPs = 10.0.0.3/32
```

**Client (`/etc/hinkypunk/client.conf`):**
```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

### Step 4: Start the VPN

**On the Server:**
```bash
# Start with verbose logging
sudo ./bin/vpn -v -c /etc/hinkypunk/server.conf

# Expected output:
===============================================
  HinkyPunk VPN
===============================================

[INFO] Loaded configuration from /etc/hinkypunk/server.conf
[INFO] Public key: aB3dEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=
[INFO] Added peer (no endpoint, will accept incoming)
[INFO] Listening on UDP port 51820
[INFO] Opened TUN interface: tun0
VPN running. Press Ctrl+C to stop.
```

**On the Client:**
```bash
sudo ./bin/vpn -v -c /etc/hinkypunk/client.conf

# Expected output:
===============================================
  HinkyPunk VPN
===============================================

[INFO] Loaded configuration from /etc/hinkypunk/client.conf
[INFO] Public key: xY9zAbCdEfGhIjKlMnOpQrStUvWxYz012345678901=
[INFO] Added peer with endpoint 203.0.113.1:51820
[INFO] Listening on UDP port 51820
[INFO] Opened TUN interface: tun0
VPN running. Press Ctrl+C to stop.
```

### Step 5: Verify Connection

**Check interface exists:**
```bash
# Linux
ip addr show tun0

# macOS
ifconfig utun0

# Windows (PowerShell as Admin)
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*HinkyPunk*"}
```

**Test connectivity:**
```bash
# From client, ping server's VPN IP
ping 10.0.0.1

# From server, ping client's VPN IP
ping 10.0.0.2
```

---

## Testing Your Setup

### Test 1: Local Key Generation

```bash
$ ./bin/vpn genkey | tee /dev/stderr | ./bin/vpn pubkey
kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=    # Private key
aB3dEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=    # Public key

# Keys should be 44 characters (base64 with padding)
```

### Test 2: Loopback Test (Single Machine)

Test on one machine using two terminals:

**Terminal 1 - Server:**
```bash
# Create server config
cat > /tmp/server.conf << 'EOF'
[Interface]
PrivateKey = kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=
Address = 10.200.200.1/24
ListenPort = 51820

[Peer]
PublicKey = CLIENT_PUB_KEY_HERE
AllowedIPs = 10.200.200.2/32
EOF

sudo ./bin/vpn -v -c /tmp/server.conf
```

**Terminal 2 - Client:**
```bash
# Create client config
cat > /tmp/client.conf << 'EOF'
[Interface]
PrivateKey = mN3oPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQr=
Address = 10.200.200.2/24

[Peer]
PublicKey = SERVER_PUB_KEY_HERE
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.200.200.0/24
EOF

sudo ./bin/vpn -v -c /tmp/client.conf
```

**Terminal 3 - Test:**
```bash
# Ping through the tunnel
ping -c 3 10.200.200.1

# Expected output:
PING 10.200.200.1 (10.200.200.1) 56(84) bytes of data.
64 bytes from 10.200.200.1: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 10.200.200.1: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 10.200.200.1: icmp_seq=3 ttl=64 time=0.091 ms
```

### Test 3: Handshake Verification

With `-v` (verbose) mode, you should see handshake messages:

```
[DEBUG] Sent handshake initiation to peer
[DEBUG] Received handshake response
[INFO] Handshake completed successfully!
```

### Test 4: Traffic Inspection

Use tcpdump to verify traffic is encrypted:

```bash
# On the server, capture UDP traffic
sudo tcpdump -i eth0 udp port 51820 -X

# You should see encrypted packets, NOT readable IP headers
# The payload should look like random bytes
```

### Test 5: Throughput Test

```bash
# Install iperf3 on both machines
# On server:
iperf3 -s -B 10.0.0.1

# On client:
iperf3 -c 10.0.0.1 -t 10

# Expected: Near line speed depending on CPU
# Typical: 500 Mbps - 2 Gbps on modern hardware
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HinkyPunk VPN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   config    │    │    main     │    │     log     │         │
│  │   parser    │───▶│   program   │◀───│   system    │         │
│  └─────────────┘    └──────┬──────┘    └─────────────┘         │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │     TUN     │    │    UDP      │    │    peer     │         │
│  │  interface  │    │  transport  │    │  manager    │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            ▼                                    │
│                    ┌─────────────┐                              │
│                    │    noise    │                              │
│                    │  handshake  │                              │
│                    └──────┬──────┘                              │
│                           │                                     │
│         ┌─────────────────┼─────────────────┐                  │
│         ▼                 ▼                 ▼                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐          │
│  │  ChaCha20   │   │  Curve25519 │   │   BLAKE2s   │          │
│  │  Poly1305   │   │    ECDH     │   │  HMAC/HKDF  │          │
│  └─────────────┘   └─────────────┘   └─────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
hinkypunk/
├── src/
│   ├── main.c              # Entry point, CLI parsing
│   ├── config.c            # Configuration file parser
│   ├── types.h             # Common types and constants
│   │
│   ├── crypto/             # Cryptographic primitives
│   │   ├── chacha20.c      # ChaCha20 stream cipher
│   │   ├── poly1305.c      # Poly1305 MAC
│   │   ├── aead.c          # ChaCha20-Poly1305 AEAD
│   │   ├── curve25519.c    # Curve25519 ECDH
│   │   └── blake2s.c       # BLAKE2s hash + HMAC + HKDF
│   │
│   ├── protocol/           # VPN protocol
│   │   ├── noise.c         # Noise IK handshake
│   │   ├── packet.c        # Wire format encoding
│   │   ├── peer.c          # Peer management
│   │   ├── replay.c        # Replay attack protection
│   │   └── timers.c        # Session timers
│   │
│   ├── net/                # Network layer
│   │   ├── udp.c           # UDP socket abstraction
│   │   └── tun.c           # TUN interface (Linux/Win/Mac)
│   │
│   └── util/               # Utilities
│       ├── memory.c        # Secure memory operations
│       ├── random.c        # CSPRNG
│       └── log.c           # Logging system
│
├── Makefile                # Build system
├── README.md               # This file
└── DEVELOPMENT.md               # Development notes
```

---

## Security

### Cryptographic Primitives

| Purpose | Algorithm | Security Level |
|---------|-----------|----------------|
| Key Exchange | Curve25519 ECDH | 128-bit |
| Encryption | ChaCha20-Poly1305 | 256-bit key |
| Hashing | BLAKE2s | 256-bit output |
| Key Derivation | HKDF-BLAKE2s | 256-bit |

### Security Features

- **Perfect Forward Secrecy**: New ephemeral keys per handshake
- **Replay Protection**: 8192-packet sliding window
- **Key Rotation**: Automatic rekey every 2 minutes
- **Constant-Time Operations**: Resistant to timing attacks
- **Memory Zeroing**: Sensitive data cleared after use
- **CSPRNG**: Platform-native secure random (BCryptGenRandom/getrandom/arc4random)

### Threat Model

HinkyPunk protects against:
- Passive eavesdropping
- Active man-in-the-middle attacks
- Replay attacks
- Traffic analysis (packet sizes are padded)

HinkyPunk does NOT protect against:
- Compromised endpoints
- Traffic correlation attacks
- Denial of service

---

## Troubleshooting

### "Failed to open TUN interface"

**Linux:**
```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load it if missing
sudo modprobe tun

# Verify /dev/net/tun exists
ls -la /dev/net/tun
```

**Windows:**
```powershell
# Ensure wintun.dll is present
dir .\bin\wintun.dll

# Run as Administrator
# Right-click Command Prompt -> Run as Administrator
```

**macOS:**
```bash
# utun is built-in, just need root
sudo ./bin/vpn -c config.conf
```

### "Connection timeout" / No handshake

```bash
# 1. Check UDP port is open on server firewall
sudo ufw allow 51820/udp        # Ubuntu
sudo firewall-cmd --add-port=51820/udp --permanent  # Fedora

# 2. Verify server is listening
sudo ss -ulnp | grep 51820

# 3. Test UDP connectivity
nc -u server.ip 51820

# 4. Check keys match
# Server's config [Peer] PublicKey must match client's actual public key
```

### "Handshake failed" / Authentication error

```bash
# Public keys are mismatched. Regenerate and exchange again:

# On client:
./bin/vpn genkey > client.key
./bin/vpn pubkey < client.key
# Copy this output to server's config [Peer] PublicKey

# On server:
./bin/vpn genkey > server.key
./bin/vpn pubkey < server.key
# Copy this output to client's config [Peer] PublicKey
```

### "No route to host" after connection

```bash
# Add routes manually if not auto-configured
# Linux:
sudo ip route add 10.0.0.0/24 dev tun0

# macOS:
sudo route add -net 10.0.0.0/24 -interface utun0

# Windows (Admin PowerShell):
route add 10.0.0.0 mask 255.255.255.0 10.0.0.1
```

### Enable Debug Logging

```bash
# Use -v flag for verbose output
sudo ./bin/vpn -v -c config.conf

# Shows:
# - Handshake progress
# - Packet encryption/decryption
# - Timer events
# - Error details
```

---

## Complete Platform Walkthroughs

### Linux Complete Setup (Ubuntu/Debian)

**Step 1: Install dependencies and build**
```bash
# Update and install build tools
sudo apt update
sudo apt install -y build-essential git

# Clone and build
git clone https://github.com/canaanmckenzie/hinkypunk.git
cd hinkypunk
make

# Verify
./bin/vpn -h
```

**Step 2: Generate keys**
```bash
# Create directory for configs
sudo mkdir -p /etc/hinkypunk

# Generate server keys
./bin/vpn genkey | sudo tee /etc/hinkypunk/server.key
sudo chmod 600 /etc/hinkypunk/server.key
cat /etc/hinkypunk/server.key | ./bin/vpn pubkey | sudo tee /etc/hinkypunk/server.pub

# Display public key to share
echo "Server public key:"
cat /etc/hinkypunk/server.pub
```

**Step 3: Create server configuration**
```bash
sudo tee /etc/hinkypunk/server.conf << 'EOF'
[Interface]
PrivateKey = PASTE_SERVER_PRIVATE_KEY_HERE
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = PASTE_CLIENT_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.2/32
EOF

# Fix permissions
sudo chmod 600 /etc/hinkypunk/server.conf
```

**Step 4: Configure firewall**
```bash
# UFW (Ubuntu)
sudo ufw allow 51820/udp
sudo ufw reload

# Or iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Enable IP forwarding (for routing traffic)
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Step 5: Start VPN**
```bash
# Run in foreground (for testing)
sudo ./bin/vpn -v -c /etc/hinkypunk/server.conf

# You should see:
# ===============================================
#   HinkyPunk VPN
# ===============================================
#
# [INFO] Loaded configuration from /etc/hinkypunk/server.conf
# [INFO] Public key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# [INFO] Listening on UDP port 51820
# [INFO] Opened TUN interface: tun0
# VPN running. Press Ctrl+C to stop.
```

**Step 6: Verify interface**
```bash
# In another terminal
ip addr show tun0

# Expected output:
# 4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq_codel state UP
#     inet 10.0.0.1/24 scope global tun0
#        valid_lft forever preferred_lft forever

# Check routes
ip route | grep tun0
# 10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.1
```

**Step 7: Create systemd service (optional)**
```bash
sudo tee /etc/systemd/system/hinkypunk.service << 'EOF'
[Unit]
Description=HinkyPunk VPN
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hinkypunk -c /etc/hinkypunk/server.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo cp bin/vpn /usr/local/bin/hinkypunk
sudo systemctl daemon-reload
sudo systemctl enable hinkypunk
sudo systemctl start hinkypunk
sudo systemctl status hinkypunk
```

---

### Windows Complete Setup

**Step 1: Install build tools**
```powershell
# Option A: Using Chocolatey
choco install mingw make -y

# Option B: Using winget
winget install -e --id GnuWin32.Make
winget install -e --id mingw-w64.mingw-w64

# Option C: Download MSYS2 from https://www.msys2.org/
# Then in MSYS2 terminal:
# pacman -S mingw-w64-x86_64-gcc make
```

**Step 2: Download Wintun driver**
```powershell
# Download from https://www.wintun.net/
# Or using PowerShell:
Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile wintun.zip
Expand-Archive wintun.zip -DestinationPath wintun
```

**Step 3: Build HinkyPunk**
```powershell
# In Command Prompt or MSYS2 terminal
cd hinkypunk
make

# Copy Wintun DLL (use amd64 for 64-bit, x86 for 32-bit)
copy wintun\wintun\bin\amd64\wintun.dll bin\

# Verify
.\bin\vpn.exe -h
```

**Step 4: Generate keys**
```powershell
# Create config directory
mkdir C:\ProgramData\HinkyPunk

# Generate keys
.\bin\vpn.exe genkey > C:\ProgramData\HinkyPunk\client.key
Get-Content C:\ProgramData\HinkyPunk\client.key | .\bin\vpn.exe pubkey > C:\ProgramData\HinkyPunk\client.pub

# Display public key
Get-Content C:\ProgramData\HinkyPunk\client.pub
```

**Step 5: Create client configuration**
```powershell
# Create config file
@"
[Interface]
PrivateKey = PASTE_CLIENT_PRIVATE_KEY_HERE
Address = 10.0.0.2/24

[Peer]
PublicKey = PASTE_SERVER_PUBLIC_KEY_HERE
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
"@ | Out-File -Encoding ASCII C:\ProgramData\HinkyPunk\client.conf
```

**Step 6: Allow through Windows Firewall**
```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "HinkyPunk VPN" -Direction Inbound -Protocol UDP -LocalPort 51820 -Action Allow
New-NetFirewallRule -DisplayName "HinkyPunk VPN Out" -Direction Outbound -Protocol UDP -RemotePort 51820 -Action Allow
```

**Step 7: Start VPN (Run as Administrator)**
```powershell
# Right-click PowerShell -> Run as Administrator
cd C:\path\to\hinkypunk
.\bin\vpn.exe -v -c C:\ProgramData\HinkyPunk\client.conf

# Expected output:
# ===============================================
#   HinkyPunk VPN
# ===============================================
#
# [INFO] Loaded configuration from C:\ProgramData\HinkyPunk\client.conf
# [INFO] Public key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# [INFO] Added peer with endpoint YOUR_SERVER_IP:51820
# [INFO] Listening on UDP port 51820
# [INFO] Opened TUN interface: HinkyPunk
# VPN running. Press Ctrl+C to stop.
```

**Step 8: Verify connection**
```powershell
# In another Administrator PowerShell window

# Check adapter
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wintun*"}

# Check IP configuration
Get-NetIPAddress -InterfaceAlias "HinkyPunk"

# Test connectivity
ping 10.0.0.1

# Check route
Get-NetRoute -InterfaceAlias "HinkyPunk"
```

**Step 9: Create Windows Service (optional)**
```powershell
# Using NSSM (Non-Sucking Service Manager)
# Download from https://nssm.cc/

nssm install HinkyPunk C:\path\to\hinkypunk\bin\vpn.exe
nssm set HinkyPunk AppParameters "-c C:\ProgramData\HinkyPunk\client.conf"
nssm set HinkyPunk Start SERVICE_AUTO_START

# Start the service
nssm start HinkyPunk
```

---

### macOS Complete Setup

**Step 1: Install Xcode Command Line Tools**
```bash
xcode-select --install

# Wait for installation to complete
# Click "Install" when prompted
```

**Step 2: Build HinkyPunk**
```bash
cd hinkypunk
make

# Verify
./bin/vpn -h
```

**Step 3: Generate keys**
```bash
# Create config directory
sudo mkdir -p /etc/hinkypunk

# Generate keys
./bin/vpn genkey | sudo tee /etc/hinkypunk/client.key
sudo chmod 600 /etc/hinkypunk/client.key
cat /etc/hinkypunk/client.key | ./bin/vpn pubkey | sudo tee /etc/hinkypunk/client.pub

# Display public key to share with server
echo "Client public key:"
cat /etc/hinkypunk/client.pub
```

**Step 4: Create configuration**
```bash
sudo tee /etc/hinkypunk/client.conf << 'EOF'
[Interface]
PrivateKey = PASTE_CLIENT_PRIVATE_KEY_HERE
Address = 10.0.0.2/24

[Peer]
PublicKey = PASTE_SERVER_PUBLIC_KEY_HERE
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/hinkypunk/client.conf
```

**Step 5: Configure macOS Firewall (if enabled)**
```bash
# Allow incoming connections in System Preferences > Security & Privacy > Firewall
# Or via command line:
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/hinkypunk/bin/vpn
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/hinkypunk/bin/vpn
```

**Step 6: Start VPN**
```bash
sudo ./bin/vpn -v -c /etc/hinkypunk/client.conf

# Expected output:
# ===============================================
#   HinkyPunk VPN
# ===============================================
#
# [INFO] Loaded configuration from /etc/hinkypunk/client.conf
# [INFO] Public key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# [INFO] Added peer with endpoint YOUR_SERVER_IP:51820
# [INFO] Listening on UDP port 51820
# [INFO] Opened TUN interface: utun0
# VPN running. Press Ctrl+C to stop.
```

**Step 7: Verify connection**
```bash
# In another terminal

# Check interface
ifconfig utun0

# Expected output:
# utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
#         inet 10.0.0.2 --> 10.0.0.2 netmask 0xffffff00

# Test connectivity
ping -c 3 10.0.0.1

# Check routing table
netstat -rn | grep utun
```

**Step 8: Add routes manually (if needed)**
```bash
# Route specific subnet through VPN
sudo route add -net 10.0.0.0/24 -interface utun0

# Route all traffic (replace default gateway)
# WARNING: This will route ALL traffic through VPN
sudo route delete default
sudo route add default 10.0.0.1
```

**Step 9: Create LaunchDaemon (optional)**
```bash
sudo tee /Library/LaunchDaemons/com.hinkypunk.vpn.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hinkypunk.vpn</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hinkypunk</string>
        <string>-c</string>
        <string>/etc/hinkypunk/client.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Copy binary
sudo cp bin/vpn /usr/local/bin/hinkypunk

# Load the service
sudo launchctl load /Library/LaunchDaemons/com.hinkypunk.vpn.plist

# Check status
sudo launchctl list | grep hinkypunk
```

---

## Multi-Platform Testing Scenario

Here's a complete example connecting all three platforms:

```
                    ┌─────────────────────┐
                    │   LINUX SERVER      │
                    │   203.0.113.1       │
                    │   VPN: 10.0.0.1     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼─────────┐     │     ┌──────────▼─────────┐
    │  WINDOWS CLIENT   │     │     │   MACOS CLIENT     │
    │  VPN: 10.0.0.2    │     │     │   VPN: 10.0.0.3    │
    └───────────────────┘     │     └────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   LINUX CLIENT    │
                    │   VPN: 10.0.0.4   │
                    └───────────────────┘
```

**Server configuration (`/etc/hinkypunk/server.conf`):**
```ini
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
# Windows client
PublicKey = WINDOWS_CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32

[Peer]
# macOS client
PublicKey = MACOS_CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.3/32

[Peer]
# Linux client
PublicKey = LINUX_CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.4/32
```

**Test from each client:**
```bash
# From Windows (PowerShell)
ping 10.0.0.1    # Server
ping 10.0.0.3    # macOS client
ping 10.0.0.4    # Linux client

# From macOS
ping 10.0.0.1    # Server
ping 10.0.0.2    # Windows client
ping 10.0.0.4    # Linux client

# From Linux client
ping 10.0.0.1    # Server
ping 10.0.0.2    # Windows client
ping 10.0.0.3    # macOS client
```

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

- **Noise Protocol Framework** - Trevor Perrin
- **WireGuard** - Jason A. Donenfeld (protocol inspiration)
- **Wintun** - WireGuard project (Windows TUN driver)

---

*HinkyPunk: A magical creature that appears as a flickering light, leading travelers safely through dark paths... or leading them astray. Use responsibly.*
