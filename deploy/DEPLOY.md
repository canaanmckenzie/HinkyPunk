# HinkyPunk VPN Deployment Guide

## Quick Start (Kali + Ubuntu)

This guide covers deploying HinkyPunk between two Linux machines.

### Prerequisites

Both machines need:
- Linux kernel 3.x+ (TUN/TAP support)
- Root access (for creating TUN interfaces)
- Network connectivity between machines

### Step 1: Build on Both Machines

```bash
# On both Kali and Ubuntu
git clone <repository-url> HinkyPunk
cd HinkyPunk
make
```

Verify the build:
```bash
./bin/vpn genkey   # Should output a base64 key
```

### Step 2: Generate Keys

**On the Server (e.g., Ubuntu):**
```bash
cd deploy
./setup.sh server 10.0.0.1 <SERVER_PUBLIC_IP> 51820
```

This creates:
- `configs/server.key` - Server private key (keep secret)
- `configs/server.pub` - Server public key (share with clients)
- `configs/server.conf` - Server configuration

**On the Client (e.g., Kali):**
```bash
cd deploy
# Enter the server's public key when prompted
./setup.sh client 10.0.0.2 <SERVER_PUBLIC_IP> 51820
```

### Step 3: Exchange Public Keys

Copy the **client's public key** and add it to the server config:

```bash
# On server, edit configs/server.conf and add:
[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

### Step 4: Start the VPN

**On the Server:**
```bash
sudo ./bin/vpn -c deploy/configs/server.conf
```

**On the Client:**
```bash
sudo ./bin/vpn -c deploy/configs/client.conf
```

### Step 5: Verify Connection

```bash
# From client
ping 10.0.0.1

# From server
ping 10.0.0.2
```

---

## Manual Key Generation

If you prefer manual setup:

```bash
# Generate private key
./bin/vpn genkey > private.key

# Derive public key
cat private.key | ./bin/vpn pubkey > public.key
```

## Configuration File Format

HinkyPunk uses WireGuard-compatible configuration:

```ini
[Interface]
PrivateKey = <base64-encoded-private-key>
ListenPort = 51820
Address = 10.0.0.1/24

[Peer]
PublicKey = <base64-encoded-peer-public-key>
Endpoint = 192.168.1.100:51820    # Optional for server
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25          # Optional
```

## Firewall Configuration

### UFW (Ubuntu)
```bash
sudo ufw allow 51820/udp
```

### iptables
```bash
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

## Troubleshooting

### "Failed to open TUN interface"
- Ensure you're running as root: `sudo ./bin/vpn ...`
- Check if TUN module is loaded: `lsmod | grep tun`
- Load TUN module: `sudo modprobe tun`

### Connection Issues
- Verify UDP port 51820 is open on server
- Check firewall rules on both sides
- Ensure public keys match correctly

### Debug Mode
Run with verbose logging:
```bash
sudo ./bin/vpn -c config.conf -v
```

## Security Notes

1. **Key Protection**: Private keys should have permissions 600
2. **Firewall**: Only expose the UDP port, not the TUN interface
3. **No Key Reuse**: Generate unique keypairs for each deployment
