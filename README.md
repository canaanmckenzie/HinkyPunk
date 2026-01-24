# HinkyPunk VPN

A secure, high-performance VPN built from scratch in pure C.

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

## Linux Quickstart (5 Minutes)

```bash
# 1. Clone and build
git clone https://github.com/canaanmckenzie/HinkyPunk.git
cd HinkyPunk
./quickstart.sh build

# 2. Run the interactive setup wizard
./quickstart.sh setup
# Follow prompts: choose server/client, set IPs, exchange keys

# 3. Start the VPN
sudo ./bin/vpn -c configs/server.conf   # On server
sudo ./bin/vpn -c configs/client.conf   # On client

# 4. Test connectivity
ping 10.0.0.1   # From client to server
```

**Or do everything in one command:**
```bash
./quickstart.sh all   # Clean, build, and run setup wizard
```

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Cryptographic Foundations](#cryptographic-foundations)
- [The Noise Protocol](#the-noise-protocol)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [C Implementation Details](#c-implementation-details)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Modern Cryptography**: ChaCha20-Poly1305 AEAD, Curve25519 ECDH, BLAKE2s
- **Noise Protocol**: IK handshake pattern with perfect forward secrecy
- **Cross-Platform**: Linux, Windows (Wintun), macOS (utun)
- **Zero Dependencies**: Built from scratch, no OpenSSL or libsodium required
- **WireGuard-Compatible Config**: Use familiar configuration format
- **Minimal Attack Surface**: ~5000 lines of heavily documented C code

---

## How It Works

### The Big Picture

A VPN creates an encrypted tunnel between two machines. HinkyPunk works like this:

```
┌─────────────────┐                           ┌─────────────────┐
│   Your App      │                           │   Remote App    │
│  (browser, ssh) │                           │  (web server)   │
└────────┬────────┘                           └────────┬────────┘
         │ IP packet                                   │
         ▼                                             ▼
┌─────────────────┐                           ┌─────────────────┐
│  TUN Interface  │                           │  TUN Interface  │
│   (vpn0)        │                           │   (vpn0)        │
└────────┬────────┘                           └────────┬────────┘
         │ Raw IP packet                               │
         ▼                                             ▼
┌─────────────────┐                           ┌─────────────────┐
│   HinkyPunk     │                           │   HinkyPunk     │
│   VPN Process   │                           │   VPN Process   │
│                 │                           │                 │
│  1. Encrypt     │                           │  1. Decrypt     │
│  2. Authenticate│                           │  2. Verify MAC  │
│  3. Send UDP    │                           │  3. Inject TUN  │
└────────┬────────┘                           └────────┬────────┘
         │ Encrypted UDP                               │
         ▼                                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Internet (Untrusted)                      │
│              Attackers see only encrypted gibberish              │
└─────────────────────────────────────────────────────────────────┘
```

### The TUN Device

A **TUN device** is a virtual network interface. Unlike a physical NIC that connects to a wire, a TUN device connects to a userspace program.

When the kernel routes a packet to `vpn0`, instead of sending it out a wire:
1. The packet appears in our program via `read(tun_fd)`
2. We encrypt it and send via UDP
3. The remote peer decrypts and writes to their TUN via `write(tun_fd)`
4. The kernel routes it to the destination application

This is why VPNs need root: creating network interfaces requires elevated privileges.

### Why UDP?

HinkyPunk uses UDP transport, not TCP, for two reasons:

1. **Performance**: TCP has built-in retransmission and congestion control. If we tunnel TCP inside TCP, when packets are lost, BOTH layers retransmit, causing exponential backoff ("TCP meltdown").

2. **Simplicity**: UDP is connectionless. Peers can come and go without connection setup overhead.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HinkyPunk VPN                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
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
HinkyPunk/
├── src/
│   ├── main.c              # Entry point, event loop
│   ├── config.c            # WireGuard config parser
│   ├── types.h             # Common types and constants
│   │
│   ├── crypto/             # Cryptographic primitives (all from scratch)
│   │   ├── chacha20.c      # ChaCha20 stream cipher (RFC 8439)
│   │   ├── poly1305.c      # Poly1305 MAC (RFC 8439)
│   │   ├── aead.c          # ChaCha20-Poly1305 AEAD
│   │   ├── curve25519.c    # Curve25519 ECDH (RFC 7748)
│   │   └── blake2s.c       # BLAKE2s hash + HMAC + HKDF (RFC 7693)
│   │
│   ├── protocol/           # VPN protocol layer
│   │   ├── noise.c         # Noise IK handshake
│   │   ├── packet.c        # Wire format encoding
│   │   ├── peer.c          # Peer and session management
│   │   ├── replay.c        # Replay attack protection
│   │   └── timers.c        # Rekey and keepalive timers
│   │
│   ├── net/                # Network abstraction
│   │   ├── udp.c           # Cross-platform UDP sockets
│   │   └── tun.c           # TUN device (Linux/macOS/Windows)
│   │
│   └── util/               # Utilities
│       ├── memory.c        # Secure memory operations
│       ├── random.c        # CSPRNG wrapper
│       └── log.c           # Logging system
│
├── quickstart.sh           # Build and setup script
├── Makefile                # Build system
└── README.md               # This file
```

---

## Cryptographic Foundations

HinkyPunk implements all cryptography from scratch. Here's what each piece does and why:

### ChaCha20 - Stream Cipher

**Purpose**: Encrypt data so only the key holder can read it.

**How it works**: ChaCha20 generates a stream of pseudorandom bytes from a key and nonce. XORing this keystream with plaintext produces ciphertext:

```
Ciphertext = Plaintext XOR KeyStream(Key, Nonce)
Plaintext  = Ciphertext XOR KeyStream(Key, Nonce)  # Same operation!
```

**The State Matrix**: ChaCha20 maintains a 4x4 matrix of 32-bit words:

```
┌──────────┬──────────┬──────────┬──────────┐
│ "expa"   │ "nd 3"   │ "2-by"   │ "te k"   │  ← Constant (ASCII)
├──────────┼──────────┼──────────┼──────────┤
│  Key[0]  │  Key[1]  │  Key[2]  │  Key[3]  │  ← 256-bit key
├──────────┼──────────┼──────────┼──────────┤
│  Key[4]  │  Key[5]  │  Key[6]  │  Key[7]  │
├──────────┼──────────┼──────────┼──────────┤
│ Counter  │ Nonce[0] │ Nonce[1] │ Nonce[2] │  ← 96-bit nonce
└──────────┴──────────┴──────────┴──────────┘
```

**The Quarter Round**: The core mixing function uses only ADD, XOR, and ROTATE:

```c
a += b; d ^= a; d = ROTL(d, 16);
c += d; b ^= c; b = ROTL(b, 12);
a += b; d ^= a; d = ROTL(d, 8);
c += d; b ^= c; b = ROTL(b, 7);
```

These operations are:
- **Fast**: No table lookups (cache-timing safe)
- **Reversible individually**: But combined, one-way
- **Non-linear**: XOR and ADD interact chaotically

After 20 rounds (80 quarter rounds), the state is thoroughly mixed. The original state is added back (feedforward), making the function non-invertible.

**Security**: Nonce must NEVER be reused with the same key. If you encrypt two messages with the same key/nonce: `C1 XOR C2 = P1 XOR P2` - the keystream cancels out!

### Poly1305 - Message Authentication Code

**Purpose**: Prove a message hasn't been tampered with.

**How it works**: Poly1305 treats the message as coefficients of a polynomial, evaluates it at a secret point `r`, and adds a secret pad `s`:

```
Tag = ((m[1]·r^n + m[2]·r^(n-1) + ... + m[n]·r) mod (2^130 - 5)) + s
```

**Why 2^130 - 5?** This prime has a special property: `2^130 ≡ 5 (mod p)`. When numbers overflow 130 bits, we can efficiently reduce by multiplying the overflow by 5.

**One-time key requirement**: The key (r, s) must be used ONLY ONCE. If you authenticate two messages with the same key, an attacker can solve for `r` and forge tags for any message.

In ChaCha20-Poly1305, the Poly1305 key is derived from ChaCha20 block 0, so each unique nonce produces a unique Poly1305 key.

### Curve25519 - Key Exchange

**Purpose**: Two parties create a shared secret without ever transmitting it.

**The math**: Elliptic curve Diffie-Hellman on the curve y² = x³ + 486662x² + x (mod 2^255 - 19):

```
Alice                              Bob
─────                              ───
a = random()                       b = random()
A = a × G (scalar mult)            B = b × G

      ──── Exchange A, B ────

shared = a × B                     shared = b × A
       = a × (b × G)                     = b × (a × G)
       = (a × b) × G                     = (a × b) × G
                    ↑ Same value! ↑
```

**Montgomery Ladder**: Our implementation uses the Montgomery ladder algorithm, which is naturally constant-time (no secret-dependent branches).

**Clamping**: Before use, private keys are "clamped":
```c
key[0] &= 248;   // Clear low 3 bits (make divisible by 8)
key[31] &= 127;  // Clear high bit
key[31] |= 64;   // Set second-highest bit
```
This prevents small-subgroup attacks and ensures the scalar is in the valid range.

### BLAKE2s - Hash Function

**Purpose**: Create a fixed-size fingerprint of arbitrary data.

**Properties**:
- **Deterministic**: Same input always produces same output
- **One-way**: Given hash, can't find input
- **Collision-resistant**: Hard to find two inputs with same hash
- **Avalanche**: Tiny change in input → drastic change in output

**Why not SHA-256?** BLAKE2s is faster, simpler, and based on ChaCha (same ARX structure). It includes built-in support for:
- Keyed hashing (MAC without HMAC construction)
- Personalization (domain separation)
- Tree hashing

**HKDF**: We use BLAKE2s in HKDF (HMAC-based Key Derivation Function) to derive multiple keys from a shared secret:

```
Extract: PRK = HMAC(salt, input_key_material)
Expand:  Key1 = HMAC(PRK, 0x01)
         Key2 = HMAC(PRK, Key1 || 0x02)
         Key3 = HMAC(PRK, Key2 || 0x03)
```

---

## The Noise Protocol

HinkyPunk uses the **Noise IK** handshake pattern. "IK" means the Initiator Knows the responder's static public key in advance (from configuration).

### Handshake Messages

```
Initiator (Client)                    Responder (Server)
──────────────────                    ──────────────────

Generate ephemeral keypair (e_i)
                │
                ▼
┌─────────────────────────────────┐
│ Message 1 (148 bytes)           │
│ ─────────────────────────────── │
│ e_i_pub          (32 bytes)     │  Ephemeral public key
│ Enc(i_static)    (48 bytes)     │  Encrypted static pubkey + tag
│ Enc(timestamp)   (28 bytes)     │  Encrypted timestamp + tag
│ MAC1             (16 bytes)     │  DoS protection
│ MAC2             (16 bytes)     │  Cookie (zeros if none)
└─────────────────────────────────┘
                │
                ├─────────────────────────────────────────▶
                │
                │                   Verify MAC1
                │                   Decrypt i_static using DH(r_static, e_i)
                │                   Verify timestamp (replay protection)
                │                   Generate ephemeral keypair (e_r)
                │
                │              ┌─────────────────────────────────┐
                │              │ Message 2 (92 bytes)            │
                │              │ ─────────────────────────────── │
                │              │ e_r_pub        (32 bytes)       │
                │              │ Enc(empty)     (16 bytes)       │
                │              │ MAC1           (16 bytes)       │
                │              │ MAC2           (16 bytes)       │
                │              └─────────────────────────────────┘
                │                              │
                ◀──────────────────────────────┘
                │
Decrypt using DH(e_i, e_r) + DH(e_i, r_static)
Derive transport keys from shared secrets
                │
                ▼
        SESSION ESTABLISHED
```

### Key Derivation

During the handshake, four Diffie-Hellman operations occur:

1. `DH(e_initiator, s_responder)` - Initiator's ephemeral × Responder's static
2. `DH(s_initiator, s_responder)` - Both static keys
3. `DH(e_initiator, e_responder)` - Both ephemeral keys
4. `DH(s_initiator, e_responder)` - Initiator's static × Responder's ephemeral

Each DH result is mixed into the "chaining key" using HKDF. The final chaining key is split into two transport keys: one for each direction.

**Perfect Forward Secrecy**: If static keys are later compromised, past sessions remain secure because ephemeral keys (which contributed to session keys) are erased.

### Transport Data

After handshake, data packets are simple:

```
┌──────────────────────────────────────────────┐
│ Type (1 byte)          = 0x04                │
│ Reserved (3 bytes)     = 0x00 0x00 0x00      │
│ Receiver Index (4 bytes, LE)                 │
│ Counter (8 bytes, LE)                        │
│ Encrypted Payload + Tag (variable + 16)     │
└──────────────────────────────────────────────┘
```

The counter serves as the AEAD nonce. It must be strictly increasing (enforced by replay protection).

---

## Installation

### Linux (Ubuntu/Debian)

```bash
# Install build tools
sudo apt update
sudo apt install -y build-essential git

# Clone and build
git clone https://github.com/canaanmckenzie/HinkyPunk.git
cd HinkyPunk
./quickstart.sh build

# Or manually:
make
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install gcc make git
git clone https://github.com/canaanmckenzie/HinkyPunk.git
cd HinkyPunk
make
```

### Linux (Arch)

```bash
sudo pacman -S base-devel git
git clone https://github.com/canaanmckenzie/HinkyPunk.git
cd HinkyPunk
make
```

### Verify Build

```bash
./bin/vpn -h                    # Show help
./bin/vpn genkey                # Generate a test key
./quickstart.sh build           # Builds and runs verification
```

---

## Configuration

HinkyPunk uses WireGuard-compatible configuration files.

### Generate Keys

```bash
# Generate private key (keep secret!)
./bin/vpn genkey > private.key

# Derive public key (share with peers)
cat private.key | ./bin/vpn pubkey > public.key
```

### Server Configuration

```ini
[Interface]
# Server's private key (NEVER share this!)
PrivateKey = kG5sTwXjKmZThntP4V8xJDFdqvL9RRhB7NqUoUCwJ1c=

# VPN IP address for this server
Address = 10.0.0.1/24

# UDP port to listen on
ListenPort = 51820

[Peer]
# Client's PUBLIC key (safe to share)
PublicKey = xY9zAbCdEfGhIjKlMnOpQrStUvWxYz012345678901=

# Only allow this IP from this peer (anti-spoofing)
AllowedIPs = 10.0.0.2/32
```

### Client Configuration

```ini
[Interface]
# Client's private key
PrivateKey = mN3oPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQr=

# VPN IP address for this client
Address = 10.0.0.2/24

[Peer]
# Server's PUBLIC key
PublicKey = aB3dEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=

# Server's public endpoint
Endpoint = 203.0.113.1:51820

# Route these IPs through the VPN
AllowedIPs = 10.0.0.0/24

# Keep NAT mappings alive
PersistentKeepalive = 25
```

### Interactive Setup

The easiest way to configure is the setup wizard:

```bash
./quickstart.sh setup
```

This interactively:
1. Asks if you're server or client
2. Generates or loads keys
3. Prompts for network settings
4. Asks for peer's public key
5. Creates the configuration file

---

## Usage Guide

### Starting the VPN

```bash
# Server
sudo ./bin/vpn -c configs/server.conf

# Client
sudo ./bin/vpn -c configs/client.conf

# With debug logging
sudo ./bin/vpn -v -c configs/client.conf
```

### Testing Connectivity

```bash
# From client, ping server's VPN IP
ping 10.0.0.1

# From server, ping client's VPN IP
ping 10.0.0.2

# Check the TUN interface exists
ip addr show vpn0
```

### Firewall Configuration

```bash
# Ubuntu (UFW)
sudo ufw allow 51820/udp

# Fedora (firewalld)
sudo firewall-cmd --add-port=51820/udp --permanent
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

---

## C Implementation Details

This section explains key C programming patterns used throughout the codebase.

### Constant-Time Comparisons

**Problem**: Standard `memcmp()` returns early on the first byte mismatch. An attacker can measure timing to learn which byte differed.

**Solution**: Always examine ALL bytes:

```c
// src/util/memory.c
bool vpn_memeq(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *p1 = a;
    const volatile uint8_t *p2 = b;
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= p1[i] ^ p2[i];  // Accumulate differences
    }

    return diff == 0;  // Only compare at the end
}
```

The `volatile` keyword prevents the compiler from optimizing away the loop.

### Secure Memory Zeroing

**Problem**: Compilers may remove "dead" stores. If you zero a key and never read it again, the compiler might skip the zeroing.

**Solution**: Use `volatile` to force the write:

```c
void vpn_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
```

### Platform Abstraction

The codebase abstracts platform differences with preprocessor conditionals:

```c
// src/net/udp.c
#ifdef _WIN32
    typedef SOCKET udp_socket_t;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
#else
    typedef int udp_socket_t;
    #define INVALID_SOCKET_VALUE (-1)
#endif
```

### Error Handling Pattern

Functions return error codes; success is always 0:

```c
typedef enum {
    VPN_OK          =  0,
    VPN_ERR_GENERIC = -1,
    VPN_ERR_NOMEM   = -2,
    VPN_ERR_CRYPTO  = -4,
    VPN_ERR_AUTH    = -5,
} vpn_error_t;

// Usage:
vpn_error_t err = some_function();
if (err != VPN_OK) {
    LOG_ERROR("Operation failed: %d", err);
    return err;  // Propagate error
}
```

### Fixed-Width Integer Types

Cryptographic code requires exact bit widths. We use `<stdint.h>` types:

```c
uint8_t   // Exactly 8 bits (bytes)
uint32_t  // Exactly 32 bits (ChaCha20 words)
uint64_t  // Exactly 64 bits (counters, Poly1305 accumulators)
```

### Little-Endian Encoding

Network protocols and WireGuard use little-endian. We explicitly encode:

```c
static inline void write_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
```

This works correctly regardless of the host's native byte order.

---

## Security

### Cryptographic Properties

| Property | How HinkyPunk Achieves It |
|----------|---------------------------|
| **Confidentiality** | ChaCha20 encryption with 256-bit keys |
| **Integrity** | Poly1305 MAC on every packet |
| **Authenticity** | Noise IK handshake verifies peer identity |
| **Forward Secrecy** | Ephemeral keys in every handshake |
| **Replay Protection** | 2048-packet sliding window + counters |

### What We Protect Against

- Passive eavesdropping
- Active man-in-the-middle
- Replay attacks
- Packet injection
- Source IP spoofing (via AllowedIPs)

### What We Don't Protect Against

- Compromised endpoints
- Traffic analysis (timing, packet sizes)
- Denial of service
- Key compromise (secure your private keys!)

---

## Troubleshooting

### "Failed to open TUN interface"

This requires root privileges:

```bash
sudo ./bin/vpn -c config.conf
```

On Linux, ensure the TUN module is loaded:

```bash
sudo modprobe tun
ls -la /dev/net/tun
```

### "Connection timeout" / No handshake

1. Check firewall allows UDP 51820:
   ```bash
   sudo ufw allow 51820/udp
   ```

2. Verify server is listening:
   ```bash
   sudo ss -ulnp | grep 51820
   ```

3. Check public keys match (server's config has client's pubkey and vice versa)

### "Handshake failed"

Public keys are mismatched. Regenerate and exchange:

```bash
# On client
./bin/vpn genkey > client.key
cat client.key | ./bin/vpn pubkey
# Copy this to server's [Peer] PublicKey

# On server
./bin/vpn genkey > server.key
cat server.key | ./bin/vpn pubkey
# Copy this to client's [Peer] PublicKey
```

### Debug Mode

```bash
sudo ./bin/vpn -v -c config.conf
```

Shows handshake progress, encryption/decryption, and errors.

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

- **Noise Protocol Framework** - Trevor Perrin
- **WireGuard** - Jason A. Donenfeld (protocol inspiration)
- **curve25519-donna** - Adam Langley (Curve25519 implementation)
- **RFC Authors** - ChaCha20 (RFC 8439), Curve25519 (RFC 7748), BLAKE2 (RFC 7693)

---

*HinkyPunk: A magical creature that appears as a flickering light, leading travelers safely through dark paths... or leading them astray. Use responsibly.*
