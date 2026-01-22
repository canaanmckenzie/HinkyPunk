/*
 * tun.h - TUN/TAP Network Interface
 * ==================================
 *
 * This module provides access to virtual network interfaces (TUN devices).
 * A TUN device is a software network interface that appears as a real network
 * card to the operating system, but instead of sending packets over a wire,
 * it delivers them to userspace.
 *
 * HOW TUN DEVICES WORK:
 *
 *   Application           VPN Process            Network Stack
 *   ───────────           ───────────            ─────────────
 *
 *   1. App sends packet to 10.0.0.5
 *          │
 *          ▼
 *   2. Kernel routes packet to TUN interface (10.0.0.0/24)
 *          │
 *          ▼
 *   3. Kernel writes packet to TUN device file
 *          │
 *          ├──────────────────►  VPN reads packet from TUN
 *          │                           │
 *          │                     4. VPN encrypts packet
 *          │                           │
 *          │                     5. VPN sends encrypted UDP to peer
 *          │                           │
 *          │                     ◄─────┘
 *
 * The reverse happens for incoming packets:
 *   - VPN receives encrypted UDP
 *   - VPN decrypts to get original IP packet
 *   - VPN writes to TUN device
 *   - Kernel delivers packet to destination application
 *
 * TUN vs TAP:
 *
 * - TUN: Layer 3 (IP packets). Simpler, what WireGuard uses.
 * - TAP: Layer 2 (Ethernet frames). Needed for bridging, more complex.
 *
 * We use TUN because we only need IP-level tunneling.
 *
 * PLATFORM IMPLEMENTATIONS:
 *
 * Linux:
 *   - Open /dev/net/tun
 *   - Use ioctl(TUNSETIFF) to create interface
 *   - Read/write IP packets directly
 *
 * macOS:
 *   - Open /dev/utunN
 *   - 4-byte header prefixed to each packet (address family)
 *
 * Windows:
 *   - Use Wintun driver (modern) or TAP-Windows (legacy)
 *   - Wintun: Ring buffers for efficient I/O
 *   - TAP-Windows: DeviceIoControl for read/write
 *
 * For this educational implementation, we provide the interface and
 * stub implementations. A full implementation would require platform-specific
 * drivers.
 */

#ifndef VPN_TUN_H
#define VPN_TUN_H

#include "../types.h"

/*
 * Maximum TUN device name length
 */
#define TUN_NAME_MAX 64

/*
 * TUN device handle
 */
typedef struct {
#ifdef _WIN32
    void *adapter;              /* Wintun adapter handle */
    void *session;              /* Wintun session handle */
    void *read_event;           /* Wintun read wait event */
    void *wintun_dll;           /* Wintun DLL module handle */
#else
    int fd;                     /* Unix file descriptor */
#endif
    char name[TUN_NAME_MAX];    /* Interface name (e.g., "tun0") */
    uint32_t mtu;               /* Maximum transmission unit */
    bool is_open;
} tun_t;

/*
 * ===========================================================================
 * TUN Operations
 * ===========================================================================
 */

/*
 * tun_open - Create and open a TUN interface
 *
 * Creates a new TUN interface with the specified name (or auto-generated
 * if name is NULL).
 *
 * @param tun       TUN handle to initialize
 * @param name      Interface name (NULL for auto)
 * @return          VPN_OK on success
 *
 * NOTE: This typically requires root/administrator privileges.
 *
 * EXAMPLE:
 *   tun_t tun;
 *   tun_open(&tun, "vpn0");
 */
vpn_error_t tun_open(tun_t *tun, const char *name);

/*
 * tun_close - Close TUN interface
 *
 * @param tun       TUN handle to close
 */
void tun_close(tun_t *tun);

/*
 * tun_read - Read a packet from the TUN interface
 *
 * Blocks until a packet is available. Returns the IP packet.
 *
 * @param tun       TUN handle
 * @param buf       Buffer for packet data
 * @param buf_len   Buffer size (should be >= MTU)
 * @return          Packet length, or negative error
 *
 * The returned data is a raw IP packet (IPv4 or IPv6).
 */
int tun_read(tun_t *tun, uint8_t *buf, size_t buf_len);

/*
 * tun_read_timeout - Read with timeout
 *
 * @param tun       TUN handle
 * @param buf       Buffer for packet data
 * @param buf_len   Buffer size
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking, -1 = block)
 * @return          Packet length, 0 on timeout, or negative error
 */
int tun_read_timeout(tun_t *tun, uint8_t *buf, size_t buf_len, int timeout_ms);

/*
 * tun_write - Write a packet to the TUN interface
 *
 * The packet will be injected into the network stack as if it arrived
 * from the network.
 *
 * @param tun       TUN handle
 * @param data      IP packet data
 * @param len       Packet length
 * @return          Bytes written, or negative error
 */
int tun_write(tun_t *tun, const uint8_t *data, size_t len);

/*
 * ===========================================================================
 * Configuration
 * ===========================================================================
 */

/*
 * tun_set_ip - Configure IP address for the interface
 *
 * @param tun       TUN handle
 * @param addr      IP address
 * @param prefix    Prefix length (e.g., 24 for /24)
 * @param is_ipv6   True for IPv6
 * @return          VPN_OK on success
 *
 * NOTE: This may require additional tools (ip, ifconfig, netsh).
 */
vpn_error_t tun_set_ip(tun_t *tun, const uint8_t *addr, uint8_t prefix, bool is_ipv6);

/*
 * tun_set_mtu - Set the MTU
 *
 * @param tun       TUN handle
 * @param mtu       MTU value (typically 1420 for VPN)
 * @return          VPN_OK on success
 */
vpn_error_t tun_set_mtu(tun_t *tun, uint32_t mtu);

/*
 * tun_up - Bring the interface up
 *
 * @param tun       TUN handle
 * @return          VPN_OK on success
 */
vpn_error_t tun_up(tun_t *tun);

/*
 * tun_down - Bring the interface down
 *
 * @param tun       TUN handle
 * @return          VPN_OK on success
 */
vpn_error_t tun_down(tun_t *tun);

/*
 * ===========================================================================
 * Utility Functions
 * ===========================================================================
 */

/*
 * tun_get_name - Get interface name
 *
 * @param tun       TUN handle
 * @return          Interface name string
 */
const char *tun_get_name(const tun_t *tun);

/*
 * tun_get_mtu - Get current MTU
 *
 * @param tun       TUN handle
 * @return          MTU value
 */
uint32_t tun_get_mtu(const tun_t *tun);

/*
 * Extract IP version from packet
 *
 * @param packet    IP packet
 * @param len       Packet length
 * @return          4 for IPv4, 6 for IPv6, 0 if invalid
 */
int tun_packet_ip_version(const uint8_t *packet, size_t len);

/*
 * Extract destination IP from packet
 *
 * @param packet    IP packet
 * @param len       Packet length
 * @param dst       Output: destination IP (4 or 16 bytes)
 * @param is_ipv6   Output: true if IPv6
 * @return          VPN_OK on success
 */
vpn_error_t tun_packet_get_dst(const uint8_t *packet, size_t len,
                               uint8_t *dst, bool *is_ipv6);

/*
 * Extract source IP from packet
 */
vpn_error_t tun_packet_get_src(const uint8_t *packet, size_t len,
                               uint8_t *src, bool *is_ipv6);

#endif /* VPN_TUN_H */
