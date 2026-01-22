/*
 * udp.h - UDP Transport Layer
 * ============================
 *
 * This module provides a simple UDP socket abstraction for sending and
 * receiving VPN packets. All VPN traffic goes over UDP because:
 *
 * 1. PERFORMANCE: No TCP overhead (retransmissions, congestion control).
 *    The tunnel protocols inside (like TCP) handle their own reliability.
 *
 * 2. SIMPLICITY: UDP is connectionless - perfect for ephemeral peers.
 *
 * 3. NAT TRAVERSAL: UDP is easier to traverse through NATs than raw IP.
 *
 * 4. FIREWALL FRIENDLY: UDP on common ports (like 51820) is usually allowed.
 *
 * WHY NOT TCP?
 *
 * Running TCP-over-TCP causes severe performance problems ("TCP meltdown").
 * When the inner TCP detects loss, it backs off. But the outer TCP also
 * backs off. The double backoff causes terrible throughput.
 *
 * UDP avoids this by being a "dumb pipe" - the inner protocols handle
 * reliability independently.
 *
 * SOCKET OPERATION:
 *
 * 1. Create socket and bind to local port
 * 2. Loop:
 *    - recvfrom() to receive packets (with sender address)
 *    - sendto() to send packets (to specific destination)
 * 3. Close socket on shutdown
 *
 * PLATFORM NOTES:
 *
 * - Windows: Uses Winsock2 (ws2_32.lib)
 * - Unix/Linux: Uses POSIX sockets
 *
 * The API is mostly the same, but there are small differences in error
 * handling and initialization that we abstract away.
 */

#ifndef VPN_UDP_H
#define VPN_UDP_H

#include "../types.h"

/*
 * Platform-specific socket type
 */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET udp_socket_t;
    #define UDP_INVALID_SOCKET INVALID_SOCKET
#else
    typedef int udp_socket_t;
    #define UDP_INVALID_SOCKET (-1)
#endif

/*
 * Socket address (unified IPv4/IPv6)
 */
typedef struct {
    uint8_t addr[16];       /* IPv4 (4 bytes) or IPv6 (16 bytes) */
    uint16_t port;          /* Port in host byte order */
    bool is_ipv6;
} udp_addr_t;

/*
 * UDP socket wrapper
 */
typedef struct {
    udp_socket_t sock4;     /* IPv4 socket */
    udp_socket_t sock6;     /* IPv6 socket */
    uint16_t port;          /* Bound port */
    bool has_ipv4;
    bool has_ipv6;
} udp_t;

/*
 * ===========================================================================
 * Initialization
 * ===========================================================================
 */

/*
 * udp_init - Initialize UDP subsystem (platform-specific)
 *
 * On Windows, this calls WSAStartup().
 * On Unix, this is a no-op.
 *
 * @return  VPN_OK on success
 */
vpn_error_t udp_init(void);

/*
 * udp_cleanup - Clean up UDP subsystem
 *
 * On Windows, this calls WSACleanup().
 */
void udp_cleanup(void);

/*
 * ===========================================================================
 * Socket Operations
 * ===========================================================================
 */

/*
 * udp_open - Create and bind UDP socket(s)
 *
 * Creates IPv4 and/or IPv6 sockets and binds them to the specified port.
 * If port is 0, the OS chooses an available port.
 *
 * @param udp       Socket structure to initialize
 * @param port      Port to bind (0 for any)
 * @param bind_addr Specific address to bind (NULL for all interfaces)
 * @return          VPN_OK on success
 *
 * EXAMPLE:
 *   udp_t udp;
 *   udp_open(&udp, 51820, NULL);  // Bind to port 51820 on all interfaces
 */
vpn_error_t udp_open(udp_t *udp, uint16_t port, const udp_addr_t *bind_addr);

/*
 * udp_close - Close UDP socket(s)
 *
 * @param udp   Socket to close
 */
void udp_close(udp_t *udp);

/*
 * udp_send - Send a packet to a specific address
 *
 * @param udp       Socket to send from
 * @param data      Data to send
 * @param len       Data length
 * @param dest      Destination address
 * @return          Bytes sent, or negative error
 */
int udp_send(udp_t *udp, const uint8_t *data, size_t len, const udp_addr_t *dest);

/*
 * udp_recv - Receive a packet (blocking)
 *
 * Waits for a packet and returns the sender's address.
 *
 * @param udp       Socket to receive from
 * @param buf       Buffer for received data
 * @param buf_len   Buffer size
 * @param from      Output: sender's address
 * @return          Bytes received, or negative error
 */
int udp_recv(udp_t *udp, uint8_t *buf, size_t buf_len, udp_addr_t *from);

/*
 * udp_recv_timeout - Receive a packet with timeout
 *
 * @param udp       Socket to receive from
 * @param buf       Buffer for received data
 * @param buf_len   Buffer size
 * @param from      Output: sender's address
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return          Bytes received, 0 on timeout, or negative error
 */
int udp_recv_timeout(udp_t *udp, uint8_t *buf, size_t buf_len,
                     udp_addr_t *from, int timeout_ms);

/*
 * ===========================================================================
 * Address Utilities
 * ===========================================================================
 */

/*
 * udp_addr_from_string - Parse address string
 *
 * Parses "1.2.3.4:5678" or "[::1]:5678" format.
 *
 * @param addr      Output address
 * @param str       String to parse
 * @return          VPN_OK on success
 */
vpn_error_t udp_addr_from_string(udp_addr_t *addr, const char *str);

/*
 * udp_addr_to_string - Format address as string
 *
 * @param addr      Address to format
 * @param buf       Output buffer
 * @param buf_len   Buffer size
 * @return          Pointer to buf, or NULL on error
 */
char *udp_addr_to_string(const udp_addr_t *addr, char *buf, size_t buf_len);

/*
 * udp_addr_equal - Compare two addresses
 *
 * @param a, b      Addresses to compare
 * @return          True if equal
 */
bool udp_addr_equal(const udp_addr_t *a, const udp_addr_t *b);

/*
 * udp_addr_copy - Copy an address
 */
void udp_addr_copy(udp_addr_t *dst, const udp_addr_t *src);

#endif /* VPN_UDP_H */
