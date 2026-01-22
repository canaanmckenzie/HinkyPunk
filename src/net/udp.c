/*
 * udp.c - UDP Transport Layer Implementation
 * ===========================================
 *
 * This implements UDP socket operations for both Windows and Unix platforms.
 *
 * PLATFORM DIFFERENCES:
 *
 * Windows:
 *   - Must call WSAStartup() before using sockets
 *   - Socket type is SOCKET (unsigned), INVALID_SOCKET for errors
 *   - Error codes via WSAGetLastError()
 *   - Uses closesocket() instead of close()
 *
 * Unix/Linux/macOS:
 *   - Sockets are file descriptors (int), -1 for errors
 *   - Error codes via errno
 *   - Uses close()
 *
 * We use #ifdef _WIN32 to handle these differences.
 */

#include "udp.h"
#include "../util/memory.h"
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
#endif

/*
 * ===========================================================================
 * Platform Compatibility
 * ===========================================================================
 */

#ifdef _WIN32

/* Windows-specific socket close */
static void close_socket(udp_socket_t sock)
{
    closesocket(sock);
}

/* Windows-specific last error */
static int get_last_error(void)
{
    return WSAGetLastError();
}

#else

/* Unix socket close */
static void close_socket(udp_socket_t sock)
{
    close(sock);
}

/* Unix last error */
static int get_last_error(void)
{
    return errno;
}

#endif

/*
 * ===========================================================================
 * Initialization
 * ===========================================================================
 */

vpn_error_t udp_init(void)
{
#ifdef _WIN32
    WSADATA wsa_data;
    int result;

    /*
     * WSAStartup initializes Winsock.
     * The version 2.2 (0x0202) is standard for modern Windows.
     */
    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        return VPN_ERR_NETWORK;
    }
#endif

    return VPN_OK;
}

void udp_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/*
 * ===========================================================================
 * Socket Operations
 * ===========================================================================
 */

/*
 * Create and configure a socket for the specified address family.
 */
static udp_socket_t create_socket(int af, uint16_t port, const udp_addr_t *bind_addr)
{
    udp_socket_t sock;
    int opt = 1;

    /* Create UDP socket */
    sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == UDP_INVALID_SOCKET) {
        return UDP_INVALID_SOCKET;
    }

    /* Allow address reuse (helps with quick restart) */
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    /* Bind to address */
    if (af == AF_INET) {
        struct sockaddr_in addr;
        vpn_memzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (bind_addr && !bind_addr->is_ipv6) {
            vpn_memcpy(&addr.sin_addr, bind_addr->addr, 4);
        } else {
            addr.sin_addr.s_addr = INADDR_ANY;
        }

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close_socket(sock);
            return UDP_INVALID_SOCKET;
        }
    } else if (af == AF_INET6) {
        struct sockaddr_in6 addr;
        vpn_memzero(&addr, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);

        if (bind_addr && bind_addr->is_ipv6) {
            vpn_memcpy(&addr.sin6_addr, bind_addr->addr, 16);
        }
        /* else in6addr_any (all zeros) */

        /* Disable IPv4-mapped addresses so we have separate IPv4 and IPv6 sockets */
        opt = 1;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&opt, sizeof(opt));

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            close_socket(sock);
            return UDP_INVALID_SOCKET;
        }
    }

    return sock;
}

vpn_error_t udp_open(udp_t *udp, uint16_t port, const udp_addr_t *bind_addr)
{
    vpn_memzero(udp, sizeof(*udp));
    udp->sock4 = UDP_INVALID_SOCKET;
    udp->sock6 = UDP_INVALID_SOCKET;
    udp->port = port;

    /*
     * Try to create both IPv4 and IPv6 sockets.
     * It's okay if IPv6 fails (some systems don't support it).
     */

    /* IPv4 socket */
    if (!bind_addr || !bind_addr->is_ipv6) {
        udp->sock4 = create_socket(AF_INET, port, bind_addr);
        if (udp->sock4 != UDP_INVALID_SOCKET) {
            udp->has_ipv4 = true;
        }
    }

    /* IPv6 socket */
    if (!bind_addr || bind_addr->is_ipv6) {
        udp->sock6 = create_socket(AF_INET6, port, bind_addr);
        if (udp->sock6 != UDP_INVALID_SOCKET) {
            udp->has_ipv6 = true;
        }
    }

    /* Need at least one socket */
    if (!udp->has_ipv4 && !udp->has_ipv6) {
        return VPN_ERR_NETWORK;
    }

    return VPN_OK;
}

void udp_close(udp_t *udp)
{
    if (udp->sock4 != UDP_INVALID_SOCKET) {
        close_socket(udp->sock4);
        udp->sock4 = UDP_INVALID_SOCKET;
    }
    if (udp->sock6 != UDP_INVALID_SOCKET) {
        close_socket(udp->sock6);
        udp->sock6 = UDP_INVALID_SOCKET;
    }
    udp->has_ipv4 = false;
    udp->has_ipv6 = false;
}

int udp_send(udp_t *udp, const uint8_t *data, size_t len, const udp_addr_t *dest)
{
    udp_socket_t sock;
    int result;

    if (dest->is_ipv6) {
        struct sockaddr_in6 addr;

        if (!udp->has_ipv6) {
            return VPN_ERR_NETWORK;
        }

        vpn_memzero(&addr, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(dest->port);
        vpn_memcpy(&addr.sin6_addr, dest->addr, 16);

        sock = udp->sock6;
        result = sendto(sock, (const char *)data, (int)len, 0,
                       (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr;

        if (!udp->has_ipv4) {
            return VPN_ERR_NETWORK;
        }

        vpn_memzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(dest->port);
        vpn_memcpy(&addr.sin_addr, dest->addr, 4);

        sock = udp->sock4;
        result = sendto(sock, (const char *)data, (int)len, 0,
                       (struct sockaddr *)&addr, sizeof(addr));
    }

    if (result < 0) {
        return VPN_ERR_NETWORK;
    }

    return result;
}

int udp_recv(udp_t *udp, uint8_t *buf, size_t buf_len, udp_addr_t *from)
{
    return udp_recv_timeout(udp, buf, buf_len, from, -1);  /* Blocking */
}

int udp_recv_timeout(udp_t *udp, uint8_t *buf, size_t buf_len,
                     udp_addr_t *from, int timeout_ms)
{
    fd_set read_fds;
    struct timeval tv, *tvp;
    int max_fd = 0;
    int result;

    FD_ZERO(&read_fds);

    if (udp->has_ipv4) {
        FD_SET(udp->sock4, &read_fds);
        if ((int)udp->sock4 > max_fd) {
            max_fd = (int)udp->sock4;
        }
    }
    if (udp->has_ipv6) {
        FD_SET(udp->sock6, &read_fds);
        if ((int)udp->sock6 > max_fd) {
            max_fd = (int)udp->sock6;
        }
    }

    /* Set timeout */
    if (timeout_ms < 0) {
        tvp = NULL;  /* Block indefinitely */
    } else {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }

    /* Wait for data */
    result = select(max_fd + 1, &read_fds, NULL, NULL, tvp);

    if (result < 0) {
        return VPN_ERR_NETWORK;
    }
    if (result == 0) {
        return 0;  /* Timeout */
    }

    /* Receive from whichever socket is ready */
    if (udp->has_ipv6 && FD_ISSET(udp->sock6, &read_fds)) {
        struct sockaddr_in6 addr;
        socklen_t addr_len = sizeof(addr);

        result = recvfrom(udp->sock6, (char *)buf, (int)buf_len, 0,
                         (struct sockaddr *)&addr, &addr_len);

        if (result >= 0 && from) {
            from->is_ipv6 = true;
            from->port = ntohs(addr.sin6_port);
            vpn_memcpy(from->addr, &addr.sin6_addr, 16);
        }
    } else if (udp->has_ipv4 && FD_ISSET(udp->sock4, &read_fds)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        result = recvfrom(udp->sock4, (char *)buf, (int)buf_len, 0,
                         (struct sockaddr *)&addr, &addr_len);

        if (result >= 0 && from) {
            from->is_ipv6 = false;
            from->port = ntohs(addr.sin_port);
            vpn_memzero(from->addr, 16);
            vpn_memcpy(from->addr, &addr.sin_addr, 4);
        }
    } else {
        return VPN_ERR_NETWORK;
    }

    if (result < 0) {
        return VPN_ERR_NETWORK;
    }

    return result;
}

/*
 * ===========================================================================
 * Address Utilities
 * ===========================================================================
 */

vpn_error_t udp_addr_from_string(udp_addr_t *addr, const char *str)
{
    char buf[64];
    char *port_str;
    char *addr_str;
    int port;

    if (!str || strlen(str) >= sizeof(buf)) {
        return VPN_ERR_INVALID;
    }

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    vpn_memzero(addr, sizeof(*addr));

    /* Check for IPv6 format: [addr]:port */
    if (buf[0] == '[') {
        addr_str = buf + 1;
        port_str = strchr(addr_str, ']');
        if (!port_str) {
            return VPN_ERR_INVALID;
        }
        *port_str++ = '\0';
        if (*port_str != ':') {
            return VPN_ERR_INVALID;
        }
        port_str++;
        addr->is_ipv6 = true;
    } else {
        /* IPv4 format: addr:port */
        addr_str = buf;
        port_str = strrchr(buf, ':');
        if (!port_str) {
            return VPN_ERR_INVALID;
        }
        *port_str++ = '\0';
        addr->is_ipv6 = false;
    }

    /* Parse port */
    port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        return VPN_ERR_INVALID;
    }
    addr->port = (uint16_t)port;

    /* Parse address */
    if (addr->is_ipv6) {
        if (inet_pton(AF_INET6, addr_str, addr->addr) != 1) {
            return VPN_ERR_INVALID;
        }
    } else {
        if (inet_pton(AF_INET, addr_str, addr->addr) != 1) {
            return VPN_ERR_INVALID;
        }
    }

    return VPN_OK;
}

char *udp_addr_to_string(const udp_addr_t *addr, char *buf, size_t buf_len)
{
    char ip_buf[64];

    if (addr->is_ipv6) {
        if (!inet_ntop(AF_INET6, addr->addr, ip_buf, sizeof(ip_buf))) {
            return NULL;
        }
        snprintf(buf, buf_len, "[%s]:%u", ip_buf, addr->port);
    } else {
        if (!inet_ntop(AF_INET, addr->addr, ip_buf, sizeof(ip_buf))) {
            return NULL;
        }
        snprintf(buf, buf_len, "%s:%u", ip_buf, addr->port);
    }

    return buf;
}

bool udp_addr_equal(const udp_addr_t *a, const udp_addr_t *b)
{
    if (a->is_ipv6 != b->is_ipv6) {
        return false;
    }
    if (a->port != b->port) {
        return false;
    }

    size_t addr_len = a->is_ipv6 ? 16 : 4;
    return vpn_memeq(a->addr, b->addr, addr_len);
}

void udp_addr_copy(udp_addr_t *dst, const udp_addr_t *src)
{
    vpn_memcpy(dst, src, sizeof(*dst));
}
