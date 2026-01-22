/*
 * tun.c - TUN/TAP Network Interface Implementation
 * =================================================
 *
 * This implements TUN device operations. The implementation varies significantly
 * by platform.
 *
 * LINUX IMPLEMENTATION:
 *
 * Linux provides TUN/TAP via /dev/net/tun. The process:
 * 1. Open /dev/net/tun
 * 2. ioctl(TUNSETIFF) to allocate and name the interface
 * 3. Read/write raw IP packets
 *
 * The kernel handles routing packets to/from the TUN device based on the
 * routing table.
 *
 * WINDOWS IMPLEMENTATION:
 *
 * Windows requires either:
 * - Wintun: Modern kernel driver, high performance ring buffers
 * - TAP-Windows: Legacy, used by OpenVPN
 *
 * For this educational implementation, we provide stubs that describe what
 * a real implementation would do.
 *
 * macOS IMPLEMENTATION:
 *
 * macOS uses /dev/utunN devices. Each open creates a new interface.
 * Packets have a 4-byte header containing the address family.
 */

#include "tun.h"
#include "../util/memory.h"
#include <string.h>
#include <stdio.h>

#ifdef __linux__
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <sys/select.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
#elif defined(__APPLE__)
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
    #include <net/if_utun.h>
    #include <sys/select.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <iphlpapi.h>
    #include <netioapi.h>

    /*
     * Wintun API declarations.
     *
     * Wintun is a modern TUN driver for Windows, developed by the WireGuard
     * project. It provides high-performance packet I/O via ring buffers.
     *
     * We dynamically load wintun.dll at runtime to avoid requiring the
     * Wintun SDK at compile time.
     *
     * See: https://www.wintun.net/
     */

    /* Wintun types */
    typedef void *WINTUN_ADAPTER_HANDLE;
    typedef void *WINTUN_SESSION_HANDLE;

    /* Ring buffer packet structure */
    typedef struct {
        DWORD Size;     /* Packet size */
    } WINTUN_PACKET;

    /* Wintun function types */
    typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
        const WCHAR *Name,
        const WCHAR *TunnelType,
        const GUID *RequestedGUID
    );

    typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(
        WINTUN_ADAPTER_HANDLE Adapter
    );

    typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(
        WINTUN_ADAPTER_HANDLE Adapter,
        DWORD Capacity
    );

    typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(
        WINTUN_SESSION_HANDLE Session
    );

    typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(
        WINTUN_SESSION_HANDLE Session
    );

    typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(
        WINTUN_SESSION_HANDLE Session,
        DWORD *PacketSize
    );

    typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
        WINTUN_SESSION_HANDLE Session,
        const BYTE *Packet
    );

    typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
        WINTUN_SESSION_HANDLE Session,
        DWORD PacketSize
    );

    typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(
        WINTUN_SESSION_HANDLE Session,
        const BYTE *Packet
    );

    typedef DWORD (WINAPI *WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)(void);

    typedef BOOL (WINAPI *WINTUN_SET_LOGGER_FUNC)(
        void *NewLogger
    );

    /* Global function pointers (loaded from DLL) */
    static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
    static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter;
    static WINTUN_START_SESSION_FUNC WintunStartSession;
    static WINTUN_END_SESSION_FUNC WintunEndSession;
    static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
    static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
    static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
    static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
    static WINTUN_SEND_PACKET_FUNC WintunSendPacket;
    static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;

    static HMODULE g_wintun_dll = NULL;

    /*
     * Load Wintun DLL and resolve function pointers
     */
    static bool wintun_load_dll(void)
    {
        if (g_wintun_dll) {
            return true;  /* Already loaded */
        }

        g_wintun_dll = LoadLibraryW(L"wintun.dll");
        if (!g_wintun_dll) {
            return false;
        }

        #define LOAD_FUNC(name) \
            name = (name##_FUNC)GetProcAddress(g_wintun_dll, #name); \
            if (!name) { FreeLibrary(g_wintun_dll); g_wintun_dll = NULL; return false; }

        LOAD_FUNC(WintunCreateAdapter);
        LOAD_FUNC(WintunCloseAdapter);
        LOAD_FUNC(WintunStartSession);
        LOAD_FUNC(WintunEndSession);
        LOAD_FUNC(WintunGetReadWaitEvent);
        LOAD_FUNC(WintunReceivePacket);
        LOAD_FUNC(WintunReleaseReceivePacket);
        LOAD_FUNC(WintunAllocateSendPacket);
        LOAD_FUNC(WintunSendPacket);
        LOAD_FUNC(WintunGetRunningDriverVersion);

        #undef LOAD_FUNC

        return true;
    }
#endif

/*
 * ===========================================================================
 * Linux Implementation
 * ===========================================================================
 */

#ifdef __linux__

vpn_error_t tun_open(tun_t *tun, const char *name)
{
    struct ifreq ifr;
    int fd;

    vpn_memzero(tun, sizeof(*tun));

    /*
     * Open the TUN clone device.
     * /dev/net/tun is the standard path on Linux.
     */
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return VPN_ERR_NETWORK;
    }

    /*
     * Configure the interface.
     * IFF_TUN = TUN device (IP packets)
     * IFF_NO_PI = No packet info header (raw IP)
     */
    vpn_memzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (name && name[0]) {
        /* Use specified name */
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }
    /* else: kernel picks a name like "tun0" */

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return VPN_ERR_NETWORK;
    }

    /* Store results */
    tun->fd = fd;
    strncpy(tun->name, ifr.ifr_name, TUN_NAME_MAX - 1);
    tun->mtu = 1500;  /* Default, can be changed */
    tun->is_open = true;

    return VPN_OK;
}

void tun_close(tun_t *tun)
{
    if (tun->is_open) {
        close(tun->fd);
        tun->fd = -1;
        tun->is_open = false;
    }
}

int tun_read(tun_t *tun, uint8_t *buf, size_t buf_len)
{
    return tun_read_timeout(tun, buf, buf_len, -1);
}

int tun_read_timeout(tun_t *tun, uint8_t *buf, size_t buf_len, int timeout_ms)
{
    fd_set read_fds;
    struct timeval tv, *tvp;
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    FD_ZERO(&read_fds);
    FD_SET(tun->fd, &read_fds);

    if (timeout_ms < 0) {
        tvp = NULL;
    } else {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }

    result = select(tun->fd + 1, &read_fds, NULL, NULL, tvp);

    if (result < 0) {
        return VPN_ERR_NETWORK;
    }
    if (result == 0) {
        return 0;  /* Timeout */
    }

    return read(tun->fd, buf, buf_len);
}

int tun_write(tun_t *tun, const uint8_t *data, size_t len)
{
    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    return write(tun->fd, data, len);
}

vpn_error_t tun_set_ip(tun_t *tun, const uint8_t *addr, uint8_t prefix, bool is_ipv6)
{
    char cmd[256];
    char ip_str[64];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    /* Format IP address */
    if (is_ipv6) {
        snprintf(ip_str, sizeof(ip_str),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2], addr[3],
                 addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11],
                 addr[12], addr[13], addr[14], addr[15]);
    } else {
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 addr[0], addr[1], addr[2], addr[3]);
    }

    /* Use 'ip' command to set address */
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%u dev %s",
             ip_str, prefix, tun->name);

    result = system(cmd);

    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_set_mtu(tun_t *tun, uint32_t mtu)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ip link set dev %s mtu %u", tun->name, mtu);
    result = system(cmd);

    if (result == 0) {
        tun->mtu = mtu;
        return VPN_OK;
    }

    return VPN_ERR_NETWORK;
}

vpn_error_t tun_up(tun_t *tun)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", tun->name);
    result = system(cmd);

    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_down(tun_t *tun)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ip link set dev %s down", tun->name);
    result = system(cmd);

    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

#elif defined(__APPLE__)

/*
 * ===========================================================================
 * macOS Implementation (utun)
 * ===========================================================================
 *
 * macOS provides utun devices for userspace tunneling. Unlike Linux TUN,
 * macOS utun uses a control socket mechanism:
 *
 * 1. Create a PF_SYSTEM socket with SYSPROTO_CONTROL protocol
 * 2. Get the control ID for "com.apple.net.utun_control"
 * 3. Connect with a sockaddr_ctl specifying the unit number
 * 4. The interface is automatically created (e.g., utun0, utun1)
 *
 * PACKET FORMAT:
 *
 * Unlike Linux TUN (raw IP), macOS utun prepends a 4-byte header:
 *   [4 bytes: address family] [IP packet...]
 *
 * Address family is in host byte order:
 *   AF_INET  (2)  for IPv4
 *   AF_INET6 (30) for IPv6
 *
 * We handle this transparently in read/write.
 */

#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>

/* Control name for utun */
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"

vpn_error_t tun_open(tun_t *tun, const char *name)
{
    struct sockaddr_ctl sc;
    struct ctl_info ctlInfo;
    int fd;
    int unit = 0;  /* 0 = auto-assign, otherwise specific unit number */
    socklen_t utunname_len;

    vpn_memzero(tun, sizeof(*tun));

    /*
     * If a name like "utun5" was specified, extract the unit number.
     * Otherwise, use 0 for auto-assignment.
     */
    if (name && strncmp(name, "utun", 4) == 0) {
        unit = atoi(name + 4);
        if (unit < 0) unit = 0;
    }

    /*
     * Step 1: Create a system control socket
     *
     * PF_SYSTEM + SYSPROTO_CONTROL gives us access to kernel controls.
     */
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return VPN_ERR_NETWORK;
    }

    /*
     * Step 2: Get the control ID for utun
     *
     * The kernel maintains a registry of control names to IDs.
     * We need the ID to connect.
     */
    vpn_memzero(&ctlInfo, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        close(fd);
        return VPN_ERR_NETWORK;
    }

    /*
     * Step 3: Connect to create the interface
     *
     * The sc_unit field specifies which utunN to create:
     *   0 = kernel picks next available (utun0, utun1, etc.)
     *   N = create utun(N-1), so sc_unit=1 creates utun0
     */
    vpn_memzero(&sc, sizeof(sc));
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = unit + 1;  /* +1 because 0 means auto, 1 means utun0, etc. */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        close(fd);
        return VPN_ERR_NETWORK;
    }

    /*
     * Step 4: Get the actual interface name
     *
     * If we used auto-assignment, we need to find out what name was given.
     */
    utunname_len = sizeof(tun->name);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                   tun->name, &utunname_len) < 0) {
        /* Fallback: construct name from unit */
        snprintf(tun->name, sizeof(tun->name), "utun%d",
                 sc.sc_unit > 0 ? sc.sc_unit - 1 : 0);
    }

    tun->fd = fd;
    tun->mtu = 1420;  /* Default VPN MTU */
    tun->is_open = true;

    return VPN_OK;
}

void tun_close(tun_t *tun)
{
    if (tun->is_open) {
        close(tun->fd);
        tun->fd = -1;
        tun->is_open = false;
    }
}

int tun_read(tun_t *tun, uint8_t *buf, size_t buf_len)
{
    return tun_read_timeout(tun, buf, buf_len, -1);
}

int tun_read_timeout(tun_t *tun, uint8_t *buf, size_t buf_len, int timeout_ms)
{
    fd_set read_fds;
    struct timeval tv, *tvp;
    int result;
    uint8_t header[4];
    struct iovec iov[2];
    ssize_t n;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    /* Wait for data with optional timeout */
    FD_ZERO(&read_fds);
    FD_SET(tun->fd, &read_fds);

    if (timeout_ms < 0) {
        tvp = NULL;
    } else {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }

    result = select(tun->fd + 1, &read_fds, NULL, NULL, tvp);

    if (result < 0) {
        return VPN_ERR_NETWORK;
    }
    if (result == 0) {
        return 0;  /* Timeout */
    }

    /*
     * Read with scatter-gather to separate the 4-byte header.
     * This avoids memmove operations.
     */
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = buf;
    iov[1].iov_len = buf_len;

    n = readv(tun->fd, iov, 2);
    if (n < 0) {
        return VPN_ERR_NETWORK;
    }
    if (n <= 4) {
        return 0;  /* No actual packet data */
    }

    /* Return just the IP packet length (exclude header) */
    return (int)(n - 4);
}

int tun_write(tun_t *tun, const uint8_t *data, size_t len)
{
    uint8_t header[4];
    struct iovec iov[2];
    ssize_t n;
    uint32_t af;

    if (!tun->is_open || len < 1) {
        return VPN_ERR_INVALID;
    }

    /*
     * Determine address family from IP version in packet.
     * IPv4: version nibble = 4
     * IPv6: version nibble = 6
     */
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version == 4) {
        af = AF_INET;
    } else if (version == 6) {
        af = AF_INET6;
    } else {
        return VPN_ERR_INVALID;  /* Unknown IP version */
    }

    /*
     * Prepend the 4-byte address family header.
     * macOS expects this in host byte order.
     */
    header[0] = (uint8_t)(af);
    header[1] = (uint8_t)(af >> 8);
    header[2] = (uint8_t)(af >> 16);
    header[3] = (uint8_t)(af >> 24);

    /*
     * Use scatter-gather write to avoid copying.
     */
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = (void *)data;
    iov[1].iov_len = len;

    n = writev(tun->fd, iov, 2);
    if (n < 0) {
        return VPN_ERR_NETWORK;
    }

    /* Return the payload length (exclude header) */
    return (n > 4) ? (int)(n - 4) : 0;
}

vpn_error_t tun_set_ip(tun_t *tun, const uint8_t *addr, uint8_t prefix, bool is_ipv6)
{
    char cmd[256];
    char ip_str[64];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    /* Format IP address */
    if (is_ipv6) {
        snprintf(ip_str, sizeof(ip_str),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2], addr[3],
                 addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11],
                 addr[12], addr[13], addr[14], addr[15]);
        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s inet6 %s/%u",
                 tun->name, ip_str, prefix);
    } else {
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 addr[0], addr[1], addr[2], addr[3]);

        /*
         * macOS ifconfig requires both address and destination for point-to-point.
         * For simplicity, we set destination = address (self-route).
         */
        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s inet %s %s netmask 0x%08x",
                 tun->name, ip_str, ip_str,
                 prefix ? (~0U << (32 - prefix)) : 0);
    }

    result = system(cmd);
    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_set_mtu(tun_t *tun, uint32_t mtu)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %u", tun->name, mtu);
    result = system(cmd);

    if (result == 0) {
        tun->mtu = mtu;
        return VPN_OK;
    }

    return VPN_ERR_NETWORK;
}

vpn_error_t tun_up(tun_t *tun)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ifconfig %s up", tun->name);
    result = system(cmd);

    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_down(tun_t *tun)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd), "ifconfig %s down", tun->name);
    result = system(cmd);

    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

#elif defined(_WIN32)

/*
 * ===========================================================================
 * Windows Implementation (Wintun)
 * ===========================================================================
 *
 * This implementation uses the Wintun driver, the same high-performance
 * TUN driver used by WireGuard for Windows.
 *
 * Wintun uses ring buffers for efficient packet I/O:
 * - WintunReceivePacket() returns a pointer into the receive ring
 * - WintunAllocateSendPacket() allocates space in the send ring
 * - Both are zero-copy operations when possible
 *
 * REQUIREMENTS:
 * - wintun.dll must be present (can be downloaded from wintun.net)
 * - Administrator privileges are required
 * - Windows 7 or later
 */

#define WINTUN_RING_CAPACITY 0x400000  /* 4MB ring buffer */

vpn_error_t tun_open(tun_t *tun, const char *name)
{
    WCHAR wide_name[TUN_NAME_MAX];
    int name_len;

    vpn_memzero(tun, sizeof(*tun));

    /* Load Wintun DLL */
    if (!wintun_load_dll()) {
        /*
         * Wintun.dll not found. This is expected if Wintun isn't installed.
         * User should download from https://www.wintun.net/
         */
        return VPN_ERR_NETWORK;
    }

    /* Check if Wintun driver is running */
    DWORD version = WintunGetRunningDriverVersion();
    if (version == 0) {
        /* Driver not installed or not running */
        return VPN_ERR_NETWORK;
    }

    /* Convert interface name to wide string */
    if (name && name[0]) {
        name_len = MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name, TUN_NAME_MAX);
        if (name_len == 0) {
            wcscpy_s(wide_name, TUN_NAME_MAX, L"VPN");
        }
    } else {
        wcscpy_s(wide_name, TUN_NAME_MAX, L"VPN");
    }

    /* Create adapter */
    tun->adapter = WintunCreateAdapter(wide_name, L"HinkyPunk", NULL);
    if (!tun->adapter) {
        return VPN_ERR_NETWORK;
    }

    /* Start session with ring buffers */
    tun->session = WintunStartSession(tun->adapter, WINTUN_RING_CAPACITY);
    if (!tun->session) {
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
        return VPN_ERR_NETWORK;
    }

    /* Get read wait event for efficient polling */
    tun->read_event = WintunGetReadWaitEvent(tun->session);

    /* Store interface name */
    WideCharToMultiByte(CP_UTF8, 0, wide_name, -1, tun->name, TUN_NAME_MAX, NULL, NULL);

    tun->mtu = 1420;  /* Default VPN MTU */
    tun->is_open = true;

    return VPN_OK;
}

void tun_close(tun_t *tun)
{
    if (!tun->is_open) {
        return;
    }

    if (tun->session) {
        WintunEndSession(tun->session);
        tun->session = NULL;
    }

    if (tun->adapter) {
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
    }

    tun->read_event = NULL;
    tun->is_open = false;
}

int tun_read(tun_t *tun, uint8_t *buf, size_t buf_len)
{
    return tun_read_timeout(tun, buf, buf_len, INFINITE);
}

int tun_read_timeout(tun_t *tun, uint8_t *buf, size_t buf_len, int timeout_ms)
{
    DWORD packet_size;
    BYTE *packet;
    DWORD wait_result;

    if (!tun->is_open || !tun->session) {
        return VPN_ERR_INVALID;
    }

    /* Wait for packet to be available */
    wait_result = WaitForSingleObject(tun->read_event,
                                      timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);

    if (wait_result == WAIT_TIMEOUT) {
        return 0;  /* Timeout, no data */
    }

    if (wait_result != WAIT_OBJECT_0) {
        return VPN_ERR_NETWORK;
    }

    /* Receive packet from ring buffer */
    packet = WintunReceivePacket(tun->session, &packet_size);
    if (!packet) {
        /*
         * No packet available despite event being signaled.
         * This can happen in race conditions; just return 0.
         */
        return 0;
    }

    /* Copy to user buffer (respecting buffer size) */
    if (packet_size > buf_len) {
        packet_size = (DWORD)buf_len;
    }
    vpn_memcpy(buf, packet, packet_size);

    /* Release the packet back to the ring buffer */
    WintunReleaseReceivePacket(tun->session, packet);

    return (int)packet_size;
}

int tun_write(tun_t *tun, const uint8_t *data, size_t len)
{
    BYTE *packet;

    if (!tun->is_open || !tun->session) {
        return VPN_ERR_INVALID;
    }

    /* Allocate space in the send ring */
    packet = WintunAllocateSendPacket(tun->session, (DWORD)len);
    if (!packet) {
        /*
         * Ring buffer full. In a production implementation,
         * we might want to wait or drop the packet.
         */
        return VPN_ERR_NETWORK;
    }

    /* Copy data to ring buffer */
    vpn_memcpy(packet, data, len);

    /* Send the packet */
    WintunSendPacket(tun->session, packet);

    return (int)len;
}

vpn_error_t tun_set_ip(tun_t *tun, const uint8_t *addr, uint8_t prefix, bool is_ipv6)
{
    char cmd[256];
    char ip_str[64];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    /* Format IP address */
    if (is_ipv6) {
        snprintf(ip_str, sizeof(ip_str),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2], addr[3],
                 addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11],
                 addr[12], addr[13], addr[14], addr[15]);
    } else {
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 addr[0], addr[1], addr[2], addr[3]);
    }

    /*
     * Use netsh to configure the interface.
     *
     * For IPv4:
     *   netsh interface ip set address "VPN" static <ip> <mask>
     *
     * For IPv6:
     *   netsh interface ipv6 add address "VPN" <ip>/<prefix>
     *
     * Note: A production implementation would use the Windows IP Helper API
     * (CreateUnicastIpAddressEntry) for better reliability.
     */
    if (is_ipv6) {
        snprintf(cmd, sizeof(cmd),
                 "netsh interface ipv6 add address \"%s\" %s/%u",
                 tun->name, ip_str, prefix);
    } else {
        /* Convert prefix to subnet mask */
        uint32_t mask = prefix ? (~0U << (32 - prefix)) : 0;
        snprintf(cmd, sizeof(cmd),
                 "netsh interface ip set address \"%s\" static %s %u.%u.%u.%u",
                 tun->name, ip_str,
                 (mask >> 24) & 0xFF,
                 (mask >> 16) & 0xFF,
                 (mask >> 8) & 0xFF,
                 mask & 0xFF);
    }

    result = system(cmd);
    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_set_mtu(tun_t *tun, uint32_t mtu)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    /*
     * Set MTU via netsh.
     * Note: netsh uses "mtu" for IPv4 and "interfacemtu" for IPv6
     */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set subinterface \"%s\" mtu=%u store=active",
             tun->name, mtu);

    result = system(cmd);
    if (result == 0) {
        tun->mtu = mtu;
        return VPN_OK;
    }

    return VPN_ERR_NETWORK;
}

vpn_error_t tun_up(tun_t *tun)
{
    /*
     * Wintun interfaces are automatically "up" when a session is active.
     * We just need to ensure the interface is enabled in Windows.
     */
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd),
             "netsh interface set interface \"%s\" admin=enabled",
             tun->name);

    result = system(cmd);
    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

vpn_error_t tun_down(tun_t *tun)
{
    char cmd[128];
    int result;

    if (!tun->is_open) {
        return VPN_ERR_INVALID;
    }

    snprintf(cmd, sizeof(cmd),
             "netsh interface set interface \"%s\" admin=disabled",
             tun->name);

    result = system(cmd);
    return (result == 0) ? VPN_OK : VPN_ERR_NETWORK;
}

#else
    #error "Unsupported platform"
#endif

/*
 * ===========================================================================
 * Common Functions (Platform-Independent)
 * ===========================================================================
 */

const char *tun_get_name(const tun_t *tun)
{
    return tun->name;
}

uint32_t tun_get_mtu(const tun_t *tun)
{
    return tun->mtu;
}

int tun_packet_ip_version(const uint8_t *packet, size_t len)
{
    if (len < 1) {
        return 0;
    }

    /*
     * IP version is in the high nibble of the first byte.
     * IPv4: 0100.... (4)
     * IPv6: 0110.... (6)
     */
    uint8_t version = (packet[0] >> 4) & 0x0F;

    if (version == 4 && len >= 20) {
        return 4;
    } else if (version == 6 && len >= 40) {
        return 6;
    }

    return 0;
}

vpn_error_t tun_packet_get_dst(const uint8_t *packet, size_t len,
                               uint8_t *dst, bool *is_ipv6)
{
    int version = tun_packet_ip_version(packet, len);

    if (version == 4) {
        /*
         * IPv4 header:
         * Bytes 16-19: Destination address
         */
        vpn_memcpy(dst, packet + 16, 4);
        *is_ipv6 = false;
        return VPN_OK;
    } else if (version == 6) {
        /*
         * IPv6 header:
         * Bytes 24-39: Destination address
         */
        vpn_memcpy(dst, packet + 24, 16);
        *is_ipv6 = true;
        return VPN_OK;
    }

    return VPN_ERR_INVALID;
}

vpn_error_t tun_packet_get_src(const uint8_t *packet, size_t len,
                               uint8_t *src, bool *is_ipv6)
{
    int version = tun_packet_ip_version(packet, len);

    if (version == 4) {
        /*
         * IPv4 header:
         * Bytes 12-15: Source address
         */
        vpn_memcpy(src, packet + 12, 4);
        *is_ipv6 = false;
        return VPN_OK;
    } else if (version == 6) {
        /*
         * IPv6 header:
         * Bytes 8-23: Source address
         */
        vpn_memcpy(src, packet + 8, 16);
        *is_ipv6 = true;
        return VPN_OK;
    }

    return VPN_ERR_INVALID;
}
