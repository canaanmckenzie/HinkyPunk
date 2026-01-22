/*
 * random.c - Cryptographically Secure Random Number Generation
 * =============================================================
 *
 * Platform-specific implementations for secure random number generation.
 */

#include "random.h"
#include "memory.h"
#include <string.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
    #include <sys/random.h>
    #include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    #include <stdlib.h>  /* arc4random_buf */
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
#endif

/*
 * ===========================================================================
 * Platform-Specific Random Byte Generation
 * ===========================================================================
 */

#ifdef _WIN32

vpn_error_t vpn_random_bytes(void *buf, size_t len)
{
    /*
     * BCryptGenRandom is the modern Windows API for cryptographic randomness.
     * BCRYPT_USE_SYSTEM_PREFERRED_RNG uses the default system RNG.
     */
    NTSTATUS status = BCryptGenRandom(
        NULL,                           /* Algorithm handle (NULL for system default) */
        (PUCHAR)buf,                    /* Output buffer */
        (ULONG)len,                     /* Length */
        BCRYPT_USE_SYSTEM_PREFERRED_RNG /* Flags */
    );

    if (!BCRYPT_SUCCESS(status)) {
        vpn_memzero(buf, len);
        return VPN_ERR_CRYPTO;
    }

    return VPN_OK;
}

#elif defined(__linux__)

vpn_error_t vpn_random_bytes(void *buf, size_t len)
{
    /*
     * getrandom() is the preferred interface on Linux 3.17+.
     * It avoids file descriptor exhaustion attacks against /dev/urandom.
     * Flags=0 means block until entropy is available (like /dev/random
     * behavior during early boot, but then acts like /dev/urandom).
     */
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = getrandom(p, remaining, 0);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted, retry */
            }
            vpn_memzero(buf, len);
            return VPN_ERR_CRYPTO;
        }

        p += ret;
        remaining -= (size_t)ret;
    }

    return VPN_OK;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

vpn_error_t vpn_random_bytes(void *buf, size_t len)
{
    /*
     * arc4random_buf is available on macOS, FreeBSD, OpenBSD.
     * It never fails and doesn't require seeding.
     * Despite the name (from RC4), modern implementations use ChaCha20.
     */
    arc4random_buf(buf, len);
    return VPN_OK;
}

#else

/* Fallback: /dev/urandom */
vpn_error_t vpn_random_bytes(void *buf, size_t len)
{
    int fd;
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        vpn_memzero(buf, len);
        return VPN_ERR_CRYPTO;
    }

    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            vpn_memzero(buf, len);
            return VPN_ERR_CRYPTO;
        }

        if (ret == 0) {
            /* EOF on /dev/urandom shouldn't happen */
            close(fd);
            vpn_memzero(buf, len);
            return VPN_ERR_CRYPTO;
        }

        p += ret;
        remaining -= (size_t)ret;
    }

    close(fd);
    return VPN_OK;
}

#endif

/*
 * ===========================================================================
 * Convenience Functions
 * ===========================================================================
 */

uint32_t vpn_random_u32(void)
{
    uint32_t val;

    if (vpn_random_bytes(&val, sizeof(val)) != VPN_OK) {
        /*
         * Critical failure - cannot generate random numbers.
         * In a real system, we might abort() here.
         * For now, return 0 and let caller handle.
         */
        return 0;
    }

    return val;
}

uint64_t vpn_random_u64(void)
{
    uint64_t val;

    if (vpn_random_bytes(&val, sizeof(val)) != VPN_OK) {
        return 0;
    }

    return val;
}

uint32_t vpn_random_uniform(uint32_t bound)
{
    uint32_t min, val;

    if (bound < 2) {
        return 0;
    }

    /*
     * Rejection sampling to avoid modulo bias.
     *
     * The naive approach (random() % bound) has bias when bound doesn't
     * evenly divide 2^32. For example, if bound=3:
     *   - Values 0, 1, 2 map to 0 (via 0, 3, 6, ...)
     *   - But there are more multiples of 3 that map to 0 than to 2
     *
     * We reject values >= (2^32 - (2^32 % bound)) to ensure uniformity.
     * For most bounds, rejection is rare (<50% chance per attempt).
     */
    min = (uint32_t)(-(int32_t)bound) % bound;  /* = 2^32 % bound */

    do {
        val = vpn_random_u32();
    } while (val < min);

    return val % bound;
}
