/*
 * random.h - Cryptographically Secure Random Number Generation
 * =============================================================
 *
 * This module provides access to the operating system's cryptographically
 * secure random number generator (CSPRNG).
 *
 * SECURITY REQUIREMENTS:
 *
 * Cryptographic keys MUST be generated using a CSPRNG. Using predictable
 * sources like time(), rand(), or linear congruential generators is a
 * critical vulnerability that allows key recovery.
 *
 * PLATFORM IMPLEMENTATIONS:
 *
 * - Linux: getrandom() syscall (kernel 3.17+) or /dev/urandom
 * - Windows: BCryptGenRandom() or RtlGenRandom()
 * - macOS/BSD: arc4random_buf() or /dev/urandom
 *
 * All these sources draw from the kernel's entropy pool, which is seeded
 * from hardware events (interrupts, disk timing, etc.) and optionally
 * hardware RNG (RDRAND on Intel, etc.).
 */

#ifndef VPN_RANDOM_H
#define VPN_RANDOM_H

#include "../types.h"

/*
 * vpn_random_bytes - Generate cryptographically secure random bytes
 *
 * Fills the buffer with random bytes from the system CSPRNG.
 * This function will block if insufficient entropy is available
 * (rare on modern systems).
 *
 * @param buf   Buffer to fill with random bytes
 * @param len   Number of bytes to generate
 * @return      VPN_OK on success, VPN_ERR_CRYPTO on failure
 *
 * FAILURE: This function failing is a critical error. The system's
 * random source is unavailable, and the program should abort rather
 * than continue with weak randomness.
 */
vpn_error_t vpn_random_bytes(void *buf, size_t len);

/*
 * vpn_random_u32 - Generate a random 32-bit integer
 *
 * @return  Random uint32_t value
 */
uint32_t vpn_random_u32(void);

/*
 * vpn_random_u64 - Generate a random 64-bit integer
 *
 * @return  Random uint64_t value
 */
uint64_t vpn_random_u64(void);

/*
 * vpn_random_uniform - Generate random integer in range [0, bound)
 *
 * Uses rejection sampling to ensure uniform distribution.
 * Avoids modulo bias that occurs with naive (rand() % bound).
 *
 * @param bound     Upper bound (exclusive)
 * @return          Random value in [0, bound)
 */
uint32_t vpn_random_uniform(uint32_t bound);

#endif /* VPN_RANDOM_H */
