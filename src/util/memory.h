/*
 * memory.h - Secure Memory Operations
 * ====================================
 *
 * Cryptographic code has special memory handling requirements that normal
 * applications don't worry about. This module provides secure alternatives
 * to standard memory functions.
 *
 * WHY SECURE MEMORY MATTERS:
 *
 * 1. COMPILER OPTIMIZATION: If you zero out a key buffer and then never use
 *    it again, the compiler might remove your zeroing code as "dead store
 *    optimization." An attacker examining memory could find your keys.
 *
 * 2. TIMING ATTACKS: Standard memcmp() returns early on first mismatch.
 *    An attacker can measure how long comparison takes to learn how many
 *    bytes matched. With enough measurements, they can guess secrets.
 *
 * 3. MEMORY DISCLOSURE: Keys left in memory can leak via core dumps,
 *    swap files, or memory disclosure vulnerabilities.
 *
 * LEARNING NOTE: These concerns seem paranoid but are responsible for
 * real-world vulnerabilities. WireGuard and other serious crypto code
 * always uses secure memory operations.
 */

#ifndef VPN_MEMORY_H
#define VPN_MEMORY_H

#include "../types.h"

/*
 * vpn_memzero - Securely zero memory (won't be optimized away)
 *
 * Use this to clear sensitive data like keys, passwords, plaintext.
 * The implementation uses volatile or memory barriers to prevent
 * the compiler from optimizing away the operation.
 *
 * @param ptr   Pointer to memory to zero
 * @param len   Number of bytes to zero
 *
 * EXAMPLE:
 *   uint8_t key[32];
 *   // ... use key ...
 *   vpn_memzero(key, sizeof(key));  // Key is now securely erased
 */
void vpn_memzero(void *ptr, size_t len);

/*
 * vpn_memeq - Constant-time memory comparison
 *
 * Compares two memory regions in constant time, preventing timing attacks.
 * Unlike memcmp(), this ALWAYS examines ALL bytes regardless of where
 * differences occur.
 *
 * @param a     First memory region
 * @param b     Second memory region
 * @param len   Number of bytes to compare
 * @return      true if equal, false if different
 *
 * TIMING ATTACK EXAMPLE:
 *   Suppose we're checking a MAC tag:
 *
 *   // INSECURE: memcmp returns early on first difference
 *   if (memcmp(computed_tag, received_tag, 16) == 0) { ... }
 *
 *   An attacker sends tags with different first bytes and measures time.
 *   If tag[0] is wrong, comparison returns immediately (~10 cycles).
 *   If tag[0] is right but tag[1] is wrong, it takes slightly longer.
 *   After ~256 attempts, attacker knows correct tag[0]. Repeat for each byte.
 *
 *   // SECURE: constant time regardless of where differences are
 *   if (vpn_memeq(computed_tag, received_tag, 16)) { ... }
 */
bool vpn_memeq(const void *a, const void *b, size_t len);

/*
 * vpn_memcpy - Copy memory (standard memcpy wrapper)
 *
 * We wrap memcpy for consistency and potential future security additions
 * (like bounds checking in debug mode).
 *
 * @param dst   Destination buffer
 * @param src   Source buffer
 * @param len   Number of bytes to copy
 * @return      dst pointer
 */
void *vpn_memcpy(void *dst, const void *src, size_t len);

/*
 * vpn_memxor - XOR two memory regions into destination
 *
 * Computes dst[i] = a[i] ^ b[i] for i in 0..len-1
 * This is fundamental to stream cipher encryption:
 *   ciphertext = plaintext XOR keystream
 *
 * @param dst   Destination buffer (can be same as a or b)
 * @param a     First source buffer
 * @param b     Second source buffer
 * @param len   Number of bytes to XOR
 *
 * EXAMPLE:
 *   uint8_t plaintext[64];
 *   uint8_t keystream[64];
 *   uint8_t ciphertext[64];
 *   vpn_memxor(ciphertext, plaintext, keystream, 64);
 */
void vpn_memxor(void *dst, const void *a, const void *b, size_t len);

#endif /* VPN_MEMORY_H */
