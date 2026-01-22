/*
 * memory.c - Secure Memory Operations Implementation
 * ===================================================
 *
 * This implements the secure memory functions declared in memory.h.
 * Read memory.h first for the "why" - this file focuses on the "how."
 */

#include "memory.h"
#include <string.h>

/*
 * vpn_memzero - Securely zero memory
 *
 * IMPLEMENTATION STRATEGY:
 * We use the 'volatile' keyword to tell the compiler "this memory access
 * has side effects you don't understand, so don't optimize it away."
 *
 * The volatile pointer forces the compiler to actually perform each write
 * to memory, even if the memory is never read afterward.
 *
 * ALTERNATIVE APPROACHES:
 * 1. explicit_bzero() - Available on some systems, does the same thing
 * 2. SecureZeroMemory() - Windows-specific
 * 3. memset_s() - C11 Annex K, but not widely supported
 * 4. Memory barrier asm - More complex, platform-specific
 *
 * We use the volatile approach for maximum portability.
 */
void vpn_memzero(void *ptr, size_t len)
{
    /*
     * Cast to volatile pointer. This tells the compiler:
     * "Something else might be watching this memory, so you MUST
     * perform these writes even if you think they're useless."
     */
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len--) {
        *p++ = 0;
    }

    /*
     * NOTE: A more optimized version might zero 8 bytes at a time
     * using uint64_t, but this simple version is correct and the
     * compiler can often optimize the loop anyway. Security over speed.
     */
}

/*
 * vpn_memeq - Constant-time memory comparison
 *
 * IMPLEMENTATION STRATEGY:
 * We XOR corresponding bytes and OR all results together.
 * If all bytes match, all XORs produce 0, and the final OR is 0.
 * If any byte differs, at least one XOR produces non-zero, and OR captures it.
 *
 * THE KEY INSIGHT: We process ALL bytes regardless of intermediate results.
 * There's no early return, no branching based on comparison values.
 *
 * WHY XOR AND OR?
 * - XOR of identical bytes = 0
 * - XOR of different bytes = non-zero (has at least one bit set)
 * - OR accumulates any non-zero bits across all comparisons
 * - Final result: 0 means all bytes matched, non-zero means difference found
 */
bool vpn_memeq(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;

    /*
     * This loop ALWAYS runs exactly 'len' iterations.
     * No early exit. No branches dependent on data values.
     * An attacker measuring execution time learns nothing about
     * where (or if) the buffers differ.
     */
    while (len--) {
        diff |= *pa++ ^ *pb++;
    }

    /*
     * Convert to boolean: 0 -> true (equal), non-zero -> false (different)
     *
     * Note: We use !! to normalize to 0 or 1, then invert.
     * diff == 0  ->  !0 = 1  ->  true (equal)
     * diff != 0  ->  !1 = 0  ->  false (different)
     */
    return diff == 0;
}

/*
 * vpn_memcpy - Copy memory
 *
 * Simple wrapper around standard memcpy. We could add debug checks here
 * for overlapping buffers, null pointers, etc.
 */
void *vpn_memcpy(void *dst, const void *src, size_t len)
{
    return memcpy(dst, src, len);
}

/*
 * vpn_memxor - XOR two memory regions
 *
 * This is the fundamental operation of stream ciphers:
 *   ciphertext = plaintext XOR keystream
 *   plaintext = ciphertext XOR keystream  (same operation!)
 *
 * XOR is its own inverse: (A XOR B) XOR B = A
 * This is why encryption and decryption use the same code.
 */
void vpn_memxor(void *dst, const void *a, const void *b, size_t len)
{
    uint8_t *pd = (uint8_t *)dst;
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;

    /*
     * Simple byte-by-byte XOR. A production implementation might:
     * 1. Align pointers to 8-byte boundaries
     * 2. XOR 8 bytes at a time using uint64_t
     * 3. Handle remaining bytes individually
     *
     * For educational clarity, we keep it simple. The compiler
     * may vectorize this loop anyway with optimization enabled.
     */
    while (len--) {
        *pd++ = *pa++ ^ *pb++;
    }
}
