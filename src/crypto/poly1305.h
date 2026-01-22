/*
 * poly1305.h - Poly1305 Message Authentication Code
 * ==================================================
 *
 * Poly1305 is a fast, one-time authenticator designed by Daniel J. Bernstein.
 * It produces a 128-bit (16-byte) tag that verifies message integrity.
 *
 * WHAT IS A MAC (Message Authentication Code)?
 *
 * A MAC is like a digital signature that uses symmetric keys instead of
 * public-key cryptography. Given a message and a key, it produces a short
 * "tag" that proves:
 *   1. The message hasn't been modified (integrity)
 *   2. The message came from someone who knows the key (authenticity)
 *
 * Without knowing the key, an attacker cannot:
 *   - Create a valid tag for a new message (forgery)
 *   - Modify a message without invalidating its tag (tampering)
 *
 * WHY POLY1305?
 *
 * 1. SPEED: Extremely fast on modern processors (often faster than HMAC-SHA256)
 * 2. SECURITY: Provably secure when used correctly (one-time key per message)
 * 3. SIMPLICITY: Based on polynomial evaluation, easy to implement
 * 4. TIMING SAFETY: Can be implemented without secret-dependent branches
 *
 * HOW IT WORKS (simplified):
 *
 * Poly1305 treats the message as a polynomial and evaluates it at a secret point.
 *
 * Given:
 *   - A message M broken into 16-byte blocks: m[1], m[2], ..., m[n]
 *   - A secret point r (part of the key)
 *   - A secret pad s (other part of the key)
 *
 * The tag is computed as:
 *   tag = ((m[1] * r^n + m[2] * r^(n-1) + ... + m[n] * r) mod (2^130 - 5)) + s
 *
 * All arithmetic is done modulo a prime (2^130 - 5), which has special properties
 * that make computation fast.
 *
 * CRITICAL SECURITY REQUIREMENT:
 *
 * Poly1305 is a ONE-TIME authenticator. The key (r, s) must NEVER be reused.
 * If you authenticate two messages with the same key:
 *   - An attacker can compute r by solving linear equations
 *   - Once they know r, they can forge tags for any message
 *
 * In ChaCha20-Poly1305, we derive a fresh Poly1305 key for each message from
 * ChaCha20 keystream (block 0), ensuring one-time use automatically.
 */

#ifndef VPN_POLY1305_H
#define VPN_POLY1305_H

#include "../types.h"

/*
 * Poly1305 context structure
 *
 * Holds intermediate state during MAC computation. Allows processing
 * large messages in chunks.
 *
 * Internal state uses larger integers for modular arithmetic.
 * The actual algorithm works with 130-bit numbers modulo (2^130 - 5).
 */
typedef struct {
    uint32_t r[5];      /* Secret value 'r' (clamped, in radix 2^26) */
    uint32_t h[5];      /* Accumulator 'h' (current hash state) */
    uint32_t pad[4];    /* Secret pad 's' (added at the end) */
    uint8_t buffer[16]; /* Partial block buffer */
    size_t buffer_len;  /* Bytes in partial block */
    bool finalized;     /* Has poly1305_finish been called? */
} poly1305_ctx;

/*
 * poly1305_init - Initialize Poly1305 context
 *
 * @param ctx   Context to initialize
 * @param key   256-bit (32-byte) one-time key
 *
 * The 32-byte key is split into:
 *   - First 16 bytes: 'r' value (with "clamping" applied)
 *   - Last 16 bytes: 's' pad value
 *
 * CLAMPING: Certain bits of 'r' are cleared for security:
 *   - r[3], r[7], r[11], r[15] are cleared to ensure r < 2^128
 *   - Some bits are cleared to make r divisible by 4 (prevents timing leaks)
 *
 * SECURITY: This key must be used for exactly ONE message.
 * In ChaCha20-Poly1305, we generate this from ChaCha20 block 0.
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE]);

/*
 * poly1305_update - Process message data
 *
 * Adds data to the MAC computation. Can be called multiple times
 * to process a message in chunks.
 *
 * @param ctx   Initialized context
 * @param data  Data to process
 * @param len   Length of data in bytes
 *
 * EXAMPLE:
 *   poly1305_init(&ctx, key);
 *   poly1305_update(&ctx, header, header_len);
 *   poly1305_update(&ctx, body, body_len);
 *   poly1305_finish(&ctx, tag);
 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t len);

/*
 * poly1305_finish - Finalize and output the tag
 *
 * Processes any remaining partial block, performs final reduction,
 * and adds the pad to produce the 16-byte tag.
 *
 * @param ctx   Context with all message data processed
 * @param tag   Output buffer for 16-byte tag
 *
 * After calling finish, the context should not be reused (reinitialize
 * with a new key for a new message).
 */
void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE]);

/*
 * poly1305_auth - One-shot MAC computation
 *
 * Convenience function when you have the entire message at once.
 *
 * @param tag   Output buffer for 16-byte tag
 * @param data  Message to authenticate
 * @param len   Message length
 * @param key   256-bit one-time key
 */
void poly1305_auth(uint8_t tag[POLY1305_TAG_SIZE],
                   const uint8_t *data,
                   size_t len,
                   const uint8_t key[POLY1305_KEY_SIZE]);

/*
 * poly1305_verify - Verify a tag (constant-time)
 *
 * Computes the expected tag and compares it to the provided tag
 * in constant time to prevent timing attacks.
 *
 * @param tag   Tag to verify
 * @param data  Message that was authenticated
 * @param len   Message length
 * @param key   The same key used to create the tag
 * @return      true if valid, false if invalid
 *
 * SECURITY: Always use this function instead of computing the tag
 * and comparing manually (which might use non-constant-time comparison).
 */
bool poly1305_verify(const uint8_t tag[POLY1305_TAG_SIZE],
                     const uint8_t *data,
                     size_t len,
                     const uint8_t key[POLY1305_KEY_SIZE]);

#endif /* VPN_POLY1305_H */
