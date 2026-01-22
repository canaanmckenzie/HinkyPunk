/*
 * blake2s.h - BLAKE2s Cryptographic Hash Function
 * ================================================
 *
 * BLAKE2s is a fast cryptographic hash function designed as a replacement
 * for MD5 and SHA-1. It's used in WireGuard for key derivation (HKDF),
 * MAC construction, and the Noise protocol handshake.
 *
 * WHAT IS A HASH FUNCTION?
 *
 * A cryptographic hash function takes arbitrary-length input and produces
 * a fixed-length "digest" (also called hash or fingerprint). Properties:
 *
 * 1. DETERMINISTIC: Same input always produces same output
 * 2. ONE-WAY: Given hash(x), computationally infeasible to find x
 * 3. COLLISION-RESISTANT: Hard to find x and y where hash(x) = hash(y)
 * 4. AVALANCHE EFFECT: Small input change causes drastic output change
 *
 * WHY BLAKE2s?
 *
 * 1. SPEED: Faster than MD5, SHA-1, SHA-2, and SHA-3 on most platforms
 * 2. SECURITY: Based on ChaCha, inherits its security properties
 * 3. SIMPLICITY: Easy to implement correctly
 * 4. VERSATILITY: Built-in support for keying, personalization, tree hashing
 *
 * BLAKE2s vs BLAKE2b:
 *
 * - BLAKE2s: Optimized for 8-32 bit platforms, 256-bit max output
 * - BLAKE2b: Optimized for 64-bit platforms, 512-bit max output
 *
 * WireGuard uses BLAKE2s because the 256-bit output is sufficient for
 * symmetric keys and it performs well on all platforms including embedded.
 *
 * HOW IT WORKS:
 *
 * BLAKE2s processes input in 64-byte blocks through a compression function.
 * The compression function is based on a modified ChaCha quarter-round,
 * working on a 4x4 matrix of 32-bit words.
 *
 * Internal state:
 *   - 8 chaining value words (h0-h7): accumulated hash state
 *   - 2 counter words (t0, t1): bytes processed so far
 *   - 2 finalization words (f0, f1): mark final block
 *
 * The compression function mixes the chaining value with the message block
 * and constants, then folds the result back into the chaining value.
 *
 * KEYED HASHING (MAC):
 *
 * BLAKE2s can be used as a MAC by providing a key during initialization.
 * This is more efficient than HMAC because no double-hashing is needed.
 *
 *   tag = BLAKE2s(key, message)
 *
 * This provides authenticity: only someone with the key can produce or
 * verify the tag.
 */

#ifndef VPN_BLAKE2S_H
#define VPN_BLAKE2S_H

#include "../types.h"

/*
 * BLAKE2s context structure
 *
 * Holds the state for incremental hashing. You can add data in chunks
 * with blake2s_update, then get the final hash with blake2s_final.
 */
typedef struct {
    uint32_t h[8];         /* Chaining value (hash state) */
    uint32_t t[2];         /* Counter: total bytes processed */
    uint32_t f[2];         /* Finalization flags */
    uint8_t  buf[64];      /* Input buffer (one block) */
    size_t   buflen;       /* Bytes in buffer */
    size_t   outlen;       /* Desired output length */
} blake2s_ctx;

/*
 * blake2s_init - Initialize for hashing (no key)
 *
 * @param ctx      Context to initialize
 * @param outlen   Desired hash length in bytes (1-32)
 * @return         VPN_OK on success
 *
 * EXAMPLE:
 *   blake2s_ctx ctx;
 *   blake2s_init(&ctx, 32);  // 256-bit hash
 */
vpn_error_t blake2s_init(blake2s_ctx *ctx, size_t outlen);

/*
 * blake2s_init_key - Initialize for keyed hashing (MAC)
 *
 * @param ctx      Context to initialize
 * @param outlen   Desired hash length in bytes (1-32)
 * @param key      Secret key
 * @param keylen   Key length in bytes (1-32)
 * @return         VPN_OK on success
 *
 * EXAMPLE:
 *   uint8_t key[32] = {...};
 *   blake2s_ctx ctx;
 *   blake2s_init_key(&ctx, 32, key, 32);
 */
vpn_error_t blake2s_init_key(blake2s_ctx *ctx, size_t outlen,
                             const void *key, size_t keylen);

/*
 * blake2s_update - Add data to hash
 *
 * Can be called multiple times to hash data incrementally.
 *
 * @param ctx   Initialized context
 * @param in    Data to hash
 * @param inlen Length of data
 * @return      VPN_OK on success
 */
vpn_error_t blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);

/*
 * blake2s_final - Finalize and output hash
 *
 * @param ctx   Context with all data added
 * @param out   Output buffer (must be at least outlen bytes)
 * @return      VPN_OK on success
 */
vpn_error_t blake2s_final(blake2s_ctx *ctx, void *out);

/*
 * blake2s - One-shot hashing (no key)
 *
 * Convenience function for hashing all data at once.
 *
 * @param out      Output buffer
 * @param outlen   Desired hash length (1-32)
 * @param in       Data to hash
 * @param inlen    Length of data
 * @return         VPN_OK on success
 *
 * EXAMPLE:
 *   uint8_t hash[32];
 *   blake2s(hash, 32, data, data_len);
 */
vpn_error_t blake2s(void *out, size_t outlen, const void *in, size_t inlen);

/*
 * blake2s_keyed - One-shot keyed hashing (MAC)
 *
 * @param out      Output buffer
 * @param outlen   Desired hash length (1-32)
 * @param in       Data to hash
 * @param inlen    Length of data
 * @param key      Secret key
 * @param keylen   Key length (1-32)
 * @return         VPN_OK on success
 */
vpn_error_t blake2s_keyed(void *out, size_t outlen,
                          const void *in, size_t inlen,
                          const void *key, size_t keylen);

/*
 * ===========================================================================
 * HMAC-BLAKE2s (for HKDF compatibility)
 * ===========================================================================
 *
 * While BLAKE2s has built-in keying, some protocols (like Noise) expect
 * HMAC construction. We provide HMAC-BLAKE2s for compatibility.
 */

/*
 * hmac_blake2s - HMAC using BLAKE2s
 *
 * Computes HMAC-BLAKE2s(key, data).
 *
 * @param out      Output buffer (32 bytes for BLAKE2s-256)
 * @param key      HMAC key
 * @param keylen   Key length
 * @param in       Data to authenticate
 * @param inlen    Data length
 */
void hmac_blake2s(uint8_t out[BLAKE2S_HASH_SIZE],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *in, size_t inlen);

/*
 * ===========================================================================
 * HKDF-BLAKE2s (for key derivation)
 * ===========================================================================
 *
 * HKDF (HMAC-based Key Derivation Function) is used to derive multiple
 * keys from a single shared secret. WireGuard uses HKDF-BLAKE2s.
 */

/*
 * hkdf_blake2s - Derive keys using HKDF
 *
 * @param out1     First output key (32 bytes)
 * @param out2     Second output key (32 bytes, or NULL if not needed)
 * @param out3     Third output key (32 bytes, or NULL if not needed)
 * @param chaining_key  HKDF chaining key (32 bytes)
 * @param input    Input keying material
 * @param input_len Length of input
 *
 * This is a simplified HKDF that outputs 1-3 keys of 32 bytes each,
 * matching WireGuard's usage pattern.
 */
void hkdf_blake2s(uint8_t out1[BLAKE2S_HASH_SIZE],
                  uint8_t *out2,  /* May be NULL */
                  uint8_t *out3,  /* May be NULL */
                  const uint8_t chaining_key[BLAKE2S_HASH_SIZE],
                  const uint8_t *input, size_t input_len);

#endif /* VPN_BLAKE2S_H */
