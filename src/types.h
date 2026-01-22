/*
 * types.h - Common Type Definitions for VPN Implementation
 * =========================================================
 *
 * This header defines the fundamental types used throughout our VPN.
 * We use fixed-width integers for cryptographic operations because:
 *
 * 1. PORTABILITY: A uint32_t is always 32 bits, whether you're on a
 *    Raspberry Pi or a server. The standard 'int' might be 16, 32, or
 *    64 bits depending on the platform.
 *
 * 2. SECURITY: Cryptographic algorithms are specified in terms of exact
 *    bit widths. Using the wrong size can break the math or create
 *    vulnerabilities.
 *
 * 3. NETWORK PROTOCOLS: When we send data over the wire, both sides must
 *    agree on exact sizes. Fixed-width types guarantee this.
 *
 * LEARNING NOTE: WireGuard and most modern crypto code uses these types
 * extensively. Get comfortable with uint8_t, uint32_t, uint64_t.
 */

#ifndef VPN_TYPES_H
#define VPN_TYPES_H

#include <stdint.h>   /* uint8_t, uint32_t, uint64_t, etc. */
#include <stddef.h>   /* size_t, NULL */
#include <stdbool.h>  /* bool, true, false (C99) */

/*
 * ---------------------------------------------------------------------------
 * Cryptographic Constants
 * ---------------------------------------------------------------------------
 *
 * These sizes come directly from the algorithms we're implementing:
 * - ChaCha20: 256-bit key (32 bytes), 96-bit nonce (12 bytes)
 * - Poly1305: 128-bit tag (16 bytes)
 * - Curve25519: 256-bit keys and shared secrets (32 bytes)
 * - BLAKE2s: 256-bit output (32 bytes)
 *
 * WireGuard uses these exact algorithms, chosen for their security,
 * speed, and resistance to timing attacks.
 */

#define CHACHA20_KEY_SIZE       32  /* 256 bits */
#define CHACHA20_NONCE_SIZE     12  /* 96 bits (IETF variant) */
#define CHACHA20_BLOCK_SIZE     64  /* 512 bits */

#define POLY1305_KEY_SIZE       32  /* 256 bits (one-time key) */
#define POLY1305_TAG_SIZE       16  /* 128 bits */

#define CURVE25519_KEY_SIZE     32  /* 256 bits */
#define CURVE25519_SHARED_SIZE  32  /* 256 bits */

#define BLAKE2S_HASH_SIZE       32  /* 256 bits */
#define BLAKE2S_BLOCK_SIZE      64  /* 512 bits */

/*
 * AEAD (Authenticated Encryption with Associated Data) combines encryption
 * and authentication. ChaCha20-Poly1305 is the AEAD we use:
 * - ChaCha20 encrypts the data
 * - Poly1305 generates an authentication tag
 * The tag lets us detect if anyone tampered with the ciphertext.
 */
#define AEAD_TAG_SIZE           POLY1305_TAG_SIZE

/*
 * ---------------------------------------------------------------------------
 * Network Constants
 * ---------------------------------------------------------------------------
 */

#define VPN_DEFAULT_PORT        51820  /* Same as WireGuard */
#define VPN_MAX_PACKET_SIZE     65535  /* Maximum UDP payload */
#define VPN_MTU                 1420   /* Default MTU for tunnel */

/*
 * ---------------------------------------------------------------------------
 * Error Codes
 * ---------------------------------------------------------------------------
 *
 * We use negative numbers for errors (Unix convention). This allows functions
 * to return positive values for success (like byte counts) and negative for
 * errors. Zero typically means "success with nothing to report."
 */

typedef enum {
    VPN_OK              =  0,   /* Success */
    VPN_ERR_GENERIC     = -1,   /* Unspecified error */
    VPN_ERR_NOMEM       = -2,   /* Memory allocation failed */
    VPN_ERR_INVALID     = -3,   /* Invalid argument */
    VPN_ERR_CRYPTO      = -4,   /* Cryptographic operation failed */
    VPN_ERR_AUTH        = -5,   /* Authentication failed (bad MAC) */
    VPN_ERR_NETWORK     = -6,   /* Network operation failed */
    VPN_ERR_TIMEOUT     = -7,   /* Operation timed out */
    VPN_ERR_PEER        = -8,   /* Peer-related error */
    VPN_ERR_CONFIG      = -9,   /* Configuration error */
} vpn_error_t;

/*
 * ---------------------------------------------------------------------------
 * Helper Macros
 * ---------------------------------------------------------------------------
 */

/*
 * ARRAY_SIZE: Calculate number of elements in a static array.
 * This is a common idiom in C. sizeof(arr) gives total bytes,
 * sizeof(arr[0]) gives bytes per element. Division = element count.
 *
 * WARNING: Only works on actual arrays, not pointers!
 *   int arr[10];      ARRAY_SIZE(arr) = 10  ✓
 *   int *ptr = arr;   ARRAY_SIZE(ptr) = WRONG (size of pointer / size of int)
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * MIN/MAX: Standard minimum/maximum macros.
 * The do-while and statement-expression forms prevent common macro pitfalls.
 */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*
 * UNUSED: Silence compiler warnings about unused parameters.
 * Useful when implementing interfaces where you don't need all arguments.
 */
#define UNUSED(x) ((void)(x))

/*
 * ---------------------------------------------------------------------------
 * Compiler Hints
 * ---------------------------------------------------------------------------
 *
 * These help the compiler optimize and catch bugs.
 */

#ifdef __GNUC__
    /* Function never returns (like exit() or abort()) */
    #define NORETURN __attribute__((noreturn))

    /* Warn if return value is ignored */
    #define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

    /* Function has no side effects, result depends only on arguments */
    #define PURE __attribute__((pure))

    /* Hint that condition is likely/unlikely (for branch prediction) */
    #define LIKELY(x)   __builtin_expect(!!(x), 1)
    #define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
    #define NORETURN
    #define WARN_UNUSED_RESULT
    #define PURE
    #define LIKELY(x)   (x)
    #define UNLIKELY(x) (x)
#endif

#endif /* VPN_TYPES_H */
