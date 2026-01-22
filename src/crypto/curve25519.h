/*
 * curve25519.h - Elliptic Curve Diffie-Hellman Key Exchange
 * ==========================================================
 *
 * Curve25519 is an elliptic curve designed by Daniel J. Bernstein for fast,
 * secure key agreement. It's used in WireGuard, Signal, SSH, and many other
 * protocols for establishing shared secrets over insecure channels.
 *
 * WHAT IS DIFFIE-HELLMAN?
 *
 * Diffie-Hellman lets two parties create a shared secret even when communicating
 * over a public channel. Neither party reveals their private key, but both
 * derive the same shared secret.
 *
 *   Alice                              Bob
 *   ─────                              ───
 *   private_a (secret)                 private_b (secret)
 *   public_a = g^private_a             public_b = g^private_b
 *
 *        ────── public_a ──────►
 *        ◄────── public_b ──────
 *
 *   shared = public_b^private_a    shared = public_a^private_b
 *          = (g^private_b)^private_a     = (g^private_a)^private_b
 *          = g^(private_a * private_b)   = g^(private_a * private_b)
 *
 * Both compute the same value! An eavesdropper only sees public_a and public_b,
 * and cannot compute the shared secret without knowing a private key.
 *
 * WHY ELLIPTIC CURVES?
 *
 * Traditional DH uses modular arithmetic in a finite field. Elliptic Curve DH
 * (ECDH) uses points on an elliptic curve instead. Benefits:
 *
 *   - SMALLER KEYS: 256-bit ECC ≈ 3072-bit RSA security
 *   - FASTER: Less computation for the same security level
 *   - SIMPLER: Fewer parameters to get wrong
 *
 * WHY CURVE25519 SPECIFICALLY?
 *
 * 1. SPEED: One of the fastest curves at its security level
 * 2. SECURITY: Designed to resist timing attacks and implementation errors
 * 3. SIMPLICITY: Uses Montgomery curves which have simple, fast formulas
 * 4. NO SPECIAL CASES: Accepts any 32-byte string as a valid public key
 *
 * THE CURVE:
 *
 *   y² = x³ + 486662x² + x  (over the field F_p, where p = 2²⁵⁵ - 19)
 *
 * The name "25519" comes from the prime: 2²⁵⁵ - 19.
 *
 * HOW WE USE IT:
 *
 * 1. Generate random 32-byte private key (with some bits fixed)
 * 2. Compute public key = private_key * base_point
 * 3. To compute shared secret: shared = their_public * my_private
 */

#ifndef VPN_CURVE25519_H
#define VPN_CURVE25519_H

#include "../types.h"

/*
 * curve25519_keygen - Generate a key pair
 *
 * Given a random 32-byte private key, computes the corresponding public key.
 *
 * @param public_key    Output: 32-byte public key
 * @param private_key   Input: 32-byte random private key
 *
 * PRIVATE KEY REQUIREMENTS:
 *   The private key should be 32 random bytes from a cryptographically secure
 *   random number generator. The function will "clamp" it internally:
 *     - Clear bits 0, 1, 2 (make divisible by 8)
 *     - Clear bit 255 (ensure < 2^255)
 *     - Set bit 254 (ensure >= 2^254)
 *
 *   Clamping doesn't weaken security; it prevents implementation bugs and
 *   ensures all private keys produce valid results.
 *
 * EXAMPLE:
 *   uint8_t private_key[32], public_key[32];
 *   get_random_bytes(private_key, 32);  // From secure RNG
 *   curve25519_keygen(public_key, private_key);
 *   // Publish public_key, keep private_key secret
 */
void curve25519_keygen(uint8_t public_key[CURVE25519_KEY_SIZE],
                       const uint8_t private_key[CURVE25519_KEY_SIZE]);

/*
 * curve25519_shared - Compute shared secret via ECDH
 *
 * Given your private key and their public key, computes a shared secret.
 * Both parties compute the same secret (see DH explanation above).
 *
 * @param shared        Output: 32-byte shared secret
 * @param their_public  Their public key
 * @param my_private    Your private key
 * @return              VPN_OK on success, error if public key invalid
 *
 * SECURITY:
 *   The raw shared secret should NOT be used directly as an encryption key.
 *   Pass it through a key derivation function (KDF) like HKDF or BLAKE2.
 *   WireGuard uses the shared secret as input to the Noise protocol's
 *   HKDF construction.
 *
 *   The result is all-zeros if the peer's public key is a "small subgroup"
 *   point (malicious). Real implementations should check for this.
 *
 * EXAMPLE:
 *   uint8_t shared[32];
 *   curve25519_shared(shared, peer_public_key, my_private_key);
 *   // Now use shared in a KDF to derive encryption keys
 */
vpn_error_t curve25519_shared(uint8_t shared[CURVE25519_SHARED_SIZE],
                              const uint8_t their_public[CURVE25519_KEY_SIZE],
                              const uint8_t my_private[CURVE25519_KEY_SIZE]);

/*
 * curve25519_clamp - Clamp a private key
 *
 * Applies the standard Curve25519 clamping to a private key:
 *   - Clear bits 0, 1, 2 (lowest 3 bits of first byte)
 *   - Clear bit 255 (highest bit of last byte)
 *   - Set bit 254 (second-highest bit of last byte)
 *
 * This is done automatically in keygen and shared, but exposed
 * for compatibility with protocols that expect clamped keys.
 *
 * @param key   Key to clamp (modified in place)
 */
void curve25519_clamp(uint8_t key[CURVE25519_KEY_SIZE]);

#endif /* VPN_CURVE25519_H */
