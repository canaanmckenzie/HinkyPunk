/*
 * chacha20.h - ChaCha20 Stream Cipher
 * ====================================
 *
 * ChaCha20 is a stream cipher designed by Daniel J. Bernstein. It's the
 * encryption component of ChaCha20-Poly1305, the AEAD cipher used by WireGuard.
 *
 * WHAT IS A STREAM CIPHER?
 *
 * A stream cipher generates a "keystream" - a long sequence of random-looking
 * bytes derived from a key and nonce. To encrypt, you XOR plaintext with keystream.
 * To decrypt, you XOR ciphertext with the same keystream. Simple!
 *
 *   Encryption: ciphertext = plaintext XOR keystream
 *   Decryption: plaintext = ciphertext XOR keystream
 *
 * WHY CHACHA20?
 *
 * 1. SPEED: Faster than AES on platforms without hardware AES support
 * 2. SECURITY: No known attacks after 14+ years of analysis
 * 3. SIMPLICITY: Easy to implement correctly (unlike AES)
 * 4. TIMING SAFETY: No table lookups that could leak via cache timing
 *
 * HOW IT WORKS (high level):
 *
 * ChaCha20 builds a 512-bit (64-byte) state from:
 *   - 128 bits of constant ("expand 32-byte k")
 *   - 256 bits of key (your secret)
 *   - 32 bits of counter (increments per block)
 *   - 96 bits of nonce (unique per message)
 *
 * It then scrambles this state through 20 rounds of "quarter-round" operations,
 * producing 64 bytes of keystream. Increment counter, repeat for more keystream.
 *
 * NONCE REQUIREMENTS:
 *
 * A nonce ("number used once") must NEVER be reused with the same key.
 * If you encrypt two messages with the same key and nonce:
 *   C1 = P1 XOR keystream
 *   C2 = P2 XOR keystream
 *   C1 XOR C2 = P1 XOR P2  <-- Attacker can XOR ciphertexts to eliminate keystream!
 *
 * WireGuard uses a counter as the nonce, which naturally ensures uniqueness.
 */

#ifndef VPN_CHACHA20_H
#define VPN_CHACHA20_H

#include "../types.h"

/*
 * ChaCha20 context structure
 *
 * Holds the cipher state between operations. For streaming encryption,
 * you can encrypt data in chunks by maintaining this context.
 *
 * The state is a 4x4 matrix of 32-bit words:
 *
 *   [ constant  constant  constant  constant  ]
 *   [ key       key       key       key       ]
 *   [ key       key       key       key       ]
 *   [ counter   nonce     nonce     nonce     ]
 *
 * Total: 16 x 32-bit = 512 bits = 64 bytes
 */
typedef struct {
    uint32_t state[16];     /* The 512-bit state matrix */
    uint8_t keystream[64];  /* Current keystream block */
    size_t keystream_pos;   /* Position within keystream block */
} chacha20_ctx;

/*
 * chacha20_init - Initialize ChaCha20 context
 *
 * Sets up the internal state from key, nonce, and initial counter.
 *
 * @param ctx       Context to initialize
 * @param key       256-bit (32-byte) secret key
 * @param nonce     96-bit (12-byte) nonce (IETF variant)
 * @param counter   Initial block counter (usually 0 or 1)
 *
 * SECURITY: Key must be random and secret. Nonce must be unique per key.
 */
void chacha20_init(chacha20_ctx *ctx,
                   const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE],
                   uint32_t counter);

/*
 * chacha20_encrypt - Encrypt or decrypt data
 *
 * XORs input with keystream to produce output. Since XOR is symmetric,
 * this function works for both encryption and decryption.
 *
 * @param ctx   Initialized context (modified: counter advances)
 * @param out   Output buffer (can be same as in for in-place operation)
 * @param in    Input buffer
 * @param len   Number of bytes to process
 *
 * NOTE: You can call this multiple times with the same context to process
 * data in chunks. The context tracks position within the keystream.
 */
void chacha20_encrypt(chacha20_ctx *ctx,
                      uint8_t *out,
                      const uint8_t *in,
                      size_t len);

/*
 * chacha20_block - Generate one keystream block
 *
 * Generates exactly 64 bytes of keystream. Lower-level function used
 * internally and for Poly1305 key generation.
 *
 * @param out       Output buffer (64 bytes)
 * @param key       256-bit key
 * @param nonce     96-bit nonce
 * @param counter   Block counter
 */
void chacha20_block(uint8_t out[CHACHA20_BLOCK_SIZE],
                    const uint8_t key[CHACHA20_KEY_SIZE],
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint32_t counter);

/*
 * chacha20_xor - Simple one-shot encryption/decryption
 *
 * Convenience function when you have all data available at once.
 * Creates temporary context, encrypts, and cleans up.
 *
 * @param out       Output buffer
 * @param in        Input buffer
 * @param len       Data length
 * @param key       256-bit key
 * @param nonce     96-bit nonce
 * @param counter   Initial counter (usually 0 or 1)
 */
void chacha20_xor(uint8_t *out,
                  const uint8_t *in,
                  size_t len,
                  const uint8_t key[CHACHA20_KEY_SIZE],
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  uint32_t counter);

#endif /* VPN_CHACHA20_H */
