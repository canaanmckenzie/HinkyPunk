/*
 * aead.h - ChaCha20-Poly1305 Authenticated Encryption
 * ====================================================
 *
 * This module combines ChaCha20 and Poly1305 into an AEAD (Authenticated
 * Encryption with Associated Data) construction. This is what WireGuard
 * uses to encrypt tunnel traffic.
 *
 * WHAT IS AEAD?
 *
 * AEAD provides both confidentiality (encryption) AND integrity (authentication)
 * in a single operation. It's the modern standard for symmetric encryption.
 *
 *   Encryption: (plaintext, key, nonce, aad) -> (ciphertext, tag)
 *   Decryption: (ciphertext, tag, key, nonce, aad) -> plaintext OR error
 *
 * Where:
 *   - plaintext: Your secret message
 *   - ciphertext: The encrypted message (same length as plaintext)
 *   - key: 256-bit secret shared by sender and receiver
 *   - nonce: 96-bit value that must be unique per message with same key
 *   - aad: "Associated data" - authenticated but not encrypted (e.g., headers)
 *   - tag: 128-bit authentication tag proving integrity
 *
 * WHY AEAD MATTERS:
 *
 * Before AEAD, developers had to combine encryption and MAC themselves, often
 * getting it wrong:
 *
 *   WRONG: Encrypt-and-MAC (SSH style)
 *     - MAC(plaintext) might leak information about plaintext
 *
 *   WRONG: MAC-then-Encrypt (SSL style)
 *     - MAC verification requires decryption first, enabling padding oracles
 *
 *   RIGHT: Encrypt-then-MAC (IPsec style) or AEAD
 *     - Verify MAC first, only decrypt if valid
 *     - AEAD does this automatically and correctly
 *
 * ChaCha20-Poly1305 AEAD (RFC 8439):
 *
 * 1. Generate Poly1305 one-time key from ChaCha20 block 0
 * 2. Encrypt plaintext with ChaCha20 starting at block 1
 * 3. Authenticate (AAD || padding || ciphertext || padding || lengths) with Poly1305
 *
 * The padding and length encoding prevent length extension attacks and ensure
 * AAD and ciphertext boundaries are unambiguous.
 */

#ifndef VPN_AEAD_H
#define VPN_AEAD_H

#include "../types.h"

/*
 * aead_encrypt - Encrypt and authenticate data
 *
 * Encrypts plaintext and produces an authentication tag over both the
 * ciphertext and the additional authenticated data (AAD).
 *
 * @param ciphertext    Output buffer, must be at least plaintext_len bytes
 * @param tag           Output authentication tag (16 bytes)
 * @param plaintext     Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad           Additional authenticated data (may be NULL if aad_len is 0)
 * @param aad_len       Length of AAD
 * @param nonce         96-bit nonce (MUST be unique per key)
 * @param key           256-bit encryption key
 *
 * MEMORY LAYOUT:
 *   ciphertext can be the same pointer as plaintext (in-place encryption).
 *   tag must be a separate 16-byte buffer.
 *
 * TYPICAL USAGE (encrypting a network packet):
 *
 *   uint8_t key[32];        // Shared secret with peer
 *   uint8_t nonce[12];      // Packet counter (unique per packet)
 *   uint8_t header[20];     // IP header (don't encrypt, but authenticate)
 *   uint8_t payload[1400];  // Packet payload (encrypt and authenticate)
 *   uint8_t encrypted[1400];
 *   uint8_t tag[16];
 *
 *   aead_encrypt(encrypted, tag, payload, sizeof(payload),
 *                header, sizeof(header), nonce, key);
 *
 *   // Send: header || encrypted || tag
 */
void aead_encrypt(uint8_t *ciphertext,
                  uint8_t tag[AEAD_TAG_SIZE],
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t *aad,
                  size_t aad_len,
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  const uint8_t key[CHACHA20_KEY_SIZE]);

/*
 * aead_decrypt - Decrypt and verify data
 *
 * Verifies the authentication tag, then decrypts if valid. If the tag
 * doesn't match, returns an error and does NOT write to plaintext buffer.
 *
 * @param plaintext      Output buffer, must be at least ciphertext_len bytes
 * @param ciphertext     Data to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag            Authentication tag to verify
 * @param aad            Additional authenticated data (same as during encrypt)
 * @param aad_len        Length of AAD
 * @param nonce          Same nonce used during encryption
 * @param key            Same key used during encryption
 * @return               VPN_OK on success, VPN_ERR_AUTH if tag invalid
 *
 * SECURITY CRITICAL:
 *   - ALWAYS check the return value!
 *   - If return is not VPN_OK, the ciphertext was tampered with or corrupted
 *   - Never use plaintext from a failed decryption
 *
 * TYPICAL USAGE (receiving a network packet):
 *
 *   // Received: header || encrypted || tag
 *   if (aead_decrypt(payload, encrypted, encrypted_len, tag,
 *                    header, header_len, nonce, key) != VPN_OK) {
 *       // Authentication failed! Drop the packet.
 *       // Could be: tampering, corruption, replay, wrong key
 *       return;
 *   }
 *   // payload is now safe to use
 */
vpn_error_t aead_decrypt(uint8_t *plaintext,
                         const uint8_t *ciphertext,
                         size_t ciphertext_len,
                         const uint8_t tag[AEAD_TAG_SIZE],
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t nonce[CHACHA20_NONCE_SIZE],
                         const uint8_t key[CHACHA20_KEY_SIZE]);

#endif /* VPN_AEAD_H */
