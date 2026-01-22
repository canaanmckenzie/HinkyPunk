/*
 * aead.c - ChaCha20-Poly1305 AEAD Implementation
 * ===============================================
 *
 * This implements the ChaCha20-Poly1305 AEAD construction from RFC 8439.
 * It's the same AEAD used by WireGuard, TLS 1.3, and many other protocols.
 *
 * CONSTRUCTION OVERVIEW:
 *
 *   ┌─────────────────────────────────────────────────────────────────┐
 *   │                     ChaCha20-Poly1305 AEAD                      │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │                                                                 │
 *   │   Key (256 bits) + Nonce (96 bits)                              │
 *   │           │                                                     │
 *   │           ▼                                                     │
 *   │   ┌──────────────┐                                              │
 *   │   │   ChaCha20   │ Block 0 ──► Poly1305 one-time key (32 bytes) │
 *   │   │              │ Block 1+ ──► Keystream for encryption        │
 *   │   └──────────────┘                                              │
 *   │                                                                 │
 *   │   Plaintext ─────XOR keystream────► Ciphertext                  │
 *   │                                                                 │
 *   │   ┌──────────────┐                                              │
 *   │   │   Poly1305   │ (AAD || pad || Ciphertext || pad || lens)    │
 *   │   │              │ ──────────────────────────► Tag (16 bytes)   │
 *   │   └──────────────┘                                              │
 *   │                                                                 │
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * KEY INSIGHT: ChaCha20 block 0 is used ONLY to derive the Poly1305 key.
 * Encryption starts at block 1. This ensures the Poly1305 key is never
 * reused (it's derived from unique nonce) and is independent of keystream.
 */

#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include "../util/memory.h"
#include <string.h>

/*
 * pad_to_16 - Calculate padding needed to reach 16-byte boundary
 *
 * Poly1305 in AEAD mode requires AAD and ciphertext to each be padded
 * to 16 bytes before computing the tag. This prevents ambiguity about
 * where AAD ends and ciphertext begins.
 *
 * Example: AAD of 20 bytes needs 12 bytes of padding to reach 32.
 */
static size_t pad_to_16(size_t len)
{
    return (16 - (len % 16)) % 16;
}

/*
 * write_u64_le - Write 64-bit value as little-endian bytes
 *
 * Used for encoding AAD and ciphertext lengths in the Poly1305 input.
 */
static void write_u64_le(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

/*
 * aead_encrypt - Encrypt and authenticate
 *
 * Algorithm (from RFC 8439):
 *
 * 1. poly_key = ChaCha20(key, nonce, counter=0)[0:32]
 * 2. ciphertext = ChaCha20(key, nonce, counter=1) XOR plaintext
 * 3. mac_data = AAD || pad(AAD) || ciphertext || pad(ciphertext) ||
 *               le64(AAD_len) || le64(ciphertext_len)
 * 4. tag = Poly1305(poly_key, mac_data)
 */
void aead_encrypt(uint8_t *ciphertext,
                  uint8_t tag[AEAD_TAG_SIZE],
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t *aad,
                  size_t aad_len,
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  const uint8_t key[CHACHA20_KEY_SIZE])
{
    uint8_t poly_key[POLY1305_KEY_SIZE];
    uint8_t block0[CHACHA20_BLOCK_SIZE];
    poly1305_ctx poly_ctx;
    uint8_t padding[16] = {0};  /* Zero padding */
    uint8_t lengths[16];
    size_t aad_padding, ct_padding;

    /*
     * STEP 1: Generate Poly1305 key from ChaCha20 block 0
     *
     * We generate a full 64-byte block but only use the first 32 bytes.
     * This ensures the Poly1305 key is derived from the nonce, making it
     * unique per message.
     */
    chacha20_block(block0, key, nonce, 0);
    vpn_memcpy(poly_key, block0, POLY1305_KEY_SIZE);
    vpn_memzero(block0, sizeof(block0));  /* Don't leave key material around */

    /*
     * STEP 2: Encrypt plaintext with ChaCha20, starting at counter 1
     *
     * Counter 0 was used for Poly1305 key. Encryption starts at counter 1.
     * This is critical - if we started at counter 0, we'd XOR plaintext
     * with the same bytes used as the Poly1305 key, which would be bad.
     */
    chacha20_xor(ciphertext, plaintext, plaintext_len, key, nonce, 1);

    /*
     * STEP 3: Compute authentication tag over AAD and ciphertext
     *
     * The input to Poly1305 is structured as:
     *   AAD || zeros_to_16_boundary || ciphertext || zeros_to_16_boundary ||
     *   le64(aad_len) || le64(ciphertext_len)
     *
     * This structure:
     *   - Authenticates AAD without encrypting it
     *   - Authenticates ciphertext (which authenticates plaintext)
     *   - Encodes lengths to prevent ambiguity and length extension attacks
     */
    poly1305_init(&poly_ctx, poly_key);

    /* Authenticate AAD with padding */
    if (aad_len > 0) {
        poly1305_update(&poly_ctx, aad, aad_len);
        aad_padding = pad_to_16(aad_len);
        if (aad_padding > 0) {
            poly1305_update(&poly_ctx, padding, aad_padding);
        }
    }

    /* Authenticate ciphertext with padding */
    if (plaintext_len > 0) {
        poly1305_update(&poly_ctx, ciphertext, plaintext_len);
        ct_padding = pad_to_16(plaintext_len);
        if (ct_padding > 0) {
            poly1305_update(&poly_ctx, padding, ct_padding);
        }
    }

    /* Authenticate lengths (as little-endian 64-bit values) */
    write_u64_le(lengths, aad_len);
    write_u64_le(lengths + 8, plaintext_len);
    poly1305_update(&poly_ctx, lengths, 16);

    /* Finalize tag */
    poly1305_finish(&poly_ctx, tag);

    /* Clean up sensitive data */
    vpn_memzero(poly_key, sizeof(poly_key));
    vpn_memzero(&poly_ctx, sizeof(poly_ctx));
}

/*
 * aead_decrypt - Verify and decrypt
 *
 * IMPORTANT: We verify BEFORE decrypting. This is the "Encrypt-then-MAC"
 * paradigm that makes AEAD secure against chosen-ciphertext attacks.
 *
 * If we decrypted first, an attacker could observe side effects of processing
 * malformed plaintext (timing, cache, error messages) and use those to mount
 * padding oracle or similar attacks.
 *
 * By verifying the tag first, we reject any tampered ciphertext without
 * ever processing it as plaintext.
 */
vpn_error_t aead_decrypt(uint8_t *plaintext,
                         const uint8_t *ciphertext,
                         size_t ciphertext_len,
                         const uint8_t tag[AEAD_TAG_SIZE],
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t nonce[CHACHA20_NONCE_SIZE],
                         const uint8_t key[CHACHA20_KEY_SIZE])
{
    uint8_t poly_key[POLY1305_KEY_SIZE];
    uint8_t block0[CHACHA20_BLOCK_SIZE];
    uint8_t computed_tag[POLY1305_TAG_SIZE];
    poly1305_ctx poly_ctx;
    uint8_t padding[16] = {0};
    uint8_t lengths[16];
    size_t aad_padding, ct_padding;
    vpn_error_t result = VPN_OK;

    /*
     * STEP 1: Generate Poly1305 key (same as encryption)
     */
    chacha20_block(block0, key, nonce, 0);
    vpn_memcpy(poly_key, block0, POLY1305_KEY_SIZE);
    vpn_memzero(block0, sizeof(block0));

    /*
     * STEP 2: Compute expected tag over AAD and ciphertext
     */
    poly1305_init(&poly_ctx, poly_key);

    if (aad_len > 0) {
        poly1305_update(&poly_ctx, aad, aad_len);
        aad_padding = pad_to_16(aad_len);
        if (aad_padding > 0) {
            poly1305_update(&poly_ctx, padding, aad_padding);
        }
    }

    if (ciphertext_len > 0) {
        poly1305_update(&poly_ctx, ciphertext, ciphertext_len);
        ct_padding = pad_to_16(ciphertext_len);
        if (ct_padding > 0) {
            poly1305_update(&poly_ctx, padding, ct_padding);
        }
    }

    write_u64_le(lengths, aad_len);
    write_u64_le(lengths + 8, ciphertext_len);
    poly1305_update(&poly_ctx, lengths, 16);

    poly1305_finish(&poly_ctx, computed_tag);

    /*
     * STEP 3: Verify tag (constant-time comparison)
     *
     * This is the critical security check. If the tag doesn't match,
     * the ciphertext was modified, corrupted, or we have the wrong key.
     */
    if (!vpn_memeq(tag, computed_tag, POLY1305_TAG_SIZE)) {
        result = VPN_ERR_AUTH;
        goto cleanup;
    }

    /*
     * STEP 4: Tag verified, now decrypt
     *
     * Since we verified the tag, we know the ciphertext is exactly what
     * was encrypted. It's safe to decrypt.
     */
    chacha20_xor(plaintext, ciphertext, ciphertext_len, key, nonce, 1);

cleanup:
    vpn_memzero(poly_key, sizeof(poly_key));
    vpn_memzero(computed_tag, sizeof(computed_tag));
    vpn_memzero(&poly_ctx, sizeof(poly_ctx));

    return result;
}
