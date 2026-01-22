/*
 * noise.c - Noise Protocol Framework Implementation
 * ==================================================
 *
 * This implements the Noise IK handshake pattern used by WireGuard.
 * Read noise.h for the conceptual overview; this file focuses on implementation.
 *
 * IK PATTERN EXECUTION:
 *
 * Initiator sends:
 *   1. Ephemeral public key (32 bytes, plaintext)
 *   2. MixKey(DH(e, rs))              -- es: ephemeral-static
 *   3. MixHash(encrypted static key)  -- s encrypted with current key
 *   4. MixKey(DH(s, rs))              -- ss: static-static
 *   5. Encrypted timestamp            -- Proves liveness
 *
 * Responder receives, then sends:
 *   1. Ephemeral public key (32 bytes, plaintext)
 *   2. MixKey(DH(e, re))              -- ee: ephemeral-ephemeral
 *   3. MixKey(DH(s, re))              -- se: static-ephemeral (responder's s)
 *   4. Encrypted empty payload        -- Proves completion
 *
 * After this, both derive identical transport keys from the final state.
 *
 * REFERENCE: Noise Protocol Specification (https://noiseprotocol.org/noise.html)
 */

#include "noise.h"
#include "../crypto/chacha20.h"
#include "../crypto/poly1305.h"
#include "../crypto/aead.h"
#include "../crypto/curve25519.h"
#include "../crypto/blake2s.h"
#include "../util/memory.h"
#include "../util/random.h"
#include <string.h>
#include <time.h>

/*
 * ===========================================================================
 * Helpers
 * ===========================================================================
 */

/*
 * Generate ephemeral key pair
 *
 * Uses platform-native CSPRNG (BCryptGenRandom on Windows,
 * getrandom/arc4random on Unix) to generate cryptographically
 * secure random bytes for the private key.
 */
static vpn_error_t generate_ephemeral_keypair(uint8_t private_key[32], uint8_t public_key[32])
{
    vpn_error_t err;

    /*
     * Generate 32 random bytes for private key using CSPRNG.
     * The random bytes are clamped by curve25519_keygen's internal
     * operations to ensure they're valid Curve25519 scalars.
     */
    err = vpn_random_bytes(private_key, 32);
    if (err != VPN_OK) {
        return err;
    }

    /* Derive public key from private key */
    curve25519_keygen(public_key, private_key);

    return VPN_OK;
}

/*
 * Get TAI64N timestamp
 *
 * TAI64N is 8 bytes of seconds since 1970-01-01 00:00:10 TAI (offset by 2^62),
 * followed by 4 bytes of nanoseconds.
 *
 * For simplicity, we use Unix time (not technically TAI but close enough).
 */
static void get_timestamp(uint8_t ts[NOISE_TIMESTAMP_SIZE])
{
    uint64_t secs = (uint64_t)time(NULL) + 0x4000000000000000ULL;  /* TAI64 offset */
    uint32_t nsecs = 0;  /* We don't have nanosecond precision in standard C */

    /* Big-endian encoding */
    ts[0] = (uint8_t)(secs >> 56);
    ts[1] = (uint8_t)(secs >> 48);
    ts[2] = (uint8_t)(secs >> 40);
    ts[3] = (uint8_t)(secs >> 32);
    ts[4] = (uint8_t)(secs >> 24);
    ts[5] = (uint8_t)(secs >> 16);
    ts[6] = (uint8_t)(secs >> 8);
    ts[7] = (uint8_t)(secs);
    ts[8] = (uint8_t)(nsecs >> 24);
    ts[9] = (uint8_t)(nsecs >> 16);
    ts[10] = (uint8_t)(nsecs >> 8);
    ts[11] = (uint8_t)(nsecs);
}

/*
 * Convert nonce counter to 12-byte nonce for AEAD
 *
 * The counter goes in the last 8 bytes, little-endian.
 * First 4 bytes are zero.
 */
static void nonce_to_bytes(uint8_t nonce[12], uint64_t n)
{
    vpn_memzero(nonce, 4);
    nonce[4]  = (uint8_t)(n);
    nonce[5]  = (uint8_t)(n >> 8);
    nonce[6]  = (uint8_t)(n >> 16);
    nonce[7]  = (uint8_t)(n >> 24);
    nonce[8]  = (uint8_t)(n >> 32);
    nonce[9]  = (uint8_t)(n >> 40);
    nonce[10] = (uint8_t)(n >> 48);
    nonce[11] = (uint8_t)(n >> 56);
}

/*
 * ===========================================================================
 * Symmetric State Operations
 * ===========================================================================
 */

void noise_init_symmetric(noise_symmetric_state *state)
{
    /*
     * Initialize h with protocol name:
     *
     * If len(protocol_name) <= HASHLEN:
     *   h = protocol_name || zeros
     * Else:
     *   h = HASH(protocol_name)
     *
     * For "Noise_IK_25519_ChaChaPoly_BLAKE2s" (36 bytes > 32):
     *   h = BLAKE2s(protocol_name)
     */
    blake2s(state->h, 32, NOISE_PROTOCOL_NAME, NOISE_PROTOCOL_NAME_LEN);

    /* ck = h */
    vpn_memcpy(state->ck, state->h, 32);

    /* No encryption key yet */
    vpn_memzero(state->k, 32);
    state->n = 0;
    state->has_key = false;
}

void noise_mix_key(noise_symmetric_state *state,
                   const uint8_t *input, size_t input_len)
{
    /*
     * (ck, temp_k) = HKDF(ck, input_key_material)
     *
     * We derive two 32-byte keys: new ck and new encryption key k.
     */
    uint8_t temp_k[32];

    hkdf_blake2s(state->ck, temp_k, NULL, state->ck, input, input_len);

    vpn_memcpy(state->k, temp_k, 32);
    state->n = 0;
    state->has_key = true;

    vpn_memzero(temp_k, sizeof(temp_k));
}

void noise_mix_hash(noise_symmetric_state *state,
                    const uint8_t *data, size_t data_len)
{
    /*
     * h = HASH(h || data)
     *
     * We hash the current h concatenated with new data.
     */
    blake2s_ctx ctx;

    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, state->h, 32);
    blake2s_update(&ctx, data, data_len);
    blake2s_final(&ctx, state->h);
}

void noise_mix_key_and_hash(noise_symmetric_state *state,
                            const uint8_t *data, size_t data_len)
{
    /*
     * temp = HKDF(ck, data, 3)  -- derive 3 keys
     * ck = temp[0]
     * temp_h = temp[1]  -- mixed into h
     * k = temp[2]       -- new encryption key
     * h = HASH(h || temp_h)
     *
     * This is used for PSK (pre-shared key) mixing in psk2 mode.
     */
    uint8_t temp_h[32], temp_k[32];

    hkdf_blake2s(state->ck, temp_h, temp_k, state->ck, data, data_len);

    noise_mix_hash(state, temp_h, 32);

    vpn_memcpy(state->k, temp_k, 32);
    state->n = 0;
    state->has_key = true;

    vpn_memzero(temp_h, sizeof(temp_h));
    vpn_memzero(temp_k, sizeof(temp_k));
}

size_t noise_encrypt_and_hash(noise_symmetric_state *state,
                              uint8_t *out,
                              const uint8_t *in, size_t in_len)
{
    size_t out_len;

    if (state->has_key) {
        /*
         * ciphertext || tag = AEAD_Encrypt(k, n++, h, plaintext)
         *
         * h is used as associated data to bind ciphertext to transcript.
         */
        uint8_t nonce[12];
        nonce_to_bytes(nonce, state->n);
        state->n++;

        aead_encrypt(out, out + in_len, in, in_len, state->h, 32, nonce, state->k);
        out_len = in_len + AEAD_TAG_SIZE;
    } else {
        /* No encryption key: ciphertext = plaintext */
        vpn_memcpy(out, in, in_len);
        out_len = in_len;
    }

    /* h = HASH(h || ciphertext) */
    noise_mix_hash(state, out, out_len);

    return out_len;
}

vpn_error_t noise_decrypt_and_hash(noise_symmetric_state *state,
                                   uint8_t *out,
                                   const uint8_t *in, size_t in_len)
{
    vpn_error_t result = VPN_OK;
    uint8_t h_copy[32];

    /* Save h for AEAD */
    vpn_memcpy(h_copy, state->h, 32);

    /* h = HASH(h || ciphertext) -- do this first before decryption */
    noise_mix_hash(state, in, in_len);

    if (state->has_key) {
        /*
         * plaintext = AEAD_Decrypt(k, n++, h_copy, ciphertext || tag)
         */
        uint8_t nonce[12];
        nonce_to_bytes(nonce, state->n);
        state->n++;

        if (in_len < AEAD_TAG_SIZE) {
            return VPN_ERR_INVALID;
        }

        size_t plaintext_len = in_len - AEAD_TAG_SIZE;
        const uint8_t *tag = in + plaintext_len;

        result = aead_decrypt(out, in, plaintext_len, tag, h_copy, 32, nonce, state->k);
    } else {
        /* No decryption key: plaintext = ciphertext */
        vpn_memcpy(out, in, in_len);
    }

    vpn_memzero(h_copy, sizeof(h_copy));
    return result;
}

void noise_split(const noise_symmetric_state *state,
                 noise_transport_state *transport,
                 bool is_initiator)
{
    /*
     * (key1, key2) = HKDF(ck, "", 2)
     *
     * Initiator: send_key = key1, recv_key = key2
     * Responder: send_key = key2, recv_key = key1
     */
    uint8_t key1[32], key2[32];

    hkdf_blake2s(key1, key2, NULL, state->ck, NULL, 0);

    if (is_initiator) {
        vpn_memcpy(transport->send_key, key1, 32);
        vpn_memcpy(transport->recv_key, key2, 32);
    } else {
        vpn_memcpy(transport->send_key, key2, 32);
        vpn_memcpy(transport->recv_key, key1, 32);
    }

    transport->send_nonce = 0;
    transport->recv_nonce = 0;
    transport->valid = true;

    vpn_memzero(key1, sizeof(key1));
    vpn_memzero(key2, sizeof(key2));
}

/*
 * ===========================================================================
 * Handshake Operations
 * ===========================================================================
 */

/*
 * Initialize symmetric state with responder's static public key
 *
 * This is called by both initiator and responder (if responder knows their
 * static public key is being used as prologue).
 */
static void noise_init_with_responder_key(noise_symmetric_state *state,
                                          const uint8_t responder_static[32])
{
    /* Initialize symmetric state */
    noise_init_symmetric(state);

    /*
     * MixHash(responder's static public key)
     *
     * This binds the responder's identity to the handshake from the start.
     * The initiator expects to talk to this specific responder.
     */
    noise_mix_hash(state, responder_static, 32);
}

void noise_handshake_init_initiator(noise_handshake_state *state,
                                    const uint8_t static_private[32],
                                    const uint8_t static_public[32],
                                    const uint8_t peer_static[32])
{
    vpn_memzero(state, sizeof(*state));

    /* Store our static keys */
    vpn_memcpy(state->s, static_private, 32);
    vpn_memcpy(state->s_pub, static_public, 32);

    /* Store peer's static public key (known beforehand in IK pattern) */
    vpn_memcpy(state->rs, peer_static, 32);

    /* Initialize symmetric state with responder's public key */
    noise_init_with_responder_key(&state->symmetric, peer_static);

    state->is_initiator = true;
    state->handshake_complete = false;
}

void noise_handshake_init_responder(noise_handshake_state *state,
                                    const uint8_t static_private[32],
                                    const uint8_t static_public[32])
{
    vpn_memzero(state, sizeof(*state));

    /* Store our static keys */
    vpn_memcpy(state->s, static_private, 32);
    vpn_memcpy(state->s_pub, static_public, 32);

    /* Initialize symmetric state with our public key (we're the responder) */
    noise_init_with_responder_key(&state->symmetric, static_public);

    state->is_initiator = false;
    state->handshake_complete = false;
}

int noise_create_initiation(noise_handshake_state *state, uint8_t *message)
{
    uint8_t dh_result[32];
    uint8_t timestamp[NOISE_TIMESTAMP_SIZE];
    size_t offset = 0;

    if (!state->is_initiator) {
        return VPN_ERR_INVALID;
    }

    /*
     * IK Initiator Message 1:
     *
     * 1. Generate ephemeral keypair
     * 2. e: Send ephemeral public key (plaintext)
     * 3. es: MixKey(DH(e, rs))
     * 4. s: Send encrypted static public key
     * 5. ss: MixKey(DH(s, rs))
     * 6. timestamp: Send encrypted timestamp
     */

    /* 1. Generate ephemeral keypair */
    if (generate_ephemeral_keypair(state->e, state->e_pub) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }

    /* 2. e: Ephemeral public key (32 bytes, plaintext) */
    vpn_memcpy(message + offset, state->e_pub, 32);
    noise_mix_hash(&state->symmetric, state->e_pub, 32);
    offset += 32;

    /* 3. es: DH(ephemeral_initiator, static_responder) */
    if (curve25519_shared(dh_result, state->rs, state->e) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 4. s: Encrypted static public key (32 + 16 = 48 bytes) */
    offset += noise_encrypt_and_hash(&state->symmetric,
                                     message + offset,
                                     state->s_pub, 32);

    /* 5. ss: DH(static_initiator, static_responder) */
    if (curve25519_shared(dh_result, state->rs, state->s) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 6. timestamp: Encrypted (12 + 16 = 28 bytes) */
    get_timestamp(timestamp);
    offset += noise_encrypt_and_hash(&state->symmetric,
                                     message + offset,
                                     timestamp, NOISE_TIMESTAMP_SIZE);

    vpn_memzero(dh_result, sizeof(dh_result));
    vpn_memzero(timestamp, sizeof(timestamp));

    return (int)offset;  /* Should be 32 + 48 + 28 = 108 bytes */
}

vpn_error_t noise_consume_initiation(noise_handshake_state *state,
                                     const uint8_t *message, size_t msg_len)
{
    uint8_t dh_result[32];
    uint8_t decrypted[48];  /* Max decrypted size */
    size_t offset = 0;

    if (state->is_initiator) {
        return VPN_ERR_INVALID;
    }

    /* Expected message size: 32 + 48 + 28 = 108 bytes */
    if (msg_len < 108) {
        return VPN_ERR_INVALID;
    }

    /*
     * Process IK message 1 as responder:
     *
     * 1. e: Receive and hash ephemeral public key
     * 2. es: MixKey(DH(s, re))  -- note: responder uses their static
     * 3. s: Decrypt initiator's static public key
     * 4. ss: MixKey(DH(s, rs))
     * 5. timestamp: Decrypt and verify timestamp
     */

    /* 1. re: Read initiator's ephemeral public key */
    vpn_memcpy(state->re, message + offset, 32);
    noise_mix_hash(&state->symmetric, state->re, 32);
    offset += 32;

    /* 2. es: DH(static_responder, ephemeral_initiator) */
    if (curve25519_shared(dh_result, state->re, state->s) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 3. rs: Decrypt initiator's static public key */
    vpn_error_t err = noise_decrypt_and_hash(&state->symmetric,
                                             decrypted,
                                             message + offset, 48);
    if (err != VPN_OK) {
        return err;
    }
    vpn_memcpy(state->rs, decrypted, 32);
    offset += 48;

    /* 4. ss: DH(static_responder, static_initiator) */
    if (curve25519_shared(dh_result, state->rs, state->s) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 5. Decrypt timestamp (not strictly verified here for simplicity) */
    err = noise_decrypt_and_hash(&state->symmetric,
                                 decrypted,
                                 message + offset, 28);
    if (err != VPN_OK) {
        return err;
    }
    /* TODO: Verify timestamp is newer than last seen */

    vpn_memzero(dh_result, sizeof(dh_result));
    vpn_memzero(decrypted, sizeof(decrypted));

    return VPN_OK;
}

int noise_create_response(noise_handshake_state *state, uint8_t *message)
{
    uint8_t dh_result[32];
    size_t offset = 0;

    if (state->is_initiator) {
        return VPN_ERR_INVALID;
    }

    /*
     * IK Responder Message 2:
     *
     * 1. Generate ephemeral keypair
     * 2. e: Send ephemeral public key (plaintext)
     * 3. ee: MixKey(DH(e, re))
     * 4. se: MixKey(DH(s, re))  -- note: responder's static with initiator's ephemeral
     * 5. empty: Send encrypted empty payload (just tag)
     */

    /* 1. Generate ephemeral keypair */
    if (generate_ephemeral_keypair(state->e, state->e_pub) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }

    /* 2. e: Ephemeral public key (32 bytes, plaintext) */
    vpn_memcpy(message + offset, state->e_pub, 32);
    noise_mix_hash(&state->symmetric, state->e_pub, 32);
    offset += 32;

    /* 3. ee: DH(ephemeral_responder, ephemeral_initiator) */
    if (curve25519_shared(dh_result, state->re, state->e) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 4. se: DH(static_responder, ephemeral_initiator) */
    if (curve25519_shared(dh_result, state->re, state->s) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 5. empty: Encrypted empty (0 + 16 = 16 bytes) */
    offset += noise_encrypt_and_hash(&state->symmetric,
                                     message + offset,
                                     NULL, 0);

    state->handshake_complete = true;

    vpn_memzero(dh_result, sizeof(dh_result));

    return (int)offset;  /* Should be 32 + 16 = 48 bytes */
}

vpn_error_t noise_consume_response(noise_handshake_state *state,
                                   const uint8_t *message, size_t msg_len)
{
    uint8_t dh_result[32];
    uint8_t decrypted[16];
    size_t offset = 0;

    if (!state->is_initiator) {
        return VPN_ERR_INVALID;
    }

    /* Expected message size: 32 + 16 = 48 bytes */
    if (msg_len < 48) {
        return VPN_ERR_INVALID;
    }

    /*
     * Process IK message 2 as initiator:
     *
     * 1. re: Receive and hash responder's ephemeral public key
     * 2. ee: MixKey(DH(e, re))
     * 3. se: MixKey(DH(e, rs))  -- note: initiator's ephemeral with responder's static
     * 4. empty: Decrypt empty payload (verifies transcript)
     */

    /* 1. re: Read responder's ephemeral public key */
    vpn_memcpy(state->re, message + offset, 32);
    noise_mix_hash(&state->symmetric, state->re, 32);
    offset += 32;

    /* 2. ee: DH(ephemeral_initiator, ephemeral_responder) */
    if (curve25519_shared(dh_result, state->re, state->e) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 3. se: DH(ephemeral_initiator, static_responder) */
    if (curve25519_shared(dh_result, state->rs, state->e) != VPN_OK) {
        return VPN_ERR_CRYPTO;
    }
    noise_mix_key(&state->symmetric, dh_result, 32);

    /* 4. Decrypt empty payload (verifies handshake integrity) */
    vpn_error_t err = noise_decrypt_and_hash(&state->symmetric,
                                             decrypted,
                                             message + offset, 16);
    if (err != VPN_OK) {
        return err;
    }

    state->handshake_complete = true;

    vpn_memzero(dh_result, sizeof(dh_result));

    return VPN_OK;
}

bool noise_handshake_complete(const noise_handshake_state *state)
{
    return state->handshake_complete;
}

vpn_error_t noise_derive_transport(const noise_handshake_state *state,
                                   noise_transport_state *transport)
{
    if (!state->handshake_complete) {
        return VPN_ERR_INVALID;
    }

    noise_split(&state->symmetric, transport, state->is_initiator);

    return VPN_OK;
}

/*
 * ===========================================================================
 * Transport Operations
 * ===========================================================================
 */

size_t noise_transport_encrypt(noise_transport_state *state,
                               uint8_t *out,
                               const uint8_t *in, size_t in_len)
{
    uint8_t nonce[12];

    if (!state->valid) {
        return 0;
    }

    nonce_to_bytes(nonce, state->send_nonce);
    state->send_nonce++;

    /* Encrypt with no additional data */
    aead_encrypt(out, out + in_len, in, in_len, NULL, 0, nonce, state->send_key);

    return in_len + AEAD_TAG_SIZE;
}

vpn_error_t noise_transport_decrypt(noise_transport_state *state,
                                    uint8_t *out,
                                    const uint8_t *in, size_t in_len)
{
    uint8_t nonce[12];

    if (!state->valid) {
        return VPN_ERR_INVALID;
    }

    if (in_len < AEAD_TAG_SIZE) {
        return VPN_ERR_INVALID;
    }

    size_t plaintext_len = in_len - AEAD_TAG_SIZE;
    const uint8_t *tag = in + plaintext_len;

    nonce_to_bytes(nonce, state->recv_nonce);
    state->recv_nonce++;

    return aead_decrypt(out, in, plaintext_len, tag, NULL, 0, nonce, state->recv_key);
}
