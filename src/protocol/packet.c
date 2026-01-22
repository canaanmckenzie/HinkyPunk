/*
 * packet.c - VPN Packet Format and Encoding Implementation
 * =========================================================
 *
 * This implements the packet encoding/decoding functions defined in packet.h.
 *
 * WIRE FORMAT DETAILS:
 *
 * All multi-byte integers are little-endian (x86/ARM native order).
 * This is simpler and faster on common platforms.
 *
 * The message format closely follows WireGuard's specification:
 * https://www.wireguard.com/protocol/
 */

#include "packet.h"
#include "../crypto/blake2s.h"
#include "../crypto/aead.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ===========================================================================
 * Helper Functions
 * ===========================================================================
 */

/*
 * Write little-endian 32-bit value
 */
static void write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * Read little-endian 32-bit value
 */
static uint32_t read_le32(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/*
 * Write little-endian 64-bit value
 */
static void write_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/*
 * Read little-endian 64-bit value
 */
static uint64_t read_le64(const uint8_t *p)
{
    return ((uint64_t)p[0])       |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

/*
 * ===========================================================================
 * MAC Functions
 * ===========================================================================
 */

/*
 * Derive MAC1 key from responder's static public key
 *
 * mac1_key = HASH(LABEL_MAC1 || responder_static)
 */
static void derive_mac1_key(uint8_t key[32], const uint8_t responder_static[32])
{
    blake2s_ctx ctx;

    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, LABEL_MAC1, 8);
    blake2s_update(&ctx, responder_static, 32);
    blake2s_final(&ctx, key);
}

void packet_compute_mac1(uint8_t mac1[16],
                         const uint8_t responder_static[32],
                         const uint8_t *message, size_t message_len)
{
    uint8_t mac1_key[32];
    uint8_t full_mac[32];

    /* Derive MAC1 key */
    derive_mac1_key(mac1_key, responder_static);

    /* MAC1 = BLAKE2s(key, message) truncated to 16 bytes */
    blake2s_keyed(full_mac, 32, message, message_len, mac1_key, 32);
    vpn_memcpy(mac1, full_mac, 16);

    vpn_memzero(mac1_key, sizeof(mac1_key));
    vpn_memzero(full_mac, sizeof(full_mac));
}

bool packet_verify_mac1(const uint8_t *message, size_t message_len,
                        const uint8_t our_static[32])
{
    uint8_t computed_mac1[16];
    size_t mac1_offset;
    bool result;

    /*
     * For initiation: MAC1 is at offset 116 (148 - 32)
     * For response: MAC1 is at offset 60 (92 - 32)
     *
     * We compute MAC1 over everything before MAC1.
     */
    if (message_len < 32) {
        return false;
    }

    mac1_offset = message_len - 32;  /* MAC1 is 32 bytes from end (MAC1 + MAC2) */

    packet_compute_mac1(computed_mac1, our_static, message, mac1_offset);

    result = vpn_memeq(computed_mac1, message + mac1_offset, 16);

    vpn_memzero(computed_mac1, sizeof(computed_mac1));

    return result;
}

/*
 * ===========================================================================
 * Packet Type Detection
 * ===========================================================================
 */

int packet_get_type(const uint8_t *packet, size_t len)
{
    if (len < 4) {
        return VPN_ERR_INVALID;
    }

    uint8_t type = packet[0];

    /* Verify reserved bytes are zero */
    if (packet[1] != 0 || packet[2] != 0 || packet[3] != 0) {
        return VPN_ERR_INVALID;
    }

    /* Validate message type and length */
    switch (type) {
        case MSG_TYPE_HANDSHAKE_INITIATION:
            if (len != MSG_INITIATION_SIZE) {
                return VPN_ERR_INVALID;
            }
            return type;

        case MSG_TYPE_HANDSHAKE_RESPONSE:
            if (len != MSG_RESPONSE_SIZE) {
                return VPN_ERR_INVALID;
            }
            return type;

        case MSG_TYPE_COOKIE_REPLY:
            if (len != MSG_COOKIE_REPLY_SIZE) {
                return VPN_ERR_INVALID;
            }
            return type;

        case MSG_TYPE_TRANSPORT_DATA:
            if (len < MSG_DATA_HEADER_SIZE + AEAD_TAG_SIZE) {
                return VPN_ERR_INVALID;
            }
            return type;

        default:
            return VPN_ERR_INVALID;
    }
}

/*
 * ===========================================================================
 * Encoding Functions
 * ===========================================================================
 */

int packet_encode_initiation(uint8_t *out,
                             uint32_t sender_index,
                             noise_handshake_state *handshake,
                             const uint8_t responder_static[32])
{
    packet_initiation *pkt = (packet_initiation *)out;
    uint8_t noise_msg[108];
    int noise_len;

    /* Create Noise handshake initiation */
    noise_len = noise_create_initiation(handshake, noise_msg);
    if (noise_len < 0) {
        return noise_len;
    }

    /* Fill packet structure */
    pkt->type = MSG_TYPE_HANDSHAKE_INITIATION;
    pkt->reserved[0] = 0;
    pkt->reserved[1] = 0;
    pkt->reserved[2] = 0;

    write_le32((uint8_t *)&pkt->sender_index, sender_index);

    /* Copy Noise message components */
    vpn_memcpy(pkt->ephemeral, noise_msg, 32);
    vpn_memcpy(pkt->static_enc, noise_msg + 32, 48);
    vpn_memcpy(pkt->timestamp, noise_msg + 80, 28);

    /* Compute MAC1 over message up to MAC1 field */
    size_t mac1_offset = MSG_INITIATION_SIZE - 32;
    packet_compute_mac1(pkt->mac1, responder_static, out, mac1_offset);

    /* MAC2 is zeros (no cookie) */
    vpn_memzero(pkt->mac2, 16);

    vpn_memzero(noise_msg, sizeof(noise_msg));

    return MSG_INITIATION_SIZE;
}

int packet_encode_response(uint8_t *out,
                           uint32_t sender_index,
                           uint32_t receiver_index,
                           noise_handshake_state *handshake,
                           const uint8_t responder_static[32])
{
    packet_response *pkt = (packet_response *)out;
    uint8_t noise_msg[48];
    int noise_len;

    /* Create Noise handshake response */
    noise_len = noise_create_response(handshake, noise_msg);
    if (noise_len < 0) {
        return noise_len;
    }

    /* Fill packet structure */
    pkt->type = MSG_TYPE_HANDSHAKE_RESPONSE;
    pkt->reserved[0] = 0;
    pkt->reserved[1] = 0;
    pkt->reserved[2] = 0;

    write_le32((uint8_t *)&pkt->sender_index, sender_index);
    write_le32((uint8_t *)&pkt->receiver_index, receiver_index);

    /* Copy Noise message components */
    vpn_memcpy(pkt->ephemeral, noise_msg, 32);
    vpn_memcpy(pkt->empty, noise_msg + 32, 16);

    /* Compute MAC1 */
    size_t mac1_offset = MSG_RESPONSE_SIZE - 32;
    packet_compute_mac1(pkt->mac1, responder_static, out, mac1_offset);

    /* MAC2 is zeros */
    vpn_memzero(pkt->mac2, 16);

    vpn_memzero(noise_msg, sizeof(noise_msg));

    return MSG_RESPONSE_SIZE;
}

int packet_encode_data(uint8_t *out,
                       uint32_t receiver_index,
                       noise_transport_state *transport,
                       const uint8_t *data, size_t data_len)
{
    packet_data_header *hdr = (packet_data_header *)out;
    size_t total_len;

    if (data_len > MAX_TRANSPORT_PAYLOAD) {
        return VPN_ERR_INVALID;
    }

    /* Fill header */
    hdr->type = MSG_TYPE_TRANSPORT_DATA;
    hdr->reserved[0] = 0;
    hdr->reserved[1] = 0;
    hdr->reserved[2] = 0;

    write_le32((uint8_t *)&hdr->receiver_index, receiver_index);
    write_le64((uint8_t *)&hdr->counter, transport->send_nonce);

    /* Encrypt data */
    size_t encrypted_len = noise_transport_encrypt(transport,
                                                   out + MSG_DATA_HEADER_SIZE,
                                                   data, data_len);
    if (encrypted_len == 0) {
        return VPN_ERR_CRYPTO;
    }

    total_len = MSG_DATA_HEADER_SIZE + encrypted_len;

    return (int)total_len;
}

/*
 * ===========================================================================
 * Decoding Functions
 * ===========================================================================
 */

vpn_error_t packet_decode_initiation(const uint8_t *packet, size_t len,
                                     uint32_t *sender_index,
                                     noise_handshake_state *handshake,
                                     const uint8_t our_static_private[32],
                                     const uint8_t our_static_public[32])
{
    const packet_initiation *pkt = (const packet_initiation *)packet;
    uint8_t noise_msg[108];

    if (len != MSG_INITIATION_SIZE) {
        return VPN_ERR_INVALID;
    }

    /* Verify MAC1 */
    if (!packet_verify_mac1(packet, len, our_static_public)) {
        return VPN_ERR_AUTH;
    }

    /* Extract sender index */
    *sender_index = read_le32((const uint8_t *)&pkt->sender_index);

    /* Initialize handshake state as responder */
    noise_handshake_init_responder(handshake, our_static_private, our_static_public);

    /* Reconstruct Noise message */
    vpn_memcpy(noise_msg, pkt->ephemeral, 32);
    vpn_memcpy(noise_msg + 32, pkt->static_enc, 48);
    vpn_memcpy(noise_msg + 80, pkt->timestamp, 28);

    /* Process with Noise */
    vpn_error_t err = noise_consume_initiation(handshake, noise_msg, 108);

    vpn_memzero(noise_msg, sizeof(noise_msg));

    return err;
}

vpn_error_t packet_decode_response(const uint8_t *packet, size_t len,
                                   uint32_t *sender_index,
                                   uint32_t *receiver_index,
                                   noise_handshake_state *handshake,
                                   const uint8_t our_static_public[32])
{
    const packet_response *pkt = (const packet_response *)packet;
    uint8_t noise_msg[48];

    if (len != MSG_RESPONSE_SIZE) {
        return VPN_ERR_INVALID;
    }

    /* Verify MAC1 */
    if (!packet_verify_mac1(packet, len, our_static_public)) {
        return VPN_ERR_AUTH;
    }

    /* Extract indices */
    *sender_index = read_le32((const uint8_t *)&pkt->sender_index);
    *receiver_index = read_le32((const uint8_t *)&pkt->receiver_index);

    /* Reconstruct Noise message */
    vpn_memcpy(noise_msg, pkt->ephemeral, 32);
    vpn_memcpy(noise_msg + 32, pkt->empty, 16);

    /* Process with Noise */
    vpn_error_t err = noise_consume_response(handshake, noise_msg, 48);

    vpn_memzero(noise_msg, sizeof(noise_msg));

    return err;
}

vpn_error_t packet_decode_data(const uint8_t *packet, size_t len,
                               uint32_t *receiver_index,
                               noise_transport_state *transport,
                               uint8_t *out, size_t *out_len)
{
    const packet_data_header *hdr = (const packet_data_header *)packet;
    size_t encrypted_len;
    uint64_t counter;

    if (len < MSG_DATA_HEADER_SIZE + AEAD_TAG_SIZE) {
        return VPN_ERR_INVALID;
    }

    /* Extract header fields */
    *receiver_index = read_le32((const uint8_t *)&hdr->receiver_index);
    counter = read_le64((const uint8_t *)&hdr->counter);

    /*
     * Counter replay protection:
     *
     * We should verify that this counter hasn't been seen before.
     * For simplicity, we just check it's >= expected.
     * A real implementation would use a sliding window.
     */
    if (counter < transport->recv_nonce) {
        return VPN_ERR_AUTH;  /* Replay detected */
    }

    /* Update nonce to match received counter */
    transport->recv_nonce = counter;

    /* Decrypt data */
    encrypted_len = len - MSG_DATA_HEADER_SIZE;
    vpn_error_t err = noise_transport_decrypt(transport,
                                              out,
                                              packet + MSG_DATA_HEADER_SIZE,
                                              encrypted_len);
    if (err != VPN_OK) {
        return err;
    }

    *out_len = encrypted_len - AEAD_TAG_SIZE;

    /* Advance nonce for next packet */
    transport->recv_nonce++;

    return VPN_OK;
}
