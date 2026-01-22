/*
 * packet.h - VPN Packet Format and Encoding
 * ==========================================
 *
 * This module defines the wire format for our VPN protocol, similar to WireGuard.
 * All communication happens over UDP with these packet types.
 *
 * PACKET STRUCTURE OVERVIEW:
 *
 * Every packet starts with a 4-byte header:
 *   - 1 byte: message type
 *   - 3 bytes: reserved (set to zero)
 *
 * MESSAGE TYPES:
 *
 *   Type 1: Handshake Initiation (148 bytes)
 *   ┌────────────┬──────────────┬─────────────────────┬───────────────────┬──────────────────┐
 *   │ type (1)   │ reserved (3) │ sender_index (4)    │ initiator msg (108) │ MAC1/MAC2 (32) │
 *   └────────────┴──────────────┴─────────────────────┴───────────────────┴──────────────────┘
 *
 *   Type 2: Handshake Response (92 bytes)
 *   ┌────────────┬──────────────┬─────────────────────┬────────────────────┬──────────────────┐
 *   │ type (1)   │ reserved (3) │ sender_index (4)    │ receiver_index (4) │ responder msg    │
 *   │            │              │                     │                    │ + MACs           │
 *   └────────────┴──────────────┴─────────────────────┴────────────────────┴──────────────────┘
 *
 *   Type 3: Cookie Reply (64 bytes)
 *   ┌────────────┬──────────────┬─────────────────────┬──────────────────────────────────────┐
 *   │ type (1)   │ reserved (3) │ receiver_index (4)  │ cookie data (56)                     │
 *   └────────────┴──────────────┴─────────────────────┴──────────────────────────────────────┘
 *
 *   Type 4: Transport Data (variable)
 *   ┌────────────┬──────────────┬─────────────────────┬─────────────────┬────────────────────┐
 *   │ type (1)   │ reserved (3) │ receiver_index (4)  │ counter (8)     │ encrypted data     │
 *   └────────────┴──────────────┴─────────────────────┴─────────────────┴────────────────────┘
 *
 * SENDER/RECEIVER INDEX:
 *
 * These 4-byte values identify which session a packet belongs to. When Alice
 * initiates to Bob, she picks a random sender_index. Bob responds with the
 * receiver_index matching Alice's sender_index, and his own sender_index.
 *
 * This allows both sides to multiplex multiple sessions over one UDP port.
 *
 * MAC1 AND MAC2:
 *
 * WireGuard adds two MACs to handshake messages for DoS protection:
 *
 * MAC1 = BLAKE2s(HASH(LABEL_MAC1 || responder_static), message)
 *   - Proves the sender knows the responder's public key
 *   - Cheap to verify, allows quick rejection of garbage packets
 *
 * MAC2 = BLAKE2s(HASH(LABEL_MAC2 || cookie), message || MAC1)
 *   - Only present under load (when cookie is valid)
 *   - Proves the sender received a recent cookie
 *   - Used for load-based DoS protection
 *
 * For this educational implementation, we simplify by focusing on the core
 * protocol without the full cookie mechanism.
 */

#ifndef VPN_PACKET_H
#define VPN_PACKET_H

#include "../types.h"
#include "noise.h"

/*
 * ===========================================================================
 * Protocol Constants
 * ===========================================================================
 */

/* Message types */
#define MSG_TYPE_HANDSHAKE_INITIATION   1
#define MSG_TYPE_HANDSHAKE_RESPONSE     2
#define MSG_TYPE_COOKIE_REPLY           3
#define MSG_TYPE_TRANSPORT_DATA         4

/* Message sizes (excluding variable data payload) */
#define MSG_INITIATION_SIZE     148
#define MSG_RESPONSE_SIZE       92
#define MSG_COOKIE_REPLY_SIZE   64
#define MSG_DATA_HEADER_SIZE    16   /* Type + reserved + index + counter */

/* Labels for MAC key derivation */
#define LABEL_MAC1 "mac1----"
#define LABEL_MAC2 "mac2----"
#define LABEL_COOKIE "cookie--"

/* Maximum transport payload before fragmentation */
#define MAX_TRANSPORT_PAYLOAD   (65535 - MSG_DATA_HEADER_SIZE - AEAD_TAG_SIZE)

/*
 * ===========================================================================
 * Packet Structures
 * ===========================================================================
 */

/*
 * Common header for all messages
 */
typedef struct {
    uint8_t type;           /* Message type (1-4) */
    uint8_t reserved[3];    /* Must be zero */
} __attribute__((packed)) packet_header;

/*
 * Handshake Initiation Message (Type 1)
 *
 * Sent by initiator to start a new session.
 */
typedef struct {
    uint8_t type;               /* MSG_TYPE_HANDSHAKE_INITIATION */
    uint8_t reserved[3];
    uint32_t sender_index;      /* Initiator's session index */
    uint8_t ephemeral[32];      /* Initiator's ephemeral public key */
    uint8_t static_enc[48];     /* Encrypted initiator static key + tag */
    uint8_t timestamp[28];      /* Encrypted timestamp + tag */
    uint8_t mac1[16];           /* MAC1 for DoS protection */
    uint8_t mac2[16];           /* MAC2 for cookie validation (may be zeros) */
} __attribute__((packed)) packet_initiation;

/*
 * Handshake Response Message (Type 2)
 *
 * Sent by responder to complete the handshake.
 */
typedef struct {
    uint8_t type;               /* MSG_TYPE_HANDSHAKE_RESPONSE */
    uint8_t reserved[3];
    uint32_t sender_index;      /* Responder's session index */
    uint32_t receiver_index;    /* Must match initiator's sender_index */
    uint8_t ephemeral[32];      /* Responder's ephemeral public key */
    uint8_t empty[16];          /* Encrypted empty + tag */
    uint8_t mac1[16];           /* MAC1 */
    uint8_t mac2[16];           /* MAC2 */
} __attribute__((packed)) packet_response;

/*
 * Cookie Reply Message (Type 3)
 *
 * Sent when under load to prove sender can receive packets.
 * The cookie allows the sender to retry with MAC2 set.
 */
typedef struct {
    uint8_t type;               /* MSG_TYPE_COOKIE_REPLY */
    uint8_t reserved[3];
    uint32_t receiver_index;    /* Index from the rejected message */
    uint8_t nonce[24];          /* Random nonce for XChaCha20-Poly1305 */
    uint8_t cookie[32];         /* Encrypted cookie + tag */
} __attribute__((packed)) packet_cookie_reply;

/*
 * Transport Data Header (Type 4)
 *
 * Header for encrypted tunnel data. The actual encrypted payload follows.
 */
typedef struct {
    uint8_t type;               /* MSG_TYPE_TRANSPORT_DATA */
    uint8_t reserved[3];
    uint32_t receiver_index;    /* Session index */
    uint64_t counter;           /* Nonce counter (little-endian) */
    /* Followed by: encrypted_data || tag */
} __attribute__((packed)) packet_data_header;

/*
 * ===========================================================================
 * Packet Encoding Functions
 * ===========================================================================
 */

/*
 * packet_encode_initiation - Encode a handshake initiation message
 *
 * @param out           Output buffer (at least MSG_INITIATION_SIZE bytes)
 * @param sender_index  Our session index
 * @param handshake     Initiator handshake state (will be modified)
 * @param responder_static  Responder's static public key (for MAC1)
 * @return              Message size on success, negative error code on failure
 */
int packet_encode_initiation(uint8_t *out,
                             uint32_t sender_index,
                             noise_handshake_state *handshake,
                             const uint8_t responder_static[32]);

/*
 * packet_encode_response - Encode a handshake response message
 *
 * @param out             Output buffer (at least MSG_RESPONSE_SIZE bytes)
 * @param sender_index    Our session index
 * @param receiver_index  Initiator's session index
 * @param handshake       Responder handshake state (will be modified)
 * @param responder_static Our static public key (for MAC1)
 * @return                Message size on success, negative error code on failure
 */
int packet_encode_response(uint8_t *out,
                           uint32_t sender_index,
                           uint32_t receiver_index,
                           noise_handshake_state *handshake,
                           const uint8_t responder_static[32]);

/*
 * packet_encode_data - Encode a transport data message
 *
 * @param out             Output buffer (at least MSG_DATA_HEADER_SIZE + data_len + 16)
 * @param receiver_index  Session index
 * @param transport       Transport state (nonce will be incremented)
 * @param data            Plaintext data to encrypt
 * @param data_len        Length of data
 * @return                Total message size on success, negative error code on failure
 */
int packet_encode_data(uint8_t *out,
                       uint32_t receiver_index,
                       noise_transport_state *transport,
                       const uint8_t *data, size_t data_len);

/*
 * ===========================================================================
 * Packet Decoding Functions
 * ===========================================================================
 */

/*
 * packet_get_type - Get message type from packet header
 *
 * @param packet    Packet data
 * @param len       Packet length
 * @return          Message type (1-4) or negative error if invalid
 */
int packet_get_type(const uint8_t *packet, size_t len);

/*
 * packet_decode_initiation - Decode a handshake initiation message
 *
 * @param packet         Received packet
 * @param len            Packet length
 * @param sender_index   Output: initiator's session index
 * @param handshake      Responder handshake state to populate
 * @param our_static     Our static key pair (for validation)
 * @return               VPN_OK on success, error code on failure
 */
vpn_error_t packet_decode_initiation(const uint8_t *packet, size_t len,
                                     uint32_t *sender_index,
                                     noise_handshake_state *handshake,
                                     const uint8_t our_static_private[32],
                                     const uint8_t our_static_public[32]);

/*
 * packet_decode_response - Decode a handshake response message
 *
 * @param packet          Received packet
 * @param len             Packet length
 * @param sender_index    Output: responder's session index
 * @param receiver_index  Output: should match our sender_index
 * @param handshake       Initiator handshake state (will be updated)
 * @param our_static      Our static public key (for MAC1 validation)
 * @return                VPN_OK on success, error code on failure
 */
vpn_error_t packet_decode_response(const uint8_t *packet, size_t len,
                                   uint32_t *sender_index,
                                   uint32_t *receiver_index,
                                   noise_handshake_state *handshake,
                                   const uint8_t our_static_public[32]);

/*
 * packet_decode_data - Decode a transport data message
 *
 * @param packet         Received packet
 * @param len            Packet length
 * @param receiver_index Output: session index
 * @param transport      Transport state for decryption
 * @param out            Output buffer for decrypted data
 * @param out_len        Output: length of decrypted data
 * @return               VPN_OK on success, error code on failure
 */
vpn_error_t packet_decode_data(const uint8_t *packet, size_t len,
                               uint32_t *receiver_index,
                               noise_transport_state *transport,
                               uint8_t *out, size_t *out_len);

/*
 * ===========================================================================
 * MAC Functions
 * ===========================================================================
 */

/*
 * packet_compute_mac1 - Compute MAC1 for a handshake message
 *
 * MAC1 = BLAKE2s(HASH(LABEL_MAC1 || responder_static), message[0..end-32])
 *
 * @param mac1              Output: 16-byte MAC1
 * @param responder_static  Responder's static public key
 * @param message           Message data (excluding MAC1 and MAC2)
 * @param message_len       Length of message
 */
void packet_compute_mac1(uint8_t mac1[16],
                         const uint8_t responder_static[32],
                         const uint8_t *message, size_t message_len);

/*
 * packet_verify_mac1 - Verify MAC1 of a received message
 *
 * @param message           Full message including MAC1 (MAC2 is excluded from check)
 * @param message_len       Total message length
 * @param our_static        Our static public key
 * @return                  true if MAC1 is valid
 */
bool packet_verify_mac1(const uint8_t *message, size_t message_len,
                        const uint8_t our_static[32]);

#endif /* VPN_PACKET_H */
