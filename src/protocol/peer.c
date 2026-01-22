/*
 * peer.c - Peer Management Implementation
 * ========================================
 *
 * This implements the peer management functions defined in peer.h.
 *
 * KEY DESIGN DECISIONS:
 *
 * 1. Simple Linear Search: For MAX_PEERS=64, linear search is fine.
 *    A production implementation might use a hash table.
 *
 * 2. Two Sessions: We keep current and previous sessions to handle
 *    rekey overlap smoothly. Packets might arrive on the old session
 *    while we're transitioning to new keys.
 *
 * 3. Random Indices: Session indices are random to prevent guessing.
 *    This provides some protection against IP spoofing attacks.
 */

#include "peer.h"
#include "packet.h"
#include "../util/memory.h"
#include "../util/random.h"
#include "../util/log.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*
 * ===========================================================================
 * Helpers
 * ===========================================================================
 */

/*
 * Generate a random 32-bit session index
 *
 * Uses CSPRNG to generate unpredictable session indices.
 * This prevents attackers from guessing indices for spoofing attacks.
 */
static uint32_t generate_index(void)
{
    uint32_t index = 0;

    if (vpn_random_bytes((uint8_t *)&index, sizeof(index)) != VPN_OK) {
        /*
         * Fallback if CSPRNG fails (should never happen in production).
         * Log error and use time-based value as last resort.
         */
        LOG_ERROR("CSPRNG failed generating session index, using fallback");
        index = (uint32_t)time(NULL) ^ 0xDEADBEEF;
    }

    /* Ensure non-zero index (zero is reserved) */
    if (index == 0) {
        index = 1;
    }

    return index;
}

/*
 * Check if IP address matches a CIDR range
 */
static bool ip_in_range(const uint8_t *ip, const ip_range *range)
{
    size_t addr_len = range->is_ipv6 ? 16 : 4;
    uint8_t prefix_len = range->prefix_len;
    size_t full_bytes = prefix_len / 8;
    uint8_t remaining_bits = prefix_len % 8;
    size_t i;

    /* Compare full bytes */
    for (i = 0; i < full_bytes && i < addr_len; i++) {
        if (ip[i] != range->addr[i]) {
            return false;
        }
    }

    /* Compare remaining bits */
    if (remaining_bits > 0 && i < addr_len) {
        uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
        if ((ip[i] & mask) != (range->addr[i] & mask)) {
            return false;
        }
    }

    return true;
}

/*
 * ===========================================================================
 * Peer Table Management
 * ===========================================================================
 */

void peer_table_init(peer_table *table,
                     const uint8_t static_private[32],
                     const uint8_t static_public[32])
{
    vpn_memzero(table, sizeof(*table));

    vpn_memcpy(table->static_private, static_private, 32);
    vpn_memcpy(table->static_public, static_public, 32);
}

peer_t *peer_add(peer_table *table, const uint8_t static_public[32])
{
    int i;
    peer_t *peer;

    /* Check if already exists */
    peer = peer_find_by_pubkey(table, static_public);
    if (peer) {
        return peer;
    }

    /* Find empty slot */
    for (i = 0; i < MAX_PEERS; i++) {
        if (!table->peers[i].is_configured) {
            peer = &table->peers[i];
            break;
        }
    }

    if (!peer) {
        return NULL;  /* Table full */
    }

    /* Initialize peer */
    vpn_memzero(peer, sizeof(*peer));
    vpn_memcpy(peer->static_public, static_public, 32);
    peer->is_configured = true;
    table->count++;

    return peer;
}

peer_t *peer_find_by_pubkey(peer_table *table, const uint8_t static_public[32])
{
    int i;

    for (i = 0; i < MAX_PEERS; i++) {
        if (table->peers[i].is_configured &&
            vpn_memeq(table->peers[i].static_public, static_public, 32)) {
            return &table->peers[i];
        }
    }

    return NULL;
}

peer_t *peer_find_by_index(peer_table *table, uint32_t index)
{
    int i;

    for (i = 0; i < MAX_PEERS; i++) {
        peer_t *peer = &table->peers[i];
        if (!peer->is_configured) {
            continue;
        }

        /* Check current session */
        if (peer->current.valid && peer->current.local_index == index) {
            return peer;
        }

        /* Check previous session */
        if (peer->previous.valid && peer->previous.local_index == index) {
            return peer;
        }

        /* Check ongoing handshake */
        if (peer->handshake.in_progress && peer->handshake.local_index == index) {
            return peer;
        }
    }

    return NULL;
}

void peer_remove(peer_table *table, peer_t *peer)
{
    if (peer && peer->is_configured) {
        /* Clear sensitive data */
        vpn_memzero(peer, sizeof(*peer));
        table->count--;
    }
}

/*
 * ===========================================================================
 * Peer Configuration
 * ===========================================================================
 */

void peer_set_endpoint(peer_t *peer,
                       const uint8_t *addr,
                       uint16_t port,
                       bool is_ipv6)
{
    size_t addr_len = is_ipv6 ? 16 : 4;

    vpn_memzero(peer->ep.addr, 16);
    vpn_memcpy(peer->ep.addr, addr, addr_len);
    peer->ep.port = port;
    peer->ep.is_ipv6 = is_ipv6;
    peer->ep.is_set = true;
}

vpn_error_t peer_add_allowed_ip(peer_t *peer,
                                const uint8_t *addr,
                                uint8_t prefix_len,
                                bool is_ipv6)
{
    ip_range *range;
    size_t addr_len;

    if (peer->num_allowed_ips >= MAX_ALLOWED_IPS) {
        return VPN_ERR_INVALID;
    }

    /* Validate prefix length */
    if ((is_ipv6 && prefix_len > 128) || (!is_ipv6 && prefix_len > 32)) {
        return VPN_ERR_INVALID;
    }

    range = &peer->allowed_ips[peer->num_allowed_ips];
    addr_len = is_ipv6 ? 16 : 4;

    vpn_memzero(range->addr, 16);
    vpn_memcpy(range->addr, addr, addr_len);
    range->prefix_len = prefix_len;
    range->is_ipv6 = is_ipv6;

    peer->num_allowed_ips++;

    return VPN_OK;
}

void peer_set_preshared_key(peer_t *peer, const uint8_t psk[32])
{
    vpn_memcpy(peer->preshared_key, psk, 32);
    peer->has_preshared_key = true;
}

void peer_set_keepalive(peer_t *peer, uint16_t interval)
{
    peer->persistent_keepalive = interval;
}

/*
 * ===========================================================================
 * Session Management
 * ===========================================================================
 */

int peer_initiate_handshake(peer_t *peer,
                            peer_table *table,
                            uint8_t *out)
{
    handshake_state *hs = &peer->handshake;
    int msg_len;

    /* Generate new session index */
    hs->local_index = generate_index();

    /* Initialize Noise handshake as initiator */
    noise_handshake_init_initiator(&hs->noise,
                                   table->static_private,
                                   table->static_public,
                                   peer->static_public);

    /* Create initiation message */
    msg_len = packet_encode_initiation(out,
                                       hs->local_index,
                                       &hs->noise,
                                       peer->static_public);

    if (msg_len > 0) {
        hs->started = time(NULL);
        hs->in_progress = true;
        hs->we_initiated = true;
        hs->retries = 0;
    }

    return msg_len;
}

int peer_respond_handshake(peer_t *peer,
                           peer_table *table,
                           const uint8_t *init_msg, size_t init_len,
                           uint8_t *out)
{
    handshake_state *hs = &peer->handshake;
    uint32_t sender_index;
    int msg_len;
    vpn_error_t err;

    /* Decode and process initiation */
    err = packet_decode_initiation(init_msg, init_len,
                                   &sender_index,
                                   &hs->noise,
                                   table->static_private,
                                   table->static_public);
    if (err != VPN_OK) {
        return (int)err;
    }

    /* Store peer's index */
    hs->remote_index = sender_index;

    /* Generate our session index */
    hs->local_index = generate_index();

    /* Create response message */
    msg_len = packet_encode_response(out,
                                     hs->local_index,
                                     hs->remote_index,
                                     &hs->noise,
                                     table->static_public);

    if (msg_len > 0) {
        /* Handshake complete on responder side */
        noise_transport_state transport;

        if (noise_derive_transport(&hs->noise, &transport) == VPN_OK) {
            /* Promote previous session and install new one */
            vpn_memzero(&peer->previous, sizeof(peer->previous));
            vpn_memcpy(&peer->previous, &peer->current, sizeof(session_state));

            peer->current.transport = transport;
            peer->current.local_index = hs->local_index;
            peer->current.remote_index = hs->remote_index;
            peer->current.created = time(NULL);
            peer->current.last_send = 0;
            peer->current.last_recv = 0;
            peer->current.tx_bytes = 0;
            peer->current.rx_bytes = 0;
            peer->current.valid = true;

            peer->last_handshake = time(NULL);
        }

        hs->in_progress = false;
        hs->we_initiated = false;
    }

    return msg_len;
}

vpn_error_t peer_complete_handshake(peer_t *peer,
                                    const uint8_t *resp_msg, size_t resp_len)
{
    handshake_state *hs = &peer->handshake;
    uint32_t sender_index, receiver_index;
    vpn_error_t err;

    if (!hs->in_progress || !hs->we_initiated) {
        return VPN_ERR_INVALID;
    }

    /* Decode and process response */
    err = packet_decode_response(resp_msg, resp_len,
                                 &sender_index,
                                 &receiver_index,
                                 &hs->noise,
                                 peer->static_public);
    if (err != VPN_OK) {
        return err;
    }

    /* Verify receiver index matches our sender index */
    if (receiver_index != hs->local_index) {
        return VPN_ERR_INVALID;
    }

    hs->remote_index = sender_index;

    /* Derive transport keys */
    noise_transport_state transport;
    err = noise_derive_transport(&hs->noise, &transport);
    if (err != VPN_OK) {
        return err;
    }

    /* Promote previous session and install new one */
    vpn_memzero(&peer->previous, sizeof(peer->previous));
    vpn_memcpy(&peer->previous, &peer->current, sizeof(session_state));

    peer->current.transport = transport;
    peer->current.local_index = hs->local_index;
    peer->current.remote_index = hs->remote_index;
    peer->current.created = time(NULL);
    peer->current.last_send = 0;
    peer->current.last_recv = 0;
    peer->current.tx_bytes = 0;
    peer->current.rx_bytes = 0;
    peer->current.valid = true;

    peer->last_handshake = time(NULL);
    hs->in_progress = false;

    return VPN_OK;
}

bool peer_session_valid(const peer_t *peer)
{
    time_t now = time(NULL);
    time_t age;

    if (!peer->current.valid) {
        return false;
    }

    /* Check session age */
    age = now - peer->current.created;
    if (age > REJECT_AFTER_TIME) {
        return false;
    }

    /* Check nonce limit */
    if (peer->current.transport.send_nonce >= REJECT_AFTER_MESSAGES) {
        return false;
    }

    return true;
}

bool peer_needs_handshake(const peer_t *peer)
{
    time_t now = time(NULL);
    time_t age;

    /* Always need handshake if no valid session */
    if (!peer->current.valid) {
        return true;
    }

    /* Check if session is old enough for rekey */
    age = now - peer->current.created;
    if (age > REKEY_AFTER_TIME) {
        return true;
    }

    /* Check if approaching nonce limit */
    if (peer->current.transport.send_nonce >= REKEY_AFTER_MESSAGES) {
        return true;
    }

    return false;
}

/*
 * ===========================================================================
 * Data Operations
 * ===========================================================================
 */

int peer_encrypt_data(peer_t *peer,
                      uint8_t *out,
                      const uint8_t *data, size_t data_len)
{
    session_state *session = &peer->current;
    int msg_len;

    if (!session->valid) {
        return VPN_ERR_INVALID;
    }

    msg_len = packet_encode_data(out,
                                 session->remote_index,
                                 &session->transport,
                                 data, data_len);

    if (msg_len > 0) {
        session->last_send = time(NULL);
        session->tx_bytes += data_len;
    }

    return msg_len;
}

vpn_error_t peer_decrypt_data(peer_t *peer,
                              uint8_t *out, size_t *out_len,
                              const uint8_t *packet, size_t pkt_len)
{
    session_state *session;
    uint32_t receiver_index;
    vpn_error_t err;

    /*
     * Determine which session this packet belongs to.
     * It could be current or previous (during rekey transition).
     */
    if (pkt_len < 8) {
        return VPN_ERR_INVALID;
    }

    /* Extract receiver index from packet */
    receiver_index = ((uint32_t)packet[4])       |
                     ((uint32_t)packet[5] << 8)  |
                     ((uint32_t)packet[6] << 16) |
                     ((uint32_t)packet[7] << 24);

    if (peer->current.valid && peer->current.local_index == receiver_index) {
        session = &peer->current;
    } else if (peer->previous.valid && peer->previous.local_index == receiver_index) {
        session = &peer->previous;
    } else {
        return VPN_ERR_INVALID;
    }

    /* Decrypt */
    err = packet_decode_data(packet, pkt_len,
                             &receiver_index,
                             &session->transport,
                             out, out_len);

    if (err == VPN_OK) {
        session->last_recv = time(NULL);
        session->rx_bytes += *out_len;

        /* Update endpoint from packet source (roaming) */
        /* TODO: Update peer->ep from received packet source */
    }

    return err;
}

/*
 * ===========================================================================
 * Routing
 * ===========================================================================
 */

peer_t *peer_lookup_by_ip(peer_table *table,
                          const uint8_t *ip,
                          bool is_ipv6)
{
    int i, j;
    peer_t *peer;
    peer_t *best_match = NULL;
    uint8_t best_prefix = 0;

    /*
     * Find the most specific match (longest prefix).
     * This is like "longest prefix match" routing.
     */
    for (i = 0; i < MAX_PEERS; i++) {
        peer = &table->peers[i];
        if (!peer->is_configured) {
            continue;
        }

        for (j = 0; j < peer->num_allowed_ips; j++) {
            ip_range *range = &peer->allowed_ips[j];

            if (range->is_ipv6 != is_ipv6) {
                continue;
            }

            if (ip_in_range(ip, range)) {
                if (range->prefix_len >= best_prefix) {
                    best_prefix = range->prefix_len;
                    best_match = peer;
                }
            }
        }
    }

    return best_match;
}

bool peer_check_source_ip(const peer_t *peer,
                          const uint8_t *ip,
                          bool is_ipv6)
{
    int i;

    for (i = 0; i < peer->num_allowed_ips; i++) {
        const ip_range *range = &peer->allowed_ips[i];

        if (range->is_ipv6 != is_ipv6) {
            continue;
        }

        if (ip_in_range(ip, range)) {
            return true;
        }
    }

    return false;
}
