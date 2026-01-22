/*
 * peer.h - Peer Management for VPN Sessions
 * ==========================================
 *
 * This module manages VPN peers - other endpoints we communicate with.
 * Each peer has cryptographic state (keys), network information (endpoint,
 * allowed IPs), and session state (handshake, transport keys).
 *
 * PEER LIFECYCLE:
 *
 * 1. CONFIGURED: Peer is known, we have their static public key
 * 2. HANDSHAKING: We're establishing a session (exchanging ephemeral keys)
 * 3. ESTABLISHED: Session is active, we can send/receive encrypted data
 * 4. EXPIRED: Session keys are old, need to re-handshake
 *
 * KEY CONCEPTS:
 *
 * - Static Key: Long-term identity key, configured once
 * - Ephemeral Key: Short-term key, changes with each handshake
 * - Session Key: Symmetric key derived from handshake, used for data
 *
 * ALLOWED IPS:
 *
 * Each peer has a list of IP ranges they're allowed to use as source addresses.
 * This is both for routing (which peer handles 10.0.0.0/24?) and for security
 * (peer A can't spoof traffic from peer B's network).
 *
 * WireGuard calls this "cryptokey routing" - the routing table is keyed by
 * the peer's public key, not by traditional metrics.
 *
 * SESSION INDICES:
 *
 * Each session has sender and receiver indices (4-byte random values).
 * These allow multiplexing multiple sessions over one UDP port and
 * provide some protection against IP spoofing of data packets.
 *
 * TIMERS:
 *
 * Several timers govern session lifecycle:
 * - Rekey-After-Time: Re-handshake after this many seconds (default: 120)
 * - Rekey-After-Messages: Re-handshake after this many messages
 * - Keepalive: Send empty packet if no traffic for this long
 * - Handshake timeout: Abort handshake if no response
 */

#ifndef VPN_PEER_H
#define VPN_PEER_H

#include "../types.h"
#include "noise.h"
#include <time.h>

/*
 * ===========================================================================
 * Constants
 * ===========================================================================
 */

/* Timer values (in seconds) */
#define REKEY_AFTER_TIME        120     /* Initiate rekey after 2 minutes */
#define REJECT_AFTER_TIME       180     /* Drop session after 3 minutes */
#define REKEY_ATTEMPT_TIME      90      /* Retry handshake interval */
#define REKEY_TIMEOUT           5       /* Handshake timeout */
#define KEEPALIVE_TIMEOUT       10      /* Default keepalive (if enabled) */

/* Message limits */
#define REKEY_AFTER_MESSAGES    (1ULL << 60)   /* Rekey after 2^60 messages */
#define REJECT_AFTER_MESSAGES   (UINT64_MAX - (1ULL << 13))  /* Reject near overflow */

/* Maximum peers */
#define MAX_PEERS               64

/* Maximum allowed IP ranges per peer */
#define MAX_ALLOWED_IPS         16

/*
 * ===========================================================================
 * Data Structures
 * ===========================================================================
 */

/*
 * IP range (CIDR notation)
 *
 * Represents a network like 10.0.0.0/24 or 2001:db8::/32
 */
typedef struct {
    uint8_t addr[16];       /* IPv4 (4 bytes) or IPv6 (16 bytes) */
    uint8_t prefix_len;     /* Number of bits in network mask */
    bool is_ipv6;           /* True if IPv6, false if IPv4 */
} ip_range;

/*
 * Network endpoint (IP + port)
 */
typedef struct {
    uint8_t addr[16];       /* IP address */
    uint16_t port;          /* UDP port (network byte order) */
    bool is_ipv6;
    bool is_set;            /* Is this endpoint known? */
} endpoint;

/*
 * Session state (one active session per peer)
 */
typedef struct {
    noise_transport_state transport;    /* Transport encryption keys */
    uint32_t local_index;               /* Our session index */
    uint32_t remote_index;              /* Peer's session index */
    time_t created;                     /* When session was established */
    time_t last_send;                   /* Last packet sent */
    time_t last_recv;                   /* Last packet received */
    uint64_t tx_bytes;                  /* Bytes sent */
    uint64_t rx_bytes;                  /* Bytes received */
    bool valid;                         /* Is session usable? */
} session_state;

/*
 * Handshake state (during key exchange)
 */
typedef struct {
    noise_handshake_state noise;        /* Noise protocol state */
    uint32_t local_index;               /* Our handshake index */
    uint32_t remote_index;              /* Peer's handshake index */
    time_t started;                     /* When handshake began */
    int retries;                        /* Number of retry attempts */
    bool in_progress;                   /* Is handshake active? */
    bool we_initiated;                  /* Did we start this handshake? */
} handshake_state;

/*
 * Peer structure
 *
 * Contains all information about a single peer.
 */
typedef struct {
    /* Identity */
    uint8_t static_public[32];          /* Peer's static public key */
    bool has_preshared_key;             /* Is PSK configured? */
    uint8_t preshared_key[32];          /* Pre-shared key (optional) */

    /* Network */
    endpoint ep;                        /* Last known endpoint */
    ip_range allowed_ips[MAX_ALLOWED_IPS];  /* Allowed source IPs */
    int num_allowed_ips;

    /* Sessions */
    session_state current;              /* Current active session */
    session_state previous;             /* Previous session (for rekey overlap) */
    handshake_state handshake;          /* Ongoing handshake */

    /* Timers */
    uint16_t persistent_keepalive;      /* Keepalive interval (0 = disabled) */
    time_t last_handshake;              /* Last successful handshake time */

    /* State */
    bool is_configured;                 /* Is peer configured? */

} peer_t;

/*
 * Peer table (all known peers)
 */
typedef struct {
    peer_t peers[MAX_PEERS];
    int count;

    /* Our identity */
    uint8_t static_private[32];
    uint8_t static_public[32];

} peer_table;

/*
 * ===========================================================================
 * Peer Table Management
 * ===========================================================================
 */

/*
 * peer_table_init - Initialize peer table with our identity
 *
 * @param table           Table to initialize
 * @param static_private  Our static private key
 * @param static_public   Our static public key
 */
void peer_table_init(peer_table *table,
                     const uint8_t static_private[32],
                     const uint8_t static_public[32]);

/*
 * peer_add - Add a new peer to the table
 *
 * @param table           Peer table
 * @param static_public   Peer's static public key
 * @return                Pointer to new peer, or NULL if table full
 */
peer_t *peer_add(peer_table *table, const uint8_t static_public[32]);

/*
 * peer_find_by_pubkey - Find peer by static public key
 *
 * @param table           Peer table
 * @param static_public   Public key to search for
 * @return                Pointer to peer, or NULL if not found
 */
peer_t *peer_find_by_pubkey(peer_table *table, const uint8_t static_public[32]);

/*
 * peer_find_by_index - Find peer by session index
 *
 * @param table           Peer table
 * @param index           Session index to search for
 * @return                Pointer to peer, or NULL if not found
 */
peer_t *peer_find_by_index(peer_table *table, uint32_t index);

/*
 * peer_remove - Remove a peer from the table
 *
 * @param table           Peer table
 * @param peer            Peer to remove
 */
void peer_remove(peer_table *table, peer_t *peer);

/*
 * ===========================================================================
 * Peer Configuration
 * ===========================================================================
 */

/*
 * peer_set_endpoint - Set peer's network endpoint
 *
 * @param peer    Peer to configure
 * @param addr    IP address
 * @param port    UDP port
 * @param is_ipv6 True if IPv6 address
 */
void peer_set_endpoint(peer_t *peer,
                       const uint8_t *addr,
                       uint16_t port,
                       bool is_ipv6);

/*
 * peer_add_allowed_ip - Add an allowed IP range
 *
 * @param peer        Peer to configure
 * @param addr        Network address
 * @param prefix_len  Prefix length (e.g., 24 for /24)
 * @param is_ipv6     True if IPv6
 * @return            VPN_OK or error
 */
vpn_error_t peer_add_allowed_ip(peer_t *peer,
                                const uint8_t *addr,
                                uint8_t prefix_len,
                                bool is_ipv6);

/*
 * peer_set_preshared_key - Set pre-shared key for peer
 *
 * @param peer  Peer to configure
 * @param psk   32-byte pre-shared key
 */
void peer_set_preshared_key(peer_t *peer, const uint8_t psk[32]);

/*
 * peer_set_keepalive - Set persistent keepalive interval
 *
 * @param peer      Peer to configure
 * @param interval  Seconds between keepalives (0 to disable)
 */
void peer_set_keepalive(peer_t *peer, uint16_t interval);

/*
 * ===========================================================================
 * Session Management
 * ===========================================================================
 */

/*
 * peer_initiate_handshake - Start a handshake with peer
 *
 * Creates handshake initiation message.
 *
 * @param peer      Peer to handshake with
 * @param table     Peer table (for our keys)
 * @param out       Output buffer for initiation message
 * @return          Message length or negative error
 */
int peer_initiate_handshake(peer_t *peer,
                            peer_table *table,
                            uint8_t *out);

/*
 * peer_respond_handshake - Respond to handshake initiation
 *
 * Processes initiation and creates response message.
 *
 * @param peer      Peer who sent initiation
 * @param table     Peer table (for our keys)
 * @param init_msg  Received initiation message
 * @param init_len  Message length
 * @param out       Output buffer for response message
 * @return          Message length or negative error
 */
int peer_respond_handshake(peer_t *peer,
                           peer_table *table,
                           const uint8_t *init_msg, size_t init_len,
                           uint8_t *out);

/*
 * peer_complete_handshake - Complete handshake as initiator
 *
 * Processes response and derives session keys.
 *
 * @param peer      Peer who sent response
 * @param resp_msg  Received response message
 * @param resp_len  Message length
 * @return          VPN_OK or error
 */
vpn_error_t peer_complete_handshake(peer_t *peer,
                                    const uint8_t *resp_msg, size_t resp_len);

/*
 * peer_session_valid - Check if peer has valid session
 *
 * @param peer      Peer to check
 * @return          True if session is usable
 */
bool peer_session_valid(const peer_t *peer);

/*
 * peer_needs_handshake - Check if peer needs new handshake
 *
 * @param peer      Peer to check
 * @return          True if handshake should be initiated
 */
bool peer_needs_handshake(const peer_t *peer);

/*
 * ===========================================================================
 * Data Operations
 * ===========================================================================
 */

/*
 * peer_encrypt_data - Encrypt data for peer
 *
 * @param peer      Destination peer
 * @param out       Output buffer
 * @param data      Plaintext data
 * @param data_len  Data length
 * @return          Encrypted message length or negative error
 */
int peer_encrypt_data(peer_t *peer,
                      uint8_t *out,
                      const uint8_t *data, size_t data_len);

/*
 * peer_decrypt_data - Decrypt data from peer
 *
 * @param peer      Source peer
 * @param out       Output buffer
 * @param out_len   Output: decrypted data length
 * @param packet    Encrypted packet
 * @param pkt_len   Packet length
 * @return          VPN_OK or error
 */
vpn_error_t peer_decrypt_data(peer_t *peer,
                              uint8_t *out, size_t *out_len,
                              const uint8_t *packet, size_t pkt_len);

/*
 * ===========================================================================
 * Routing
 * ===========================================================================
 */

/*
 * peer_lookup_by_ip - Find peer for routing by destination IP
 *
 * Returns the peer whose allowed_ips match the destination.
 *
 * @param table     Peer table
 * @param ip        Destination IP address
 * @param is_ipv6   True if IPv6
 * @return          Peer to route through, or NULL if no match
 */
peer_t *peer_lookup_by_ip(peer_table *table,
                          const uint8_t *ip,
                          bool is_ipv6);

/*
 * peer_check_source_ip - Verify source IP is allowed for peer
 *
 * @param peer      Peer who sent packet
 * @param ip        Source IP address
 * @param is_ipv6   True if IPv6
 * @return          True if IP is in peer's allowed ranges
 */
bool peer_check_source_ip(const peer_t *peer,
                          const uint8_t *ip,
                          bool is_ipv6);

#endif /* VPN_PEER_H */
