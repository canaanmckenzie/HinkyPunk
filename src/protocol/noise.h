/*
 * noise.h - Noise Protocol Framework Implementation
 * ==================================================
 *
 * The Noise Protocol Framework is a modern approach to cryptographic handshakes.
 * WireGuard uses the "IK" pattern from Noise for its key exchange.
 *
 * WHAT IS NOISE?
 *
 * Noise is a framework for building secure channel protocols. Instead of
 * inventing your own handshake (and probably getting it wrong), you choose
 * a "pattern" that specifies the message flow and key operations.
 *
 * Each pattern is named like "XX", "IK", "NK", etc., where:
 *   - First letter: Initiator's static key handling (X=transmitted, I=known, N=none)
 *   - Second letter: Responder's static key handling
 *
 * WHY NOISE?
 *
 * 1. PROVEN SECURITY: Patterns have been analyzed by cryptographers
 * 2. SIMPLICITY: Clear specification, hard to misimplement
 * 3. FLEXIBILITY: Choose the pattern that fits your threat model
 * 4. MODERN: Uses state-of-the-art primitives (Curve25519, ChaCha20-Poly1305)
 *
 * WireGuard's "IK" PATTERN:
 *
 * In IK (Initiator Known), the initiator already knows the responder's static
 * public key. This is typical for VPNs where you configure the peer's key.
 *
 * Message flow:
 *   -> e, es, s, ss    (Initiator sends: ephemeral pubkey, encrypted static pubkey)
 *   <- e, ee, se       (Responder sends: ephemeral pubkey)
 *
 * Where:
 *   e = ephemeral public key
 *   s = static public key (encrypted)
 *   es = DH(ephemeral_initiator, static_responder)
 *   ee = DH(ephemeral_initiator, ephemeral_responder)
 *   se = DH(static_initiator, ephemeral_responder)
 *   ss = DH(static_initiator, static_responder)
 *
 * After the handshake, both parties derive the same symmetric keys.
 *
 * NOISE CONCEPTS:
 *
 * - Chaining Key (CK): Accumulated key material, updated after each DH
 * - Hash (H): Hash of the entire handshake transcript
 * - Symmetric State: Holds CK, H, and current encryption key
 *
 * The handshake uses "MixKey" and "MixHash" operations to fold new
 * material into the state:
 *
 *   MixKey(input): (CK, K) = HKDF(CK, input)  // Derive new chaining key and temp key
 *   MixHash(data): H = HASH(H || data)        // Hash data into transcript
 *
 * AUTHENTICATION:
 *
 * Each encrypted payload includes the hash H as "associated data" in the AEAD.
 * This binds the ciphertext to the entire transcript, preventing tampering.
 *
 * REPLAY PROTECTION:
 *
 * WireGuard adds TAI64N timestamps to handshake messages. The responder rejects
 * messages with timestamps not newer than the last seen, preventing replay attacks.
 */

#ifndef VPN_NOISE_H
#define VPN_NOISE_H

#include "../types.h"

/*
 * Protocol identifiers (for domain separation)
 *
 * WireGuard uses "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" as its protocol name.
 * We'll simplify slightly for this educational implementation.
 */
#define NOISE_PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s"
#define NOISE_PROTOCOL_NAME_LEN 36

/*
 * Construction label (used in hash initialization)
 */
#define NOISE_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

/*
 * Timestamp size (TAI64N format: 8 bytes epoch + 4 bytes nanoseconds)
 */
#define NOISE_TIMESTAMP_SIZE 12

/*
 * ===========================================================================
 * Noise Handshake State
 * ===========================================================================
 */

/*
 * Symmetric state maintained during handshake
 *
 * This tracks:
 *   - h: Hash of all handshake data (used as AEAD associated data)
 *   - ck: Chaining key for key derivation
 *   - k: Current encryption key (derived during handshake)
 *   - n: Nonce counter for AEAD
 *   - has_key: Whether k is valid for encryption
 */
typedef struct {
    uint8_t h[32];      /* Handshake hash */
    uint8_t ck[32];     /* Chaining key */
    uint8_t k[32];      /* Encryption key (when has_key is true) */
    uint64_t n;         /* Nonce counter */
    bool has_key;       /* Is k valid? */
} noise_symmetric_state;

/*
 * Handshake state
 *
 * Holds all state needed to execute a Noise handshake:
 *   - Symmetric state (as above)
 *   - Our static and ephemeral key pairs
 *   - Peer's static and ephemeral public keys
 *   - Role (initiator or responder)
 */
typedef struct {
    noise_symmetric_state symmetric;

    /* Our keys */
    uint8_t s[32];      /* Our static private key */
    uint8_t s_pub[32];  /* Our static public key */
    uint8_t e[32];      /* Our ephemeral private key */
    uint8_t e_pub[32];  /* Our ephemeral public key */

    /* Peer's keys */
    uint8_t rs[32];     /* Peer's static public key (known beforehand for IK) */
    uint8_t re[32];     /* Peer's ephemeral public key (received in handshake) */

    /* Session state */
    bool is_initiator;  /* Are we the initiator? */
    bool handshake_complete;
} noise_handshake_state;

/*
 * Transport state (after handshake)
 *
 * Once the handshake completes, we derive transport keys for encrypting data.
 * Each direction has its own key to prevent reflection attacks.
 */
typedef struct {
    uint8_t send_key[32];   /* Key for encrypting outgoing data */
    uint8_t recv_key[32];   /* Key for decrypting incoming data */
    uint64_t send_nonce;    /* Nonce counter for sending */
    uint64_t recv_nonce;    /* Nonce counter for receiving */
    bool valid;             /* Is this state usable? */
} noise_transport_state;

/*
 * ===========================================================================
 * Symmetric State Operations
 * ===========================================================================
 */

/*
 * noise_init_symmetric - Initialize symmetric state with protocol name
 *
 * Sets h = HASH(protocol_name) or HASH(zeros || protocol_name) if name is short.
 * Sets ck = h.
 *
 * @param state     State to initialize
 */
void noise_init_symmetric(noise_symmetric_state *state);

/*
 * noise_mix_key - Mix key material into chaining key
 *
 * (ck, k) = HKDF(ck, input)
 * Sets has_key = true.
 *
 * @param state     Symmetric state
 * @param input     Key material to mix (typically DH output)
 * @param input_len Length of input (usually 32)
 */
void noise_mix_key(noise_symmetric_state *state,
                   const uint8_t *input, size_t input_len);

/*
 * noise_mix_hash - Mix data into handshake hash
 *
 * h = HASH(h || data)
 *
 * @param state     Symmetric state
 * @param data      Data to hash in
 * @param data_len  Length of data
 */
void noise_mix_hash(noise_symmetric_state *state,
                    const uint8_t *data, size_t data_len);

/*
 * noise_mix_key_and_hash - Mix data into both ck and h (for PSK)
 *
 * temp = HKDF(ck, data)
 * ck = temp[0..31]
 * k = temp[32..63]
 * h = HASH(h || temp[64..95])
 *
 * @param state     Symmetric state
 * @param data      Data to mix (typically PSK)
 * @param data_len  Length of data
 */
void noise_mix_key_and_hash(noise_symmetric_state *state,
                            const uint8_t *data, size_t data_len);

/*
 * noise_encrypt_and_hash - Encrypt plaintext and mix ciphertext into hash
 *
 * If has_key:
 *   ciphertext = AEAD_Encrypt(k, n++, h, plaintext)
 * Else:
 *   ciphertext = plaintext (no encryption)
 *
 * h = HASH(h || ciphertext)
 *
 * @param state     Symmetric state
 * @param out       Output ciphertext buffer
 * @param in        Input plaintext
 * @param in_len    Plaintext length
 * @return          Ciphertext length (in_len or in_len + 16 if encrypted)
 */
size_t noise_encrypt_and_hash(noise_symmetric_state *state,
                              uint8_t *out,
                              const uint8_t *in, size_t in_len);

/*
 * noise_decrypt_and_hash - Decrypt ciphertext and mix into hash
 *
 * h_copy = h
 * h = HASH(h || ciphertext)
 *
 * If has_key:
 *   plaintext = AEAD_Decrypt(k, n++, h_copy, ciphertext)
 * Else:
 *   plaintext = ciphertext
 *
 * @param state     Symmetric state
 * @param out       Output plaintext buffer
 * @param in        Input ciphertext
 * @param in_len    Ciphertext length
 * @return          VPN_OK or VPN_ERR_AUTH if decryption fails
 */
vpn_error_t noise_decrypt_and_hash(noise_symmetric_state *state,
                                   uint8_t *out,
                                   const uint8_t *in, size_t in_len);

/*
 * noise_split - Derive transport keys from final handshake state
 *
 * (send_key, recv_key) = HKDF(ck, "")
 * The order depends on whether we're initiator or responder.
 *
 * @param state         Final symmetric state
 * @param transport     Transport state to initialize
 * @param is_initiator  Are we the initiator?
 */
void noise_split(const noise_symmetric_state *state,
                 noise_transport_state *transport,
                 bool is_initiator);

/*
 * ===========================================================================
 * Handshake Operations
 * ===========================================================================
 */

/*
 * noise_handshake_init - Initialize handshake as initiator
 *
 * Sets up state for initiating a handshake. You must provide your static
 * key pair and the peer's static public key.
 *
 * @param state             Handshake state to initialize
 * @param static_private    Our static private key (32 bytes)
 * @param static_public     Our static public key (32 bytes)
 * @param peer_static       Peer's static public key (32 bytes)
 */
void noise_handshake_init_initiator(noise_handshake_state *state,
                                    const uint8_t static_private[32],
                                    const uint8_t static_public[32],
                                    const uint8_t peer_static[32]);

/*
 * noise_handshake_init - Initialize handshake as responder
 *
 * Sets up state for responding to a handshake. You must provide your
 * static key pair. Peer's keys will be learned during handshake.
 *
 * @param state             Handshake state to initialize
 * @param static_private    Our static private key (32 bytes)
 * @param static_public     Our static public key (32 bytes)
 */
void noise_handshake_init_responder(noise_handshake_state *state,
                                    const uint8_t static_private[32],
                                    const uint8_t static_public[32]);

/*
 * noise_create_initiation - Create handshake initiation message
 *
 * Initiator creates message 1: e, es, s, ss, timestamp
 *
 * @param state     Initialized initiator state
 * @param message   Output buffer (must be at least 148 bytes)
 * @return          Message length or negative error
 */
int noise_create_initiation(noise_handshake_state *state,
                            uint8_t *message);

/*
 * noise_consume_initiation - Process received initiation message
 *
 * Responder processes message 1, learns initiator's keys.
 *
 * @param state     Initialized responder state
 * @param message   Received message
 * @param msg_len   Message length
 * @return          VPN_OK or error code
 */
vpn_error_t noise_consume_initiation(noise_handshake_state *state,
                                     const uint8_t *message, size_t msg_len);

/*
 * noise_create_response - Create handshake response message
 *
 * Responder creates message 2: e, ee, se, empty
 *
 * @param state     State after processing initiation
 * @param message   Output buffer (must be at least 92 bytes)
 * @return          Message length or negative error
 */
int noise_create_response(noise_handshake_state *state,
                          uint8_t *message);

/*
 * noise_consume_response - Process received response message
 *
 * Initiator processes message 2, completes handshake.
 *
 * @param state     State after sending initiation
 * @param message   Received message
 * @param msg_len   Message length
 * @return          VPN_OK or error code
 */
vpn_error_t noise_consume_response(noise_handshake_state *state,
                                   const uint8_t *message, size_t msg_len);

/*
 * noise_handshake_complete - Check if handshake is finished
 *
 * @param state     Handshake state
 * @return          true if handshake is complete
 */
bool noise_handshake_complete(const noise_handshake_state *state);

/*
 * noise_derive_transport - Derive transport keys from completed handshake
 *
 * @param state     Completed handshake state
 * @param transport Transport state to initialize
 * @return          VPN_OK or error if handshake not complete
 */
vpn_error_t noise_derive_transport(const noise_handshake_state *state,
                                   noise_transport_state *transport);

/*
 * ===========================================================================
 * Transport Operations
 * ===========================================================================
 */

/*
 * noise_transport_encrypt - Encrypt a data packet
 *
 * @param state     Transport state
 * @param out       Output buffer (must be in_len + 16 bytes)
 * @param in        Input plaintext
 * @param in_len    Plaintext length
 * @return          Ciphertext length (in_len + 16)
 */
size_t noise_transport_encrypt(noise_transport_state *state,
                               uint8_t *out,
                               const uint8_t *in, size_t in_len);

/*
 * noise_transport_decrypt - Decrypt a data packet
 *
 * @param state     Transport state
 * @param out       Output buffer (must be in_len - 16 bytes)
 * @param in        Input ciphertext
 * @param in_len    Ciphertext length (must be >= 16)
 * @return          VPN_OK or VPN_ERR_AUTH
 */
vpn_error_t noise_transport_decrypt(noise_transport_state *state,
                                    uint8_t *out,
                                    const uint8_t *in, size_t in_len);

#endif /* VPN_NOISE_H */
