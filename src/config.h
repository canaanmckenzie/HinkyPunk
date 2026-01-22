/*
 * config.h - Configuration File Parsing
 * ======================================
 *
 * This module handles parsing of VPN configuration files in a format
 * similar to WireGuard's .conf files:
 *
 * [Interface]
 * PrivateKey = <base64-encoded-key>
 * Address = 10.0.0.1/24
 * ListenPort = 51820
 *
 * [Peer]
 * PublicKey = <base64-encoded-key>
 * AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
 * Endpoint = 192.168.1.1:51820
 * PersistentKeepalive = 25
 *
 * KEY ENCODING:
 *
 * Keys are encoded in base64 (32 bytes -> 44 characters with padding).
 * This is the standard format used by WireGuard's `wg genkey` and `wg pubkey`.
 */

#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include "types.h"
#include "protocol/peer.h"

/*
 * Maximum configuration limits
 */
#define CONFIG_MAX_PEERS        64
#define CONFIG_MAX_ALLOWED_IPS  32
#define CONFIG_MAX_LINE         1024
#define CONFIG_MAX_PATH         256

/*
 * Interface configuration
 */
typedef struct {
    uint8_t private_key[32];            /* Interface private key */
    uint8_t public_key[32];             /* Derived public key */
    bool has_private_key;

    char address[64];                   /* Interface IP address */
    uint8_t address_prefix;             /* CIDR prefix */
    bool has_address;

    uint16_t listen_port;               /* UDP listen port */
    bool has_listen_port;

    uint32_t fwmark;                    /* Firewall mark */
    bool has_fwmark;

    uint32_t mtu;                       /* Interface MTU */
    bool has_mtu;

    char dns[256];                      /* DNS servers */
    bool has_dns;
} config_interface;

/*
 * Peer configuration
 */
typedef struct {
    uint8_t public_key[32];             /* Peer's public key */
    bool has_public_key;

    uint8_t preshared_key[32];          /* Pre-shared key (optional) */
    bool has_preshared_key;

    char endpoint[128];                 /* Endpoint address:port */
    bool has_endpoint;

    struct {
        char cidr[64];                  /* CIDR notation */
    } allowed_ips[CONFIG_MAX_ALLOWED_IPS];
    int num_allowed_ips;

    uint16_t persistent_keepalive;      /* Keepalive interval */
    bool has_persistent_keepalive;
} config_peer;

/*
 * Complete configuration
 */
typedef struct {
    config_interface interface;
    config_peer peers[CONFIG_MAX_PEERS];
    int num_peers;
    char config_path[CONFIG_MAX_PATH];
    bool loaded;
} vpn_config;

/*
 * ===========================================================================
 * Configuration Loading
 * ===========================================================================
 */

/*
 * config_init - Initialize configuration structure
 *
 * @param config    Configuration to initialize
 */
void config_init(vpn_config *config);

/*
 * config_load - Load configuration from file
 *
 * @param config    Configuration structure to populate
 * @param path      Path to configuration file
 * @return          VPN_OK on success, error code on failure
 *
 * EXAMPLE:
 *   vpn_config config;
 *   config_init(&config);
 *   if (config_load(&config, "/etc/vpn/wg0.conf") != VPN_OK) {
 *       LOG_ERROR("Failed to load config");
 *   }
 */
vpn_error_t config_load(vpn_config *config, const char *path);

/*
 * config_save - Save configuration to file
 *
 * @param config    Configuration to save
 * @param path      Path to configuration file
 * @return          VPN_OK on success
 */
vpn_error_t config_save(const vpn_config *config, const char *path);

/*
 * config_free - Free configuration resources
 *
 * @param config    Configuration to free
 */
void config_free(vpn_config *config);

/*
 * ===========================================================================
 * Configuration Validation
 * ===========================================================================
 */

/*
 * config_validate - Validate configuration
 *
 * @param config    Configuration to validate
 * @return          VPN_OK if valid, error code otherwise
 */
vpn_error_t config_validate(const vpn_config *config);

/*
 * ===========================================================================
 * Key Encoding
 * ===========================================================================
 */

/*
 * config_key_to_base64 - Encode a 32-byte key to base64
 *
 * @param out       Output buffer (at least 45 bytes)
 * @param key       32-byte key
 */
void config_key_to_base64(char *out, const uint8_t key[32]);

/*
 * config_key_from_base64 - Decode a base64 key to 32 bytes
 *
 * @param out       32-byte output buffer
 * @param base64    Base64-encoded key
 * @return          VPN_OK on success
 */
vpn_error_t config_key_from_base64(uint8_t out[32], const char *base64);

/*
 * config_key_from_hex - Decode a hex key to 32 bytes
 *
 * @param out       32-byte output buffer
 * @param hex       64-character hex string
 * @return          VPN_OK on success
 */
vpn_error_t config_key_from_hex(uint8_t out[32], const char *hex);

/*
 * ===========================================================================
 * Configuration Generation
 * ===========================================================================
 */

/*
 * config_generate_keypair - Generate a new keypair
 *
 * @param private_key   Output: 32-byte private key
 * @param public_key    Output: 32-byte public key
 * @return              VPN_OK on success
 */
vpn_error_t config_generate_keypair(uint8_t private_key[32], uint8_t public_key[32]);

#endif /* VPN_CONFIG_H */
