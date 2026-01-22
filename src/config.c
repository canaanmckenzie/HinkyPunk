/*
 * config.c - Configuration File Parsing Implementation
 * =====================================================
 */

#include "config.h"
#include "util/memory.h"
#include "util/random.h"
#include "util/log.h"
#include "crypto/curve25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
 * ===========================================================================
 * Base64 Encoding/Decoding
 * ===========================================================================
 */

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int base64_index[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

void config_key_to_base64(char *out, const uint8_t key[32])
{
    int i, j;
    uint32_t v;

    for (i = 0, j = 0; i < 30; i += 3, j += 4) {
        v = ((uint32_t)key[i] << 16) | ((uint32_t)key[i+1] << 8) | key[i+2];
        out[j]   = base64_chars[(v >> 18) & 0x3F];
        out[j+1] = base64_chars[(v >> 12) & 0x3F];
        out[j+2] = base64_chars[(v >> 6) & 0x3F];
        out[j+3] = base64_chars[v & 0x3F];
    }

    /* Last 2 bytes with padding */
    v = ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 8);
    out[40] = base64_chars[(v >> 18) & 0x3F];
    out[41] = base64_chars[(v >> 12) & 0x3F];
    out[42] = base64_chars[(v >> 6) & 0x3F];
    out[43] = '=';
    out[44] = '\0';
}

vpn_error_t config_key_from_base64(uint8_t out[32], const char *base64)
{
    size_t len = strlen(base64);
    int i, j;
    int idx[4];
    uint32_t v;

    /* Expected: 44 characters (43 + padding or 44 with =) */
    if (len < 43 || len > 44) {
        return VPN_ERR_INVALID;
    }

    /* Decode 30 bytes (40 characters) */
    for (i = 0, j = 0; i < 40; i += 4, j += 3) {
        idx[0] = base64_index[(unsigned char)base64[i]];
        idx[1] = base64_index[(unsigned char)base64[i+1]];
        idx[2] = base64_index[(unsigned char)base64[i+2]];
        idx[3] = base64_index[(unsigned char)base64[i+3]];

        if (idx[0] < 0 || idx[1] < 0 || idx[2] < 0 || idx[3] < 0) {
            return VPN_ERR_INVALID;
        }

        v = ((uint32_t)idx[0] << 18) | ((uint32_t)idx[1] << 12) |
            ((uint32_t)idx[2] << 6) | idx[3];

        out[j]   = (uint8_t)(v >> 16);
        out[j+1] = (uint8_t)(v >> 8);
        out[j+2] = (uint8_t)v;
    }

    /* Decode last 2 bytes (4 characters with padding) */
    idx[0] = base64_index[(unsigned char)base64[40]];
    idx[1] = base64_index[(unsigned char)base64[41]];
    idx[2] = base64_index[(unsigned char)base64[42]];

    if (idx[0] < 0 || idx[1] < 0 || idx[2] < 0) {
        return VPN_ERR_INVALID;
    }

    v = ((uint32_t)idx[0] << 18) | ((uint32_t)idx[1] << 12) | ((uint32_t)idx[2] << 6);
    out[30] = (uint8_t)(v >> 16);
    out[31] = (uint8_t)(v >> 8);

    return VPN_OK;
}

vpn_error_t config_key_from_hex(uint8_t out[32], const char *hex)
{
    size_t len = strlen(hex);
    size_t i;

    if (len != 64) {
        return VPN_ERR_INVALID;
    }

    for (i = 0; i < 32; i++) {
        char byte_hex[3] = { hex[i*2], hex[i*2+1], 0 };
        char *endp;
        long val = strtol(byte_hex, &endp, 16);
        if (*endp != '\0' || val < 0 || val > 255) {
            return VPN_ERR_INVALID;
        }
        out[i] = (uint8_t)val;
    }

    return VPN_OK;
}

/*
 * ===========================================================================
 * String Utilities
 * ===========================================================================
 */

static char *trim(char *str)
{
    char *end;

    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;

    /* Trim trailing whitespace */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

static bool starts_with(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/*
 * ===========================================================================
 * Configuration Initialization
 * ===========================================================================
 */

void config_init(vpn_config *config)
{
    vpn_memzero(config, sizeof(*config));
    config->interface.mtu = 1420;  /* Default MTU */
    config->interface.listen_port = 51820;  /* Default port */
}

void config_free(vpn_config *config)
{
    /* Zero out sensitive data */
    vpn_memzero(config->interface.private_key, 32);
    for (int i = 0; i < config->num_peers; i++) {
        vpn_memzero(config->peers[i].preshared_key, 32);
    }
    vpn_memzero(config, sizeof(*config));
}

/*
 * ===========================================================================
 * Configuration Parsing
 * ===========================================================================
 */

typedef enum {
    SECTION_NONE,
    SECTION_INTERFACE,
    SECTION_PEER
} section_type;

static vpn_error_t parse_interface_line(config_interface *iface, const char *key, const char *value)
{
    if (strcmp(key, "PrivateKey") == 0) {
        /* Try base64 first, then hex */
        if (strlen(value) == 44) {
            if (config_key_from_base64(iface->private_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else if (strlen(value) == 64) {
            if (config_key_from_hex(iface->private_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else {
            return VPN_ERR_CONFIG;
        }
        curve25519_keygen(iface->public_key, iface->private_key);
        iface->has_private_key = true;
    } else if (strcmp(key, "Address") == 0) {
        strncpy(iface->address, value, sizeof(iface->address) - 1);
        iface->has_address = true;
    } else if (strcmp(key, "ListenPort") == 0) {
        iface->listen_port = (uint16_t)atoi(value);
        iface->has_listen_port = true;
    } else if (strcmp(key, "MTU") == 0) {
        iface->mtu = (uint32_t)atoi(value);
        iface->has_mtu = true;
    } else if (strcmp(key, "DNS") == 0) {
        strncpy(iface->dns, value, sizeof(iface->dns) - 1);
        iface->has_dns = true;
    } else if (strcmp(key, "FwMark") == 0) {
        iface->fwmark = (uint32_t)strtoul(value, NULL, 0);
        iface->has_fwmark = true;
    } else {
        LOG_WARN("Unknown interface key: %s", key);
    }

    return VPN_OK;
}

static vpn_error_t parse_peer_line(config_peer *peer, const char *key, const char *value)
{
    if (strcmp(key, "PublicKey") == 0) {
        if (strlen(value) == 44) {
            if (config_key_from_base64(peer->public_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else if (strlen(value) == 64) {
            if (config_key_from_hex(peer->public_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else {
            return VPN_ERR_CONFIG;
        }
        peer->has_public_key = true;
    } else if (strcmp(key, "PresharedKey") == 0) {
        if (strlen(value) == 44) {
            if (config_key_from_base64(peer->preshared_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else if (strlen(value) == 64) {
            if (config_key_from_hex(peer->preshared_key, value) != VPN_OK) {
                return VPN_ERR_CONFIG;
            }
        } else {
            return VPN_ERR_CONFIG;
        }
        peer->has_preshared_key = true;
    } else if (strcmp(key, "Endpoint") == 0) {
        strncpy(peer->endpoint, value, sizeof(peer->endpoint) - 1);
        peer->has_endpoint = true;
    } else if (strcmp(key, "AllowedIPs") == 0) {
        /* Parse comma-separated list of CIDRs */
        char *copy = strdup(value);
        char *token = strtok(copy, ",");
        while (token && peer->num_allowed_ips < CONFIG_MAX_ALLOWED_IPS) {
            token = trim(token);
            if (*token) {
                strncpy(peer->allowed_ips[peer->num_allowed_ips].cidr, token,
                        sizeof(peer->allowed_ips[0].cidr) - 1);
                peer->num_allowed_ips++;
            }
            token = strtok(NULL, ",");
        }
        free(copy);
    } else if (strcmp(key, "PersistentKeepalive") == 0) {
        peer->persistent_keepalive = (uint16_t)atoi(value);
        peer->has_persistent_keepalive = true;
    } else {
        LOG_WARN("Unknown peer key: %s", key);
    }

    return VPN_OK;
}

vpn_error_t config_load(vpn_config *config, const char *path)
{
    FILE *f;
    char line[CONFIG_MAX_LINE];
    section_type section = SECTION_NONE;
    config_peer *current_peer = NULL;
    int line_num = 0;

    f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        return VPN_ERR_CONFIG;
    }

    strncpy(config->config_path, path, sizeof(config->config_path) - 1);

    while (fgets(line, sizeof(line), f)) {
        char *trimmed;
        char *equals;
        char *key, *value;

        line_num++;
        trimmed = trim(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#') {
            continue;
        }

        /* Section header */
        if (*trimmed == '[') {
            if (strcmp(trimmed, "[Interface]") == 0) {
                section = SECTION_INTERFACE;
            } else if (strcmp(trimmed, "[Peer]") == 0) {
                section = SECTION_PEER;
                if (config->num_peers >= CONFIG_MAX_PEERS) {
                    LOG_ERROR("Too many peers in config");
                    fclose(f);
                    return VPN_ERR_CONFIG;
                }
                current_peer = &config->peers[config->num_peers++];
                vpn_memzero(current_peer, sizeof(*current_peer));
            } else {
                LOG_WARN("Unknown section: %s (line %d)", trimmed, line_num);
            }
            continue;
        }

        /* Key = Value */
        equals = strchr(trimmed, '=');
        if (!equals) {
            LOG_WARN("Invalid config line %d: %s", line_num, trimmed);
            continue;
        }

        *equals = '\0';
        key = trim(trimmed);
        value = trim(equals + 1);

        vpn_error_t err = VPN_OK;
        switch (section) {
            case SECTION_INTERFACE:
                err = parse_interface_line(&config->interface, key, value);
                break;
            case SECTION_PEER:
                if (current_peer) {
                    err = parse_peer_line(current_peer, key, value);
                }
                break;
            default:
                LOG_WARN("Config key outside section: %s (line %d)", key, line_num);
                break;
        }

        if (err != VPN_OK) {
            LOG_ERROR("Error parsing config line %d: %s = %s", line_num, key, value);
            fclose(f);
            return err;
        }
    }

    fclose(f);
    config->loaded = true;

    return config_validate(config);
}

vpn_error_t config_validate(const vpn_config *config)
{
    /* Must have private key */
    if (!config->interface.has_private_key) {
        LOG_ERROR("Configuration missing PrivateKey");
        return VPN_ERR_CONFIG;
    }

    /* Each peer must have public key */
    for (int i = 0; i < config->num_peers; i++) {
        if (!config->peers[i].has_public_key) {
            LOG_ERROR("Peer %d missing PublicKey", i + 1);
            return VPN_ERR_CONFIG;
        }
    }

    return VPN_OK;
}

vpn_error_t config_save(const vpn_config *config, const char *path)
{
    FILE *f;
    char key_b64[45];
    int i, j;

    f = fopen(path, "w");
    if (!f) {
        return VPN_ERR_CONFIG;
    }

    /* Interface section */
    fprintf(f, "[Interface]\n");
    if (config->interface.has_private_key) {
        config_key_to_base64(key_b64, config->interface.private_key);
        fprintf(f, "PrivateKey = %s\n", key_b64);
    }
    if (config->interface.has_address) {
        fprintf(f, "Address = %s\n", config->interface.address);
    }
    if (config->interface.has_listen_port) {
        fprintf(f, "ListenPort = %u\n", config->interface.listen_port);
    }
    if (config->interface.has_mtu) {
        fprintf(f, "MTU = %u\n", config->interface.mtu);
    }
    if (config->interface.has_dns) {
        fprintf(f, "DNS = %s\n", config->interface.dns);
    }

    /* Peer sections */
    for (i = 0; i < config->num_peers; i++) {
        const config_peer *peer = &config->peers[i];

        fprintf(f, "\n[Peer]\n");
        if (peer->has_public_key) {
            config_key_to_base64(key_b64, peer->public_key);
            fprintf(f, "PublicKey = %s\n", key_b64);
        }
        if (peer->has_preshared_key) {
            config_key_to_base64(key_b64, peer->preshared_key);
            fprintf(f, "PresharedKey = %s\n", key_b64);
        }
        if (peer->has_endpoint) {
            fprintf(f, "Endpoint = %s\n", peer->endpoint);
        }
        if (peer->num_allowed_ips > 0) {
            fprintf(f, "AllowedIPs = ");
            for (j = 0; j < peer->num_allowed_ips; j++) {
                if (j > 0) fprintf(f, ", ");
                fprintf(f, "%s", peer->allowed_ips[j].cidr);
            }
            fprintf(f, "\n");
        }
        if (peer->has_persistent_keepalive && peer->persistent_keepalive > 0) {
            fprintf(f, "PersistentKeepalive = %u\n", peer->persistent_keepalive);
        }
    }

    fclose(f);
    return VPN_OK;
}

vpn_error_t config_generate_keypair(uint8_t private_key[32], uint8_t public_key[32])
{
    vpn_error_t err = vpn_random_bytes(private_key, 32);
    if (err != VPN_OK) {
        return err;
    }

    curve25519_clamp(private_key);
    curve25519_keygen(public_key, private_key);

    return VPN_OK;
}
