/*
 * main.c - VPN Main Program
 * ==========================
 *
 * This is the entry point for our WireGuard-like VPN. It demonstrates how all
 * the components (crypto, protocol, network) work together.
 *
 * USAGE:
 *
 *   vpn [OPTIONS]
 *
 * OPTIONS:
 *   -l <port>           Listen port (default: 51820)
 *   -k <keyfile>        Private key file
 *   -p <peer>           Add peer: <pubkey>@<endpoint>
 *   -i <ip/prefix>      Set tunnel IP address
 *   -r <ip/prefix>      Add allowed IP for last peer
 *   -h                  Show help
 *
 * EXAMPLE:
 *
 *   # Server (listens on 51820, accepts connections)
 *   vpn -l 51820 -k server.key -i 10.0.0.1/24
 *
 *   # Client (connects to server)
 *   vpn -l 51821 -k client.key -i 10.0.0.2/24 \
 *       -p <server_pubkey>@192.168.1.1:51820 -r 10.0.0.0/24
 *
 * HOW IT WORKS:
 *
 * 1. Initialize crypto primitives and peer table
 * 2. Create UDP socket for transport
 * 3. Create TUN interface for tunnel
 * 4. Main loop:
 *    a. Read from TUN -> encrypt -> send via UDP
 *    b. Read from UDP -> decrypt -> write to TUN
 *    c. Handle handshakes as needed
 *
 * This is a simplified implementation for educational purposes. A production
 * VPN would need:
 * - Multi-threading or async I/O for better performance
 * - Proper timer management for rekeys and keepalives
 * - Signal handling for graceful shutdown
 * - Configuration file parsing
 * - Logging and monitoring
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "types.h"
#include "config.h"
#include "crypto/curve25519.h"
#include "crypto/blake2s.h"
#include "protocol/peer.h"
#include "protocol/packet.h"
#include "protocol/timers.h"
#include "net/udp.h"
#include "net/tun.h"
#include "util/memory.h"
#include "util/random.h"
#include "util/log.h"

/*
 * ===========================================================================
 * Configuration
 * ===========================================================================
 */

typedef struct {
    uint16_t listen_port;
    char keyfile[256];
    char tunnel_ip[64];
    uint8_t tunnel_prefix;
    bool tunnel_ipv6;

    /* Configured peers (from command line) */
    struct {
        char pubkey_hex[65];
        char endpoint[128];
        char allowed_ips[16][64];
        int num_allowed_ips;
    } peers[MAX_PEERS];
    int num_peers;
} config_t;

/*
 * ===========================================================================
 * Global State
 * ===========================================================================
 */

static volatile bool running = true;
static peer_table g_peers;
static udp_t g_udp;
static tun_t g_tun;
static config_t g_config;

/*
 * ===========================================================================
 * Signal Handler
 * ===========================================================================
 */

static void signal_handler(int sig)
{
    UNUSED(sig);
    running = false;
    printf("\nShutting down...\n");
}

/*
 * ===========================================================================
 * Utility Functions
 * ===========================================================================
 */

/*
 * Parse hex string to bytes
 */
static int hex_to_bytes(uint8_t *out, size_t out_len, const char *hex)
{
    size_t hex_len = strlen(hex);
    size_t i;

    if (hex_len != out_len * 2) {
        return -1;
    }

    for (i = 0; i < out_len; i++) {
        char byte_hex[3] = { hex[i*2], hex[i*2+1], 0 };
        char *endp;
        long val = strtol(byte_hex, &endp, 16);
        if (*endp != '\0' || val < 0 || val > 255) {
            return -1;
        }
        out[i] = (uint8_t)val;
    }

    return 0;
}

/*
 * Format bytes as hex string
 */
static void bytes_to_hex(char *out, const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", data[i]);
    }
}

/*
 * Generate a random private key using CSPRNG
 */
static vpn_error_t generate_private_key(uint8_t key[32])
{
    vpn_error_t err;

    err = vpn_random_bytes(key, 32);
    if (err != VPN_OK) {
        LOG_ERROR("Failed to generate random key");
        return err;
    }

    /* Apply Curve25519 clamping */
    curve25519_clamp(key);
    return VPN_OK;
}

/*
 * Load or generate private key
 */
static vpn_error_t load_key(const char *filename, uint8_t private_key[32], uint8_t public_key[32])
{
    FILE *f;
    char hex[65];
    int result;

    f = fopen(filename, "r");
    if (f) {
        /* Load existing key */
        result = fscanf(f, "%64s", hex);
        fclose(f);

        if (result != 1 || hex_to_bytes(private_key, 32, hex) != 0) {
            LOG_ERROR("Invalid key file format");
            return VPN_ERR_CONFIG;
        }
        LOG_INFO("Loaded private key from %s", filename);
    } else {
        /* Generate new key */
        LOG_INFO("Generating new private key...");
        if (generate_private_key(private_key) != VPN_OK) {
            return VPN_ERR_CRYPTO;
        }

        /* Save to file */
        f = fopen(filename, "w");
        if (f) {
            bytes_to_hex(hex, private_key, 32);
            fprintf(f, "%s\n", hex);
            fclose(f);
            LOG_INFO("Saved private key to %s", filename);
        } else {
            LOG_WARN("Could not save key to %s", filename);
        }
    }

    /* Derive public key */
    curve25519_keygen(public_key, private_key);

    return VPN_OK;
}

/*
 * ===========================================================================
 * Command Line Parsing
 * ===========================================================================
 */

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOptions:\n");
    printf("  -c <file>         Configuration file (WireGuard format)\n");
    printf("  -l <port>         Listen port (default: 51820)\n");
    printf("  -k <keyfile>      Private key file (default: vpn.key)\n");
    printf("  -p <peer>         Add peer: <pubkey>@<endpoint>\n");
    printf("  -i <ip/prefix>    Set tunnel IP address\n");
    printf("  -r <ip/prefix>    Add allowed IP for last peer\n");
    printf("  -v                Verbose output (debug logging)\n");
    printf("  -h                Show this help\n");
    printf("\nKey Generation:\n");
    printf("  %s genkey         Generate new private key\n", prog);
    printf("  %s pubkey         Derive public key from stdin\n", prog);
    printf("\nExamples:\n");
    printf("  Server: %s -c server.conf\n", prog);
    printf("  Client: %s -c client.conf\n", prog);
    printf("  Legacy: %s -l 51820 -k server.key -i 10.0.0.1/24\n", prog);
}

static bool g_verbose = false;
static char g_config_path[256] = {0};

static vpn_error_t parse_args(int argc, char *argv[])
{
    int i;

    /* Defaults */
    g_config.listen_port = 51820;
    strcpy(g_config.keyfile, "vpn.key");
    g_config.num_peers = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = true;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strncpy(g_config_path, argv[++i], sizeof(g_config_path) - 1);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            g_config.listen_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            strncpy(g_config.keyfile, argv[++i], sizeof(g_config.keyfile) - 1);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(g_config.tunnel_ip, argv[++i], sizeof(g_config.tunnel_ip) - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            if (g_config.num_peers >= MAX_PEERS) {
                fprintf(stderr, "Error: Too many peers\n");
                return VPN_ERR_CONFIG;
            }

            /* Parse pubkey@endpoint */
            char *arg = argv[++i];
            char *at = strchr(arg, '@');
            if (!at) {
                fprintf(stderr, "Error: Invalid peer format (expected pubkey@endpoint)\n");
                return VPN_ERR_CONFIG;
            }

            size_t pubkey_len = at - arg;
            if (pubkey_len != 64) {
                fprintf(stderr, "Error: Public key must be 64 hex characters\n");
                return VPN_ERR_CONFIG;
            }

            strncpy(g_config.peers[g_config.num_peers].pubkey_hex, arg, 64);
            g_config.peers[g_config.num_peers].pubkey_hex[64] = '\0';
            strncpy(g_config.peers[g_config.num_peers].endpoint, at + 1,
                    sizeof(g_config.peers[0].endpoint) - 1);
            g_config.num_peers++;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            if (g_config.num_peers == 0) {
                fprintf(stderr, "Error: -r must come after -p\n");
                return VPN_ERR_CONFIG;
            }
            int peer_idx = g_config.num_peers - 1;
            int ip_idx = g_config.peers[peer_idx].num_allowed_ips;
            if (ip_idx >= 16) {
                fprintf(stderr, "Error: Too many allowed IPs for peer\n");
                return VPN_ERR_CONFIG;
            }
            strncpy(g_config.peers[peer_idx].allowed_ips[ip_idx], argv[++i],
                    sizeof(g_config.peers[0].allowed_ips[0]) - 1);
            g_config.peers[peer_idx].num_allowed_ips++;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return VPN_ERR_CONFIG;
        }
    }

    return VPN_OK;
}

/*
 * ===========================================================================
 * Main Event Loop
 * ===========================================================================
 */

/*
 * Process a packet received from the TUN interface (outgoing)
 *
 * 1. Look up destination peer based on destination IP
 * 2. Initiate handshake if needed
 * 3. Encrypt and send
 */
static void process_tun_packet(const uint8_t *packet, size_t len)
{
    uint8_t dst_ip[16];
    bool is_ipv6;
    peer_t *peer;
    uint8_t encrypted[65535];
    int encrypted_len;

    /* Extract destination IP */
    if (tun_packet_get_dst(packet, len, dst_ip, &is_ipv6) != VPN_OK) {
        return;
    }

    /* Find peer for this destination */
    peer = peer_lookup_by_ip(&g_peers, dst_ip, is_ipv6);
    if (!peer) {
        /* No peer for this destination */
        return;
    }

    /* Check if we have a valid session */
    if (!peer_session_valid(peer)) {
        /* Need to initiate handshake */
        if (!peer->handshake.in_progress) {
            uint8_t init_msg[256];
            int init_len;

            init_len = peer_initiate_handshake(peer, &g_peers, init_msg);
            if (init_len > 0 && peer->ep.is_set) {
                udp_addr_t dest;
                vpn_memcpy(dest.addr, peer->ep.addr, 16);
                dest.port = peer->ep.port;
                dest.is_ipv6 = peer->ep.is_ipv6;

                udp_send(&g_udp, init_msg, init_len, &dest);
                printf("Sent handshake initiation to peer\n");
            }
        }
        return;  /* Can't send data yet */
    }

    /* Encrypt and send */
    encrypted_len = peer_encrypt_data(peer, encrypted, packet, len);
    if (encrypted_len > 0 && peer->ep.is_set) {
        udp_addr_t dest;
        vpn_memcpy(dest.addr, peer->ep.addr, 16);
        dest.port = peer->ep.port;
        dest.is_ipv6 = peer->ep.is_ipv6;

        udp_send(&g_udp, encrypted, encrypted_len, &dest);
    }
}

/*
 * Process a packet received from UDP (incoming)
 *
 * Handles handshake messages and encrypted data packets.
 */
static void process_udp_packet(const uint8_t *packet, size_t len, const udp_addr_t *from)
{
    int msg_type;
    peer_t *peer;

    msg_type = packet_get_type(packet, len);
    if (msg_type < 0) {
        return;  /* Invalid packet */
    }

    switch (msg_type) {
        case MSG_TYPE_HANDSHAKE_INITIATION: {
            /*
             * Received handshake initiation
             * 1. Find or create peer
             * 2. Process initiation
             * 3. Send response
             */
            uint32_t sender_index;
            noise_handshake_state temp_hs;
            uint8_t resp_msg[256];
            int resp_len;

            /* Decode to get initiator's public key */
            if (packet_decode_initiation(packet, len, &sender_index, &temp_hs,
                                         g_peers.static_private,
                                         g_peers.static_public) != VPN_OK) {
                printf("Failed to decode handshake initiation\n");
                return;
            }

            /* Find peer by public key */
            peer = peer_find_by_pubkey(&g_peers, temp_hs.rs);
            if (!peer) {
                /* Unknown peer - could add dynamically or reject */
                printf("Received initiation from unknown peer\n");
                return;
            }

            /* Update endpoint from incoming packet */
            peer_set_endpoint(peer, from->addr, from->port, from->is_ipv6);

            /* Process initiation and create response */
            resp_len = peer_respond_handshake(peer, &g_peers, packet, len, resp_msg);
            if (resp_len > 0) {
                udp_send(&g_udp, resp_msg, resp_len, from);
                printf("Sent handshake response\n");
            }
            break;
        }

        case MSG_TYPE_HANDSHAKE_RESPONSE: {
            /*
             * Received handshake response
             * 1. Find peer by receiver index
             * 2. Complete handshake
             */
            uint32_t sender_index, receiver_index;

            /* Extract indices from packet */
            receiver_index = ((uint32_t)packet[8])        |
                            ((uint32_t)packet[9] << 8)   |
                            ((uint32_t)packet[10] << 16) |
                            ((uint32_t)packet[11] << 24);

            peer = peer_find_by_index(&g_peers, receiver_index);
            if (!peer) {
                printf("Received response for unknown session\n");
                return;
            }

            if (peer_complete_handshake(peer, packet, len) == VPN_OK) {
                printf("Handshake completed successfully!\n");
            } else {
                printf("Failed to complete handshake\n");
            }
            break;
        }

        case MSG_TYPE_TRANSPORT_DATA: {
            /*
             * Received encrypted data
             * 1. Find peer by receiver index
             * 2. Decrypt
             * 3. Write to TUN
             */
            uint32_t receiver_index;
            uint8_t decrypted[65535];
            size_t decrypted_len;
            uint8_t src_ip[16];
            bool src_is_ipv6;

            receiver_index = ((uint32_t)packet[4])        |
                            ((uint32_t)packet[5] << 8)   |
                            ((uint32_t)packet[6] << 16)  |
                            ((uint32_t)packet[7] << 24);

            peer = peer_find_by_index(&g_peers, receiver_index);
            if (!peer) {
                return;
            }

            if (peer_decrypt_data(peer, decrypted, &decrypted_len,
                                  packet, len) != VPN_OK) {
                printf("Failed to decrypt packet\n");
                return;
            }

            /* Verify source IP is allowed for this peer */
            if (tun_packet_get_src(decrypted, decrypted_len, src_ip, &src_is_ipv6) == VPN_OK) {
                if (!peer_check_source_ip(peer, src_ip, src_is_ipv6)) {
                    printf("Dropped packet with unauthorized source IP\n");
                    return;
                }
            }

            /* Write to TUN */
            tun_write(&g_tun, decrypted, decrypted_len);
            break;
        }

        default:
            break;
    }
}

/*
 * Main event loop
 */
static void run_main_loop(void)
{
    uint8_t tun_buf[65535];
    uint8_t udp_buf[65535];
    int result;

    printf("VPN running. Press Ctrl+C to stop.\n");

    while (running) {
        /* Check for TUN data (with short timeout to not block) */
        result = tun_read_timeout(&g_tun, tun_buf, sizeof(tun_buf), 10);
        if (result > 0) {
            process_tun_packet(tun_buf, result);
        }

        /* Check for UDP data */
        udp_addr_t from;
        result = udp_recv_timeout(&g_udp, udp_buf, sizeof(udp_buf), &from, 10);
        if (result > 0) {
            process_udp_packet(udp_buf, result, &from);
        }

        /* TODO: Check timers for keepalives and rekeys */
    }
}

/*
 * ===========================================================================
 * Main
 * ===========================================================================
 */

/*
 * Handle key generation commands
 */
static int handle_key_commands(int argc, char *argv[])
{
    if (argc >= 2 && strcmp(argv[1], "genkey") == 0) {
        /* Generate and print a new private key */
        uint8_t private_key[32];
        char base64[45];

        if (vpn_random_bytes(private_key, 32) != VPN_OK) {
            fprintf(stderr, "Error: Failed to generate random key\n");
            return 1;
        }
        curve25519_clamp(private_key);
        config_key_to_base64(base64, private_key);
        printf("%s\n", base64);

        vpn_memzero(private_key, sizeof(private_key));
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "pubkey") == 0) {
        /* Read private key from stdin, output public key */
        char base64_in[64];
        uint8_t private_key[32], public_key[32];
        char base64_out[45];

        if (fgets(base64_in, sizeof(base64_in), stdin) == NULL) {
            fprintf(stderr, "Error: Failed to read private key\n");
            return 1;
        }
        /* Remove newline */
        base64_in[strcspn(base64_in, "\r\n")] = '\0';

        if (config_key_from_base64(private_key, base64_in) != VPN_OK) {
            fprintf(stderr, "Error: Invalid private key\n");
            return 1;
        }

        curve25519_keygen(public_key, private_key);
        config_key_to_base64(base64_out, public_key);
        printf("%s\n", base64_out);

        vpn_memzero(private_key, sizeof(private_key));
        return 0;
    }

    return -1;  /* Not a key command */
}

int main(int argc, char *argv[])
{
    uint8_t private_key[32], public_key[32];
    char pubkey_hex[65];
    int i, j;
    int key_result;

    /* Check for key generation commands first */
    key_result = handle_key_commands(argc, argv);
    if (key_result >= 0) {
        return key_result;
    }

    /* Show usage if no arguments provided */
    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    /* Parse command line first to get -v flag */
    if (parse_args(argc, argv) != VPN_OK) {
        return 1;
    }

    /* Initialize logging based on verbosity */
    log_init(g_verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO, LOG_OUTPUT_STDERR);

    printf("===============================================\n");
    printf("  HinkyPunk VPN\n");
    printf("===============================================\n\n");

    /* Initialize UDP subsystem */
    if (udp_init() != VPN_OK) {
        LOG_ERROR("Failed to initialize UDP");
        return 1;
    }

    /* Load configuration */
    if (g_config_path[0]) {
        /* Load from WireGuard-format config file */
        vpn_config wg_config;
        config_init(&wg_config);

        if (config_load(&wg_config, g_config_path) != VPN_OK) {
            LOG_ERROR("Failed to load config file: %s", g_config_path);
            return 1;
        }

        LOG_INFO("Loaded configuration from %s", g_config_path);

        /* Copy keys from config */
        if (!wg_config.interface.has_private_key) {
            LOG_ERROR("Configuration missing private key");
            config_free(&wg_config);
            return 1;
        }

        vpn_memcpy(private_key, wg_config.interface.private_key, 32);
        vpn_memcpy(public_key, wg_config.interface.public_key, 32);

        /* Override port if specified in config */
        if (wg_config.interface.has_listen_port) {
            g_config.listen_port = wg_config.interface.listen_port;
        }

        /* Initialize peer table */
        peer_table_init(&g_peers, private_key, public_key);

        /* Add peers from config */
        for (i = 0; i < wg_config.num_peers; i++) {
            peer_t *peer = peer_add(&g_peers, wg_config.peers[i].public_key);
            if (!peer) {
                LOG_WARN("Failed to add peer %d", i);
                continue;
            }

            /* Set endpoint if specified */
            if (wg_config.peers[i].has_endpoint) {
                udp_addr_t ep;
                if (udp_addr_from_string(&ep, wg_config.peers[i].endpoint) == VPN_OK) {
                    peer_set_endpoint(peer, ep.addr, ep.port, ep.is_ipv6);
                    LOG_INFO("Added peer with endpoint %s", wg_config.peers[i].endpoint);
                }
            } else {
                LOG_INFO("Added peer (no endpoint, will accept incoming)");
            }

            /* Add allowed IPs */
            for (j = 0; j < wg_config.peers[i].num_allowed_ips; j++) {
                LOG_DEBUG("  Allowed IP: %s", wg_config.peers[i].allowed_ips[j].cidr);
            }
        }

        config_free(&wg_config);
    } else {
        /* Legacy command-line mode */
        if (load_key(g_config.keyfile, private_key, public_key) != VPN_OK) {
            return 1;
        }

        /* Initialize peer table */
        peer_table_init(&g_peers, private_key, public_key);

        /* Add configured peers from command line */
        for (i = 0; i < g_config.num_peers; i++) {
            uint8_t peer_pubkey[32];
            peer_t *peer;

            if (hex_to_bytes(peer_pubkey, 32, g_config.peers[i].pubkey_hex) != 0) {
                LOG_ERROR("Invalid peer public key: %s", g_config.peers[i].pubkey_hex);
                continue;
            }

            peer = peer_add(&g_peers, peer_pubkey);
            if (!peer) {
                LOG_ERROR("Failed to add peer");
                continue;
            }

            /* Set endpoint */
            udp_addr_t ep;
            if (udp_addr_from_string(&ep, g_config.peers[i].endpoint) == VPN_OK) {
                peer_set_endpoint(peer, ep.addr, ep.port, ep.is_ipv6);
                LOG_INFO("Added peer: %s @ %s",
                        g_config.peers[i].pubkey_hex,
                        g_config.peers[i].endpoint);
            }

            /* Add allowed IPs */
            for (j = 0; j < g_config.peers[i].num_allowed_ips; j++) {
                LOG_DEBUG("  Allowed IP: %s", g_config.peers[i].allowed_ips[j]);
            }
        }
    }

    bytes_to_hex(pubkey_hex, public_key, 32);
    LOG_INFO("Public key: %s", pubkey_hex);

    /* Open UDP socket */
    if (udp_open(&g_udp, g_config.listen_port, NULL) != VPN_OK) {
        LOG_ERROR("Failed to open UDP socket on port %u", g_config.listen_port);
        return 1;
    }
    LOG_INFO("Listening on UDP port %u", g_config.listen_port);

    /* Open TUN interface */
    if (tun_open(&g_tun, "vpn0") != VPN_OK) {
        LOG_ERROR("Failed to open TUN interface");
        LOG_ERROR("(This requires root/administrator privileges)");
        udp_close(&g_udp);
        return 1;
    }
    LOG_INFO("Opened TUN interface: %s", tun_get_name(&g_tun));

    /* Configure TUN interface */
    if (g_config.tunnel_ip[0]) {
        /* TODO: Parse IP and set */
        tun_set_mtu(&g_tun, 1420);
        tun_up(&g_tun);
    }

    /* Install signal handler */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Run main loop */
    run_main_loop();

    /* Cleanup */
    tun_close(&g_tun);
    udp_close(&g_udp);
    udp_cleanup();

    vpn_memzero(private_key, sizeof(private_key));

    LOG_INFO("Shutdown complete");
    log_shutdown();

    return 0;
}
