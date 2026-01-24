/*
 * Debug program to print actual ChaCha20 output vs expected
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/types.h"
#include "src/crypto/chacha20.h"

static const uint8_t rfc8439_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t rfc8439_nonce[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
};

/* Expected from test file */
static const uint8_t rfc8439_keystream_block1[] = {
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
    0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
    0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
    0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
    0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
};

int main(void)
{
    uint8_t block[64];

    printf("Testing ChaCha20 block function with RFC 8439 Section 2.4.2 inputs\n\n");

    printf("Key: ");
    for (int i = 0; i < 32; i++) printf("%02x", rfc8439_key[i]);
    printf("\n");

    printf("Nonce: ");
    for (int i = 0; i < 12; i++) printf("%02x", rfc8439_nonce[i]);
    printf("\n");

    printf("Counter: 1\n\n");

    chacha20_block(block, rfc8439_key, rfc8439_nonce, 1);

    printf("Expected keystream:\n");
    for (int i = 0; i < 64; i++) {
        printf("0x%02x, ", rfc8439_keystream_block1[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }

    printf("\nActual keystream:\n");
    for (int i = 0; i < 64; i++) {
        printf("0x%02x, ", block[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }

    printf("\nDifferences:\n");
    int diffs = 0;
    for (int i = 0; i < 64; i++) {
        if (block[i] != rfc8439_keystream_block1[i]) {
            printf("  Byte %d: expected 0x%02x, got 0x%02x\n",
                   i, rfc8439_keystream_block1[i], block[i]);
            diffs++;
        }
    }
    if (diffs == 0) {
        printf("  (none)\n");
    }
    printf("Total differences: %d bytes\n", diffs);

    return 0;
}
