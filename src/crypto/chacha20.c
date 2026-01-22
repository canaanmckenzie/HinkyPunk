/*
 * chacha20.c - ChaCha20 Stream Cipher Implementation
 * ===================================================
 *
 * This is a complete, from-scratch implementation of ChaCha20.
 * Read chacha20.h for the conceptual overview; this file focuses on
 * the actual algorithm mechanics.
 *
 * ALGORITHM OVERVIEW:
 *
 * ChaCha20 is built on a simple principle: take a 64-byte block of initial
 * state, scramble it thoroughly with simple operations, add the original
 * state back, and output the result as keystream.
 *
 * The "scrambling" uses only three operations:
 *   1. ADD (modular 32-bit addition)
 *   2. XOR (bitwise exclusive or)
 *   3. ROT (bitwise rotation)
 *
 * This "ARX" construction is elegant because:
 *   - No table lookups (constant-time, cache-timing safe)
 *   - Works on any CPU with basic 32-bit operations
 *   - Each operation is fast and reversible
 *   - Combined effect is highly non-linear (cryptographically strong)
 *
 * REFERENCE: RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
 */

#include "chacha20.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ---------------------------------------------------------------------------
 * Helper Macros
 * ---------------------------------------------------------------------------
 */

/*
 * ROTL32 - Rotate left a 32-bit value
 *
 * Rotation moves bits around cyclically. Bits that fall off the left side
 * come back on the right side. This is different from shifting, where bits
 * fall off and zeros come in.
 *
 * Example (8-bit for clarity, we use 32-bit):
 *   ROTL(10110001, 2) = 11000110
 *   Left 2: 110001?? (two bits fell off left, two unknowns on right)
 *   Those two bits wrap around: 11000110
 *
 * In C, we implement rotation as: (x << n) | (x >> (32 - n))
 *   - Left shift moves bits left, zeros come in from right
 *   - Right shift captures the bits that "fell off"
 *   - OR combines them
 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * U8TO32_LE - Convert 4 bytes (little-endian) to 32-bit integer
 *
 * "Little-endian" means the least significant byte comes first in memory.
 * Most modern CPUs (x86, ARM) use little-endian natively.
 *
 * Memory: [0x78, 0x56, 0x34, 0x12]
 * Value:  0x12345678
 *
 * We explicitly construct the value to be portable across all architectures.
 */
#define U8TO32_LE(p)                      \
    (((uint32_t)(p)[0])       |           \
     ((uint32_t)(p)[1] << 8)  |           \
     ((uint32_t)(p)[2] << 16) |           \
     ((uint32_t)(p)[3] << 24))

/*
 * U32TO8_LE - Convert 32-bit integer to 4 bytes (little-endian)
 *
 * Inverse of U8TO32_LE. Stores a 32-bit value into 4 bytes.
 */
#define U32TO8_LE(p, v)                   \
    do {                                  \
        (p)[0] = (uint8_t)((v));          \
        (p)[1] = (uint8_t)((v) >> 8);     \
        (p)[2] = (uint8_t)((v) >> 16);    \
        (p)[3] = (uint8_t)((v) >> 24);    \
    } while (0)

/*
 * ---------------------------------------------------------------------------
 * The ChaCha20 Constant
 * ---------------------------------------------------------------------------
 *
 * The first 16 bytes of the state are a fixed constant: "expand 32-byte k"
 * This serves several purposes:
 *
 * 1. DOMAIN SEPARATION: Ensures ChaCha20 produces different output than
 *    related algorithms that might use the same key material differently.
 *
 * 2. ASYMMETRY: Prevents certain classes of attacks that exploit symmetry.
 *
 * 3. NOTHING-UP-MY-SLEEVE: This ASCII string shows there's no hidden backdoor.
 *    Cryptographers could have chosen any constant; using readable text proves
 *    the choice wasn't malicious.
 *
 * In little-endian 32-bit words:
 *   "expa" -> 0x61707865
 *   "nd 3" -> 0x3320646e
 *   "2-by" -> 0x79622d32
 *   "te k" -> 0x6b206574
 */
static const uint32_t CHACHA_CONSTANT[4] = {
    0x61707865,  /* "expa" */
    0x3320646e,  /* "nd 3" */
    0x79622d32,  /* "2-by" */
    0x6b206574   /* "te k" */
};

/*
 * ---------------------------------------------------------------------------
 * The Quarter Round
 * ---------------------------------------------------------------------------
 *
 * This is the core mixing function of ChaCha20. It operates on four 32-bit
 * words (hence "quarter" of the 16-word state).
 *
 * QUARTER_ROUND(a, b, c, d):
 *   a += b; d ^= a; d <<<= 16;
 *   c += d; b ^= c; b <<<= 12;
 *   a += b; d ^= a; d <<<= 8;
 *   c += d; b ^= c; b <<<= 7;
 *
 * Each step:
 *   1. Add two words together (modular, wraps at 2^32)
 *   2. XOR result into another word
 *   3. Rotate the XORed word
 *
 * The rotation amounts (16, 12, 8, 7) were chosen through extensive analysis
 * to maximize "diffusion" - how quickly changes in one bit affect all others.
 *
 * WHY THIS WORKS:
 * - Addition is non-linear over GF(2) (the XOR field) and vice versa
 * - Combining them creates complex relationships between input and output
 * - Rotation spreads bit changes across word boundaries
 * - After enough rounds, every output bit depends on every input bit
 */
#define QUARTER_ROUND(a, b, c, d)       \
    do {                                \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while (0)

/*
 * ---------------------------------------------------------------------------
 * State Layout
 * ---------------------------------------------------------------------------
 *
 * The 16 words of state are arranged in a 4x4 matrix:
 *
 *        Column 0   Column 1   Column 2   Column 3
 *       +----------+----------+----------+----------+
 * Row 0 | const[0] | const[1] | const[2] | const[3] |  <- "expand 32-byte k"
 *       +----------+----------+----------+----------+
 * Row 1 | key[0]   | key[1]   | key[2]   | key[3]   |  <- First half of key
 *       +----------+----------+----------+----------+
 * Row 2 | key[4]   | key[5]   | key[6]   | key[7]   |  <- Second half of key
 *       +----------+----------+----------+----------+
 * Row 3 | counter  | nonce[0] | nonce[1] | nonce[2] |  <- Counter + nonce
 *       +----------+----------+----------+----------+
 *
 * Index mapping (linear array):
 *   0  1  2  3
 *   4  5  6  7
 *   8  9  10 11
 *   12 13 14 15
 */

/*
 * chacha20_block_internal - The core block function
 *
 * Takes a state array, performs 20 rounds of mixing, adds original state,
 * and writes 64 bytes of output.
 *
 * This is marked static because it's internal. External code uses
 * chacha20_block() which handles the state setup.
 */
static void chacha20_block_internal(uint8_t output[64], const uint32_t state[16])
{
    uint32_t x[16];
    int i;

    /* Copy initial state (we'll add it back at the end) */
    for (i = 0; i < 16; i++) {
        x[i] = state[i];
    }

    /*
     * 20 rounds of mixing
     *
     * ChaCha20 does 20 rounds (hence the name). Each round consists of:
     *   - 4 "column" quarter-rounds (vertical mixing)
     *   - 4 "diagonal" quarter-rounds (diagonal mixing)
     *
     * We do 10 "double-rounds" (each double-round = columns + diagonals).
     *
     * COLUMN ROUNDS - Mix each column:
     *   QR(0, 4, 8, 12)   <- Column 0
     *   QR(1, 5, 9, 13)   <- Column 1
     *   QR(2, 6, 10, 14)  <- Column 2
     *   QR(3, 7, 11, 15)  <- Column 3
     *
     * DIAGONAL ROUNDS - Mix each diagonal:
     *   QR(0, 5, 10, 15)  <- Main diagonal
     *   QR(1, 6, 11, 12)  <- Wrapping diagonal
     *   QR(2, 7, 8, 13)   <- Wrapping diagonal
     *   QR(3, 4, 9, 14)   <- Wrapping diagonal
     *
     * The diagonal rounds break up any patterns that column rounds might
     * create, ensuring thorough mixing.
     */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTER_ROUND(x[0], x[4], x[8],  x[12]);
        QUARTER_ROUND(x[1], x[5], x[9],  x[13]);
        QUARTER_ROUND(x[2], x[6], x[10], x[14]);
        QUARTER_ROUND(x[3], x[7], x[11], x[15]);

        /* Diagonal rounds */
        QUARTER_ROUND(x[0], x[5], x[10], x[15]);
        QUARTER_ROUND(x[1], x[6], x[11], x[12]);
        QUARTER_ROUND(x[2], x[7], x[8],  x[13]);
        QUARTER_ROUND(x[3], x[4], x[9],  x[14]);
    }

    /*
     * Add original state back
     *
     * This is crucial! Without this step, the function would be invertible:
     * given the output, an attacker could run the rounds backward to find
     * the input (which contains the key).
     *
     * Adding the original state makes inversion require knowing the state,
     * which requires knowing the key. The output looks random without the key.
     *
     * This technique is called a "Davies-Meyer construction" in hash functions,
     * or more generally, a "feedforward" in block cipher design.
     */
    for (i = 0; i < 16; i++) {
        x[i] += state[i];
    }

    /*
     * Serialize to bytes (little-endian)
     *
     * The internal state uses 32-bit words for fast computation.
     * The output is a byte stream for XORing with plaintext.
     */
    for (i = 0; i < 16; i++) {
        U32TO8_LE(output + (i * 4), x[i]);
    }
}

/*
 * chacha20_init - Set up the ChaCha20 state
 *
 * Arranges key, nonce, and counter into the 16-word state matrix.
 */
void chacha20_init(chacha20_ctx *ctx,
                   const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE],
                   uint32_t counter)
{
    /* Words 0-3: The constant "expand 32-byte k" */
    ctx->state[0] = CHACHA_CONSTANT[0];
    ctx->state[1] = CHACHA_CONSTANT[1];
    ctx->state[2] = CHACHA_CONSTANT[2];
    ctx->state[3] = CHACHA_CONSTANT[3];

    /* Words 4-11: The 256-bit key (8 words x 32 bits = 256 bits) */
    ctx->state[4]  = U8TO32_LE(key + 0);
    ctx->state[5]  = U8TO32_LE(key + 4);
    ctx->state[6]  = U8TO32_LE(key + 8);
    ctx->state[7]  = U8TO32_LE(key + 12);
    ctx->state[8]  = U8TO32_LE(key + 16);
    ctx->state[9]  = U8TO32_LE(key + 20);
    ctx->state[10] = U8TO32_LE(key + 24);
    ctx->state[11] = U8TO32_LE(key + 28);

    /* Word 12: Block counter */
    ctx->state[12] = counter;

    /* Words 13-15: The 96-bit nonce (3 words x 32 bits = 96 bits) */
    ctx->state[13] = U8TO32_LE(nonce + 0);
    ctx->state[14] = U8TO32_LE(nonce + 4);
    ctx->state[15] = U8TO32_LE(nonce + 8);

    /* No keystream generated yet */
    ctx->keystream_pos = CHACHA20_BLOCK_SIZE;  /* Will trigger generation on first use */
}

/*
 * chacha20_encrypt - Encrypt (or decrypt) data with ChaCha20
 *
 * Generates keystream as needed and XORs it with input.
 */
void chacha20_encrypt(chacha20_ctx *ctx,
                      uint8_t *out,
                      const uint8_t *in,
                      size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        /*
         * If we've used all 64 bytes of the current keystream block,
         * generate a new one.
         */
        if (ctx->keystream_pos >= CHACHA20_BLOCK_SIZE) {
            chacha20_block_internal(ctx->keystream, ctx->state);
            ctx->state[12]++;  /* Increment counter for next block */
            ctx->keystream_pos = 0;

            /*
             * COUNTER OVERFLOW CHECK
             *
             * The counter is 32 bits, so after 2^32 blocks (256 GB) it wraps.
             * In a real implementation, you'd want to detect this and error.
             * WireGuard avoids this by rekeying frequently.
             *
             * For now, we let it wrap (which would be insecure in practice).
             */
        }

        /* XOR plaintext with keystream to produce ciphertext (or vice versa) */
        out[i] = in[i] ^ ctx->keystream[ctx->keystream_pos++];
    }
}

/*
 * chacha20_block - Generate one block of keystream
 *
 * Public interface for single-block generation. Used for generating
 * the Poly1305 key in ChaCha20-Poly1305 AEAD.
 */
void chacha20_block(uint8_t out[CHACHA20_BLOCK_SIZE],
                    const uint8_t key[CHACHA20_KEY_SIZE],
                    const uint8_t nonce[CHACHA20_NONCE_SIZE],
                    uint32_t counter)
{
    chacha20_ctx ctx;

    chacha20_init(&ctx, key, nonce, counter);
    chacha20_block_internal(out, ctx.state);

    /* Clear sensitive data from stack */
    vpn_memzero(&ctx, sizeof(ctx));
}

/*
 * chacha20_xor - One-shot encryption convenience function
 */
void chacha20_xor(uint8_t *out,
                  const uint8_t *in,
                  size_t len,
                  const uint8_t key[CHACHA20_KEY_SIZE],
                  const uint8_t nonce[CHACHA20_NONCE_SIZE],
                  uint32_t counter)
{
    chacha20_ctx ctx;

    chacha20_init(&ctx, key, nonce, counter);
    chacha20_encrypt(&ctx, out, in, len);

    /* Clear sensitive data from stack */
    vpn_memzero(&ctx, sizeof(ctx));
}
