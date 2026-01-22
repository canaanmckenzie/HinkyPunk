/*
 * blake2s.c - BLAKE2s Cryptographic Hash Function Implementation
 * ===============================================================
 *
 * This implements BLAKE2s from scratch. Read blake2s.h for the conceptual
 * overview; this file focuses on the algorithm mechanics.
 *
 * ALGORITHM STRUCTURE:
 *
 * BLAKE2s processes data in 64-byte blocks. The compression function
 * takes the current hash state and a message block, and produces a new
 * hash state.
 *
 * The compression function works on a 4x4 matrix of 32-bit words:
 *   - Upper half (rows 0-1): hash state (h0-h7)
 *   - Lower half (rows 2-3): constants XORed with counter and flags
 *
 * It applies 10 rounds of mixing, where each round uses the "G" mixing
 * function (similar to ChaCha's quarter-round).
 *
 * REFERENCE: RFC 7693 - The BLAKE2 Cryptographic Hash and MAC
 */

#include "blake2s.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ===========================================================================
 * Constants
 * ===========================================================================
 */

/*
 * Initialization vector (IV)
 *
 * These are the first 32 bits of the fractional parts of the square roots
 * of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
 *
 * This is a "nothing up my sleeve" constant - derived from an obvious
 * mathematical source, proving no backdoor was inserted.
 */
static const uint32_t blake2s_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*
 * Sigma: Message word permutation schedule
 *
 * Each round uses a different permutation of the 16 message words.
 * This ensures thorough mixing of all input bits into all output bits.
 */
static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/*
 * ===========================================================================
 * Helper Functions
 * ===========================================================================
 */

/* Right rotation */
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* Load 32-bit little-endian value from bytes */
static uint32_t load32_le(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Store 32-bit value as little-endian bytes */
static void store32_le(void *dst, uint32_t w)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

/*
 * ===========================================================================
 * The G Mixing Function
 * ===========================================================================
 *
 * G mixes four words (a, b, c, d) with two message words (x, y).
 * It's similar to ChaCha's quarter-round but with additions of message words.
 *
 * G(a, b, c, d, x, y):
 *   a = a + b + x
 *   d = (d ^ a) >>> 16
 *   c = c + d
 *   b = (b ^ c) >>> 12
 *   a = a + b + y
 *   d = (d ^ a) >>> 8
 *   c = c + d
 *   b = (b ^ c) >>> 7
 *
 * The rotation amounts (16, 12, 8, 7) are the same as ChaCha for similar reasons.
 */
#define G(v, a, b, c, d, x, y)                  \
    do {                                        \
        v[a] = v[a] + v[b] + (x);               \
        v[d] = ROTR32(v[d] ^ v[a], 16);         \
        v[c] = v[c] + v[d];                     \
        v[b] = ROTR32(v[b] ^ v[c], 12);         \
        v[a] = v[a] + v[b] + (y);               \
        v[d] = ROTR32(v[d] ^ v[a], 8);          \
        v[c] = v[c] + v[d];                     \
        v[b] = ROTR32(v[b] ^ v[c], 7);          \
    } while (0)

/*
 * ===========================================================================
 * Compression Function
 * ===========================================================================
 *
 * This is the core of BLAKE2s. It takes the current hash state (h),
 * a 64-byte message block (m), the byte count (t), and finalization flag (f),
 * and updates the hash state.
 */
static void blake2s_compress(blake2s_ctx *ctx, const uint8_t block[64])
{
    uint32_t v[16];
    uint32_t m[16];
    int i;

    /*
     * Load message block into 16 32-bit words (little-endian).
     */
    for (i = 0; i < 16; i++) {
        m[i] = load32_le(block + i * 4);
    }

    /*
     * Initialize working vector v.
     *
     * First 8 words: current hash state
     * Last 8 words: IV XORed with counter and finalization flags
     *
     *   v[0..7] = h[0..7]
     *   v[8..11] = IV[0..3]
     *   v[12] = IV[4] ^ t0 (low 32 bits of counter)
     *   v[13] = IV[5] ^ t1 (high 32 bits of counter)
     *   v[14] = IV[6] ^ f0 (finalization flag)
     *   v[15] = IV[7] ^ f1 (second finalization flag, usually 0)
     */
    for (i = 0; i < 8; i++) {
        v[i] = ctx->h[i];
    }
    v[8]  = blake2s_IV[0];
    v[9]  = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = blake2s_IV[4] ^ ctx->t[0];
    v[13] = blake2s_IV[5] ^ ctx->t[1];
    v[14] = blake2s_IV[6] ^ ctx->f[0];
    v[15] = blake2s_IV[7] ^ ctx->f[1];

    /*
     * 10 rounds of mixing.
     *
     * Each round applies G to columns, then to diagonals.
     * Different rounds use different message word orderings (sigma).
     */
    for (i = 0; i < 10; i++) {
        const uint8_t *s = blake2s_sigma[i];

        /* Column mixing */
        G(v, 0, 4,  8, 12, m[s[0]], m[s[1]]);
        G(v, 1, 5,  9, 13, m[s[2]], m[s[3]]);
        G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        /* Diagonal mixing */
        G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    /*
     * Finalize: XOR upper and lower halves of v into h.
     *
     * h'[i] = h[i] ^ v[i] ^ v[i+8]
     *
     * This is the "feed-forward" operation that makes the function one-way.
     * Without it, an attacker could reverse the rounds to find the input.
     */
    for (i = 0; i < 8; i++) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

/*
 * ===========================================================================
 * Public API
 * ===========================================================================
 */

vpn_error_t blake2s_init(blake2s_ctx *ctx, size_t outlen)
{
    if (outlen == 0 || outlen > 32) {
        return VPN_ERR_INVALID;
    }

    /* Initialize hash state to IV XORed with parameter block */
    ctx->h[0] = blake2s_IV[0] ^ (0x01010000 | outlen);  /* digest length */
    ctx->h[1] = blake2s_IV[1];
    ctx->h[2] = blake2s_IV[2];
    ctx->h[3] = blake2s_IV[3];
    ctx->h[4] = blake2s_IV[4];
    ctx->h[5] = blake2s_IV[5];
    ctx->h[6] = blake2s_IV[6];
    ctx->h[7] = blake2s_IV[7];

    /* Initialize counters and flags */
    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->f[0] = 0;
    ctx->f[1] = 0;

    /* Initialize buffer */
    ctx->buflen = 0;
    ctx->outlen = outlen;

    return VPN_OK;
}

vpn_error_t blake2s_init_key(blake2s_ctx *ctx, size_t outlen,
                             const void *key, size_t keylen)
{
    if (keylen == 0 || keylen > 32) {
        return VPN_ERR_INVALID;
    }

    if (blake2s_init(ctx, outlen) != VPN_OK) {
        return VPN_ERR_INVALID;
    }

    /* Modify initial hash state for keyed mode */
    ctx->h[0] = blake2s_IV[0] ^ (0x01010000 | (keylen << 8) | outlen);

    /*
     * Process key as first block (padded with zeros).
     *
     * This is equivalent to: BLAKE2s(pad(key) || message)
     * The key becomes part of the initial state, affecting all subsequent
     * compression operations.
     */
    uint8_t block[64];
    vpn_memzero(block, 64);
    vpn_memcpy(block, key, keylen);

    /* Update counter for key block */
    ctx->t[0] = 64;

    /* Compress key block */
    blake2s_compress(ctx, block);

    /* Clear key material */
    vpn_memzero(block, sizeof(block));

    return VPN_OK;
}

vpn_error_t blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen)
{
    const uint8_t *p = (const uint8_t *)in;

    if (inlen == 0) {
        return VPN_OK;
    }

    /* Fill buffer if not empty */
    if (ctx->buflen > 0) {
        size_t fill = 64 - ctx->buflen;
        if (inlen < fill) {
            vpn_memcpy(ctx->buf + ctx->buflen, p, inlen);
            ctx->buflen += inlen;
            return VPN_OK;
        }
        vpn_memcpy(ctx->buf + ctx->buflen, p, fill);
        ctx->t[0] += 64;
        if (ctx->t[0] < 64) ctx->t[1]++;  /* Overflow to t[1] */
        blake2s_compress(ctx, ctx->buf);
        ctx->buflen = 0;
        p += fill;
        inlen -= fill;
    }

    /* Process full blocks */
    while (inlen > 64) {
        ctx->t[0] += 64;
        if (ctx->t[0] < 64) ctx->t[1]++;
        blake2s_compress(ctx, p);
        p += 64;
        inlen -= 64;
    }

    /* Buffer remaining data */
    if (inlen > 0) {
        vpn_memcpy(ctx->buf, p, inlen);
        ctx->buflen = inlen;
    }

    return VPN_OK;
}

vpn_error_t blake2s_final(blake2s_ctx *ctx, void *out)
{
    size_t i;

    /* Update counter with remaining bytes */
    ctx->t[0] += (uint32_t)ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;

    /* Set finalization flag */
    ctx->f[0] = 0xFFFFFFFF;

    /* Pad remaining buffer with zeros */
    vpn_memzero(ctx->buf + ctx->buflen, 64 - ctx->buflen);

    /* Final compression */
    blake2s_compress(ctx, ctx->buf);

    /* Output hash (little-endian) */
    for (i = 0; i < ctx->outlen / 4; i++) {
        store32_le((uint8_t *)out + i * 4, ctx->h[i]);
    }
    /* Handle non-multiple-of-4 output length */
    if (ctx->outlen % 4) {
        uint8_t tmp[4];
        store32_le(tmp, ctx->h[i]);
        vpn_memcpy((uint8_t *)out + i * 4, tmp, ctx->outlen % 4);
    }

    /* Clear sensitive state */
    vpn_memzero(ctx, sizeof(*ctx));

    return VPN_OK;
}

vpn_error_t blake2s(void *out, size_t outlen, const void *in, size_t inlen)
{
    blake2s_ctx ctx;

    if (blake2s_init(&ctx, outlen) != VPN_OK) {
        return VPN_ERR_INVALID;
    }
    blake2s_update(&ctx, in, inlen);
    return blake2s_final(&ctx, out);
}

vpn_error_t blake2s_keyed(void *out, size_t outlen,
                          const void *in, size_t inlen,
                          const void *key, size_t keylen)
{
    blake2s_ctx ctx;

    if (blake2s_init_key(&ctx, outlen, key, keylen) != VPN_OK) {
        return VPN_ERR_INVALID;
    }
    blake2s_update(&ctx, in, inlen);
    return blake2s_final(&ctx, out);
}

/*
 * ===========================================================================
 * HMAC-BLAKE2s
 * ===========================================================================
 *
 * HMAC construction:
 *   HMAC(K, M) = H((K' XOR opad) || H((K' XOR ipad) || M))
 *
 * Where:
 *   K' = H(K) if len(K) > block_size, else K padded to block_size
 *   ipad = 0x36 repeated
 *   opad = 0x5c repeated
 */
void hmac_blake2s(uint8_t out[BLAKE2S_HASH_SIZE],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *in, size_t inlen)
{
    blake2s_ctx ctx;
    uint8_t k_ipad[64], k_opad[64];
    uint8_t keyhash[32];
    const uint8_t *k;
    size_t klen;
    size_t i;

    /* If key is longer than block size, hash it first */
    if (keylen > 64) {
        blake2s(keyhash, 32, key, keylen);
        k = keyhash;
        klen = 32;
    } else {
        k = key;
        klen = keylen;
    }

    /* XOR key with ipad and opad */
    vpn_memzero(k_ipad, 64);
    vpn_memzero(k_opad, 64);
    vpn_memcpy(k_ipad, k, klen);
    vpn_memcpy(k_opad, k, klen);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* Inner hash: H((K' XOR ipad) || M) */
    uint8_t inner[32];
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, k_ipad, 64);
    blake2s_update(&ctx, in, inlen);
    blake2s_final(&ctx, inner);

    /* Outer hash: H((K' XOR opad) || inner) */
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, k_opad, 64);
    blake2s_update(&ctx, inner, 32);
    blake2s_final(&ctx, out);

    /* Clear sensitive data */
    vpn_memzero(keyhash, sizeof(keyhash));
    vpn_memzero(k_ipad, sizeof(k_ipad));
    vpn_memzero(k_opad, sizeof(k_opad));
    vpn_memzero(inner, sizeof(inner));
}

/*
 * ===========================================================================
 * HKDF-BLAKE2s
 * ===========================================================================
 *
 * HKDF (HMAC-based Key Derivation Function) has two phases:
 *
 * 1. EXTRACT: prk = HMAC(salt, input_key_material)
 * 2. EXPAND: output = HMAC(prk, info || counter)
 *
 * WireGuard uses a simplified version where salt = chaining_key and
 * info is empty or minimal.
 */
void hkdf_blake2s(uint8_t out1[BLAKE2S_HASH_SIZE],
                  uint8_t *out2,
                  uint8_t *out3,
                  const uint8_t chaining_key[BLAKE2S_HASH_SIZE],
                  const uint8_t *input, size_t input_len)
{
    uint8_t prk[32];
    uint8_t t[33];  /* 32 bytes + 1 byte counter */

    /*
     * Extract: prk = HMAC(chaining_key, input)
     *
     * This concentrates the entropy from input into a fixed-size PRK
     * (pseudorandom key).
     */
    hmac_blake2s(prk, chaining_key, 32, input, input_len);

    /*
     * Expand: derive output keys
     *
     * T(1) = HMAC(prk, 0x01)
     * T(2) = HMAC(prk, T(1) || 0x02)
     * T(3) = HMAC(prk, T(2) || 0x03)
     */

    /* T(1) = HMAC(prk, 0x01) */
    t[0] = 0x01;
    hmac_blake2s(out1, prk, 32, t, 1);

    if (out2) {
        /* T(2) = HMAC(prk, T(1) || 0x02) */
        vpn_memcpy(t, out1, 32);
        t[32] = 0x02;
        hmac_blake2s(out2, prk, 32, t, 33);
    }

    if (out3) {
        /* T(3) = HMAC(prk, T(2) || 0x03) */
        vpn_memcpy(t, out2, 32);
        t[32] = 0x03;
        hmac_blake2s(out3, prk, 32, t, 33);
    }

    /* Clear sensitive data */
    vpn_memzero(prk, sizeof(prk));
    vpn_memzero(t, sizeof(t));
}
