/*
 * poly1305.c - Poly1305 Message Authentication Code Implementation
 * =================================================================
 *
 * This implements Poly1305 from scratch. Read poly1305.h for the conceptual
 * overview; this file focuses on the mathematical implementation.
 *
 * THE CORE MATH:
 *
 * Poly1305 computes: ((m[1]*r^n + m[2]*r^(n-1) + ... + m[n]*r) mod p) + s
 *
 * Where:
 *   - m[i] are 128-bit message blocks (with a high bit set)
 *   - r is a 128-bit secret (clamped to have certain bits zero)
 *   - p = 2^130 - 5 (a prime)
 *   - s is a 128-bit secret pad
 *
 * WHY 2^130 - 5?
 *
 * This prime has a special property: 2^130 ≡ 5 (mod p)
 *
 * This makes reduction fast! When we have a number larger than 2^130,
 * we can replace the high bits with 5 times their value. Example:
 *   2^131 = 2 * 2^130 ≡ 2 * 5 = 10 (mod p)
 *
 * IMPLEMENTATION APPROACH:
 *
 * We represent 130-bit numbers in base 2^26 using five 32-bit "limbs":
 *   number = h[0] + h[1]*2^26 + h[2]*2^52 + h[3]*2^78 + h[4]*2^104
 *
 * Why radix 2^26? Because:
 *   - 26 * 5 = 130 bits exactly
 *   - Two 26-bit numbers multiplied fit in 52 bits (fits in uint64_t)
 *   - Leaves room for carries during accumulation
 *
 * REFERENCE: RFC 8439, Section 2.5
 */

#include "poly1305.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ---------------------------------------------------------------------------
 * Helper Functions
 * ---------------------------------------------------------------------------
 */

/*
 * U8TO32_LE - Read 32-bit little-endian value from bytes
 */
static uint32_t u8to32_le(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/*
 * U32TO8_LE - Write 32-bit value as little-endian bytes
 */
static void u32to8_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * ---------------------------------------------------------------------------
 * Context Initialization
 * ---------------------------------------------------------------------------
 */

/*
 * poly1305_init - Initialize context with a one-time key
 *
 * Key layout (32 bytes):
 *   Bytes 0-15:  r value (clamped)
 *   Bytes 16-31: s pad value
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE])
{
    /*
     * Load 'r' from first 16 bytes and clamp it
     *
     * CLAMPING REQUIREMENTS (from RFC 8439):
     *   - r[3], r[7], r[11], r[15] have their top 4 bits cleared
     *   - r[4], r[8], r[12] have their bottom 2 bits cleared
     *
     * In terms of the 128-bit value:
     *   - Bits 128-131 must be zero (top 4 bits of r[15])
     *   - Bits 124-127 must be zero (top 4 bits of r[11])
     *   - etc.
     *
     * Clamping ensures r has specific structure that's important for security
     * (prevents certain algebraic attacks) and implementation (ensures carries
     * don't overflow).
     *
     * We load r into five 26-bit limbs.
     */

    uint32_t t0 = u8to32_le(&key[0]);
    uint32_t t1 = u8to32_le(&key[4]);
    uint32_t t2 = u8to32_le(&key[8]);
    uint32_t t3 = u8to32_le(&key[12]);

    /*
     * Extract 26-bit limbs from the 128-bit r value.
     *
     * The 128 bits are laid out in little-endian 32-bit words:
     *   t0 = bits 0-31
     *   t1 = bits 32-63
     *   t2 = bits 64-95
     *   t3 = bits 96-127
     *
     * We extract:
     *   r[0] = bits 0-25   (26 bits)
     *   r[1] = bits 26-51  (26 bits)
     *   r[2] = bits 52-77  (26 bits)
     *   r[3] = bits 78-103 (26 bits)
     *   r[4] = bits 104-127 (24 bits, but we mask to 26)
     *
     * Clamping is applied via masks:
     *   0x03ffffff = 26 bits all 1s
     *   0x0ffffffc = 26 bits with bottom 2 cleared
     *   0x0fffffff = top limb mask (24 bits)
     */
    ctx->r[0] = (t0)        & 0x03ffffff;
    ctx->r[1] = (t0 >> 26 | t1 << 6)  & 0x03ffff03;  /* clamp: bits 26,27 of this limb */
    ctx->r[2] = (t1 >> 20 | t2 << 12) & 0x03ffc0ff;  /* clamp */
    ctx->r[3] = (t2 >> 14 | t3 << 18) & 0x03f03fff;  /* clamp */
    ctx->r[4] = (t3 >> 8)             & 0x000fffff;  /* clamp: only 20 bits */

    /*
     * Actually, let me redo this with clearer clamping.
     * Standard approach: load r, apply clamp mask, then convert to limbs.
     */

    /* Load r as four 32-bit words */
    t0 = u8to32_le(&key[0])  & 0x0fffffff;  /* clamp bits 28-31 */
    t1 = u8to32_le(&key[4])  & 0x0ffffffc;  /* clamp bits 0-1, 28-31 */
    t2 = u8to32_le(&key[8])  & 0x0ffffffc;  /* clamp bits 0-1, 28-31 */
    t3 = u8to32_le(&key[12]) & 0x0ffffffc;  /* clamp bits 0-1, 28-31 */

    /* Convert to radix 2^26 */
    ctx->r[0] = t0 & 0x03ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    ctx->r[4] = (t3 >> 8);

    /* Initialize accumulator h to zero */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* Load pad 's' from last 16 bytes (kept as four 32-bit words) */
    ctx->pad[0] = u8to32_le(&key[16]);
    ctx->pad[1] = u8to32_le(&key[20]);
    ctx->pad[2] = u8to32_le(&key[24]);
    ctx->pad[3] = u8to32_le(&key[28]);

    /* Initialize buffer */
    ctx->buffer_len = 0;
    ctx->finalized = false;
}

/*
 * ---------------------------------------------------------------------------
 * Block Processing
 * ---------------------------------------------------------------------------
 */

/*
 * poly1305_block - Process a 16-byte block
 *
 * This is the core of Poly1305. It computes:
 *   h = (h + m) * r mod (2^130 - 5)
 *
 * Where m is the 128-bit message block with a high bit (129th bit) set.
 *
 * @param ctx     Context with current state
 * @param block   16-byte message block
 * @param hibit   1 for normal blocks, 0 for final partial block
 */
static void poly1305_block(poly1305_ctx *ctx, const uint8_t block[16], uint32_t hibit)
{
    /*
     * Load the 16-byte block into five 26-bit limbs, with hibit as the 129th bit.
     *
     * For a full block, hibit=1, so the number is:
     *   m = block[0..15] as little-endian 128-bit + 2^128
     *
     * The 2^128 ensures that blocks of zeros have different hashes than
     * an empty message (domain separation).
     */
    uint32_t t0 = u8to32_le(&block[0]);
    uint32_t t1 = u8to32_le(&block[4]);
    uint32_t t2 = u8to32_le(&block[8]);
    uint32_t t3 = u8to32_le(&block[12]);

    /* Convert to radix 2^26 limbs */
    uint32_t m0 = t0 & 0x03ffffff;
    uint32_t m1 = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    uint32_t m2 = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    uint32_t m3 = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    uint32_t m4 = (t3 >> 8) | (hibit << 24);  /* hibit goes at bit 128 (24 bits into limb 4) */

    /* h = h + m */
    uint32_t h0 = ctx->h[0] + m0;
    uint32_t h1 = ctx->h[1] + m1;
    uint32_t h2 = ctx->h[2] + m2;
    uint32_t h3 = ctx->h[3] + m3;
    uint32_t h4 = ctx->h[4] + m4;

    /* Prepare r and 5*r values for multiplication */
    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];

    /*
     * 5*r values are used for reduction. When multiplying:
     *   h * r = h0*r0 + h0*r1*2^26 + ... + h4*r4*2^104
     *
     * Terms like h4*r4 produce results at bit position 104+104=208, which is
     * 78 bits above 2^130. To reduce, we use: 2^130 ≡ 5 (mod p)
     *
     * So h4*r4 * 2^208 = h4*r4 * 2^78 * 2^130 ≡ h4*r4 * 2^78 * 5 (mod p)
     *
     * By precomputing 5*r[i], we can fold high terms into low terms.
     */
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    /*
     * Full multiplication: h = h * r mod p
     *
     * We compute all cross products. The math:
     *
     * h * r = (h0 + h1*2^26 + h2*2^52 + h3*2^78 + h4*2^104) *
     *         (r0 + r1*2^26 + r2*2^52 + r3*2^78 + r4*2^104)
     *
     * Expanding and reducing modulo 2^130-5:
     *
     * d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1  (s = 5*r for reduction)
     * d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
     * d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
     * d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
     * d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
     *
     * Each di can be up to 64 bits (sum of five 52-bit products).
     */
    uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    /*
     * Carry propagation: reduce each limb to 26 bits
     *
     * For each limb, keep low 26 bits, carry the rest to the next limb.
     * For d4's carry, we multiply by 5 (because 2^130 ≡ 5) and add to d0.
     */
    uint32_t c;

    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff;
    d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff;
    d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff;
    d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff;
    d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff;

    /* Carry from h4 wraps to h0 multiplied by 5 */
    h0 += c * 5;

    /* One more carry from h0 to h1 (c*5 might have pushed h0 over 26 bits) */
    c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    /* Store back */
    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

/*
 * ---------------------------------------------------------------------------
 * Main API Functions
 * ---------------------------------------------------------------------------
 */

/*
 * poly1305_update - Add data to MAC computation
 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    /* If we have buffered data, try to complete a block */
    if (ctx->buffer_len > 0) {
        size_t need = 16 - ctx->buffer_len;
        size_t take = (len < need) ? len : need;

        for (i = 0; i < take; i++) {
            ctx->buffer[ctx->buffer_len + i] = data[i];
        }
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == 16) {
            poly1305_block(ctx, ctx->buffer, 1);
            ctx->buffer_len = 0;
        }
    }

    /* Process full 16-byte blocks */
    while (len >= 16) {
        poly1305_block(ctx, data, 1);
        data += 16;
        len -= 16;
    }

    /* Buffer remaining partial block */
    for (i = 0; i < len; i++) {
        ctx->buffer[i] = data[i];
    }
    ctx->buffer_len = len;
}

/*
 * poly1305_finish - Finalize and output tag
 */
void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t c, mask;
    uint64_t f;

    /* Process final partial block if any */
    if (ctx->buffer_len > 0) {
        size_t i;

        /* Pad with 0x01 then zeros */
        ctx->buffer[ctx->buffer_len] = 0x01;
        for (i = ctx->buffer_len + 1; i < 16; i++) {
            ctx->buffer[i] = 0x00;
        }

        /* Process with hibit=0 (final block marker) */
        poly1305_block(ctx, ctx->buffer, 0);
    }

    /* Load final h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    /*
     * Final reduction: ensure h < p
     *
     * h might be slightly larger than p (up to 2p-1).
     * We need to reduce it to the canonical representative.
     *
     * Strategy: compute g = h - p, check if g >= 0 (no borrow).
     * If g >= 0, use g. Otherwise, use h.
     *
     * p = 2^130 - 5 = 0x3fffffffffffffffffffffffffffffffb (130 bits)
     * In limbs: [0x3fffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3]
     *
     * Actually, easier: h - (2^130 - 5) = h - 2^130 + 5 = h + 5 - 2^130
     * So g = h + 5, then check if bit 130 is set.
     */

    /* First, fully carry h */
    c = h1 >> 26; h1 &= 0x03ffffff;
    h2 += c;
    c = h2 >> 26; h2 &= 0x03ffffff;
    h3 += c;
    c = h3 >> 26; h3 &= 0x03ffffff;
    h4 += c;
    c = h4 >> 26; h4 &= 0x03ffffff;
    h0 += c * 5;
    c = h0 >> 26; h0 &= 0x03ffffff;
    h1 += c;

    /* Compute g = h + 5 */
    g0 = h0 + 5;
    c = g0 >> 26; g0 &= 0x03ffffff;
    g1 = h1 + c;
    c = g1 >> 26; g1 &= 0x03ffffff;
    g2 = h2 + c;
    c = g2 >> 26; g2 &= 0x03ffffff;
    g3 = h3 + c;
    c = g3 >> 26; g3 &= 0x03ffffff;
    g4 = h4 + c - (1 << 26);  /* Subtract 2^130 by removing bit 130 */

    /*
     * If g4's top bit is clear (g4 >= 0 as signed), then h >= p, so use g.
     * Otherwise, h < p, keep h.
     *
     * g4 after subtraction is negative (has bit 31 set) if h < p.
     */
    mask = (g4 >> 31) - 1;  /* 0xffffffff if g4 >= 0 (use g), 0x00000000 if g4 < 0 (use h) */

    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /*
     * Convert h back to 128 bits (four 32-bit words) and add pad s
     *
     * tag = h + s mod 2^128
     */
    f = (uint64_t)h0 + (h1 << 26) + ctx->pad[0];
    u32to8_le(&tag[0], (uint32_t)f);
    f = (f >> 32) + (h1 >> 6) + (h2 << 20) + ctx->pad[1];
    u32to8_le(&tag[4], (uint32_t)f);
    f = (f >> 32) + (h2 >> 12) + (h3 << 14) + ctx->pad[2];
    u32to8_le(&tag[8], (uint32_t)f);
    f = (f >> 32) + (h3 >> 18) + (h4 << 8) + ctx->pad[3];
    u32to8_le(&tag[12], (uint32_t)f);

    ctx->finalized = true;
}

/*
 * poly1305_auth - One-shot MAC computation
 */
void poly1305_auth(uint8_t tag[POLY1305_TAG_SIZE],
                   const uint8_t *data,
                   size_t len,
                   const uint8_t key[POLY1305_KEY_SIZE])
{
    poly1305_ctx ctx;

    poly1305_init(&ctx, key);
    poly1305_update(&ctx, data, len);
    poly1305_finish(&ctx, tag);

    /* Clear sensitive data */
    vpn_memzero(&ctx, sizeof(ctx));
}

/*
 * poly1305_verify - Constant-time tag verification
 */
bool poly1305_verify(const uint8_t tag[POLY1305_TAG_SIZE],
                     const uint8_t *data,
                     size_t len,
                     const uint8_t key[POLY1305_KEY_SIZE])
{
    uint8_t computed_tag[POLY1305_TAG_SIZE];

    poly1305_auth(computed_tag, data, len, key);

    bool result = vpn_memeq(tag, computed_tag, POLY1305_TAG_SIZE);

    vpn_memzero(computed_tag, sizeof(computed_tag));

    return result;
}
