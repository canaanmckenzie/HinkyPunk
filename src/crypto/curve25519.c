/*
 * curve25519.c - Elliptic Curve Diffie-Hellman Implementation
 * ============================================================
 *
 * This implements Curve25519 from scratch. Read curve25519.h for the conceptual
 * overview; this file focuses on the mathematical implementation.
 *
 * MATHEMATICAL BACKGROUND:
 *
 * Curve25519 is a Montgomery curve: y² = x³ + 486662x² + x
 * All arithmetic is done modulo p = 2²⁵⁵ - 19 (a prime).
 *
 * Montgomery curves have a useful property: we can compute scalar multiplication
 * using only the x-coordinate. This is called the "Montgomery ladder" and:
 *   - Uses less memory (no y-coordinate storage)
 *   - Is naturally constant-time (resists timing attacks)
 *   - Has simple, fast formulas
 *
 * FIELD ARITHMETIC:
 *
 * We work in the field F_p where p = 2²⁵⁵ - 19.
 *
 * Representation: We use "radix 2^51" with 5 limbs:
 *   x = x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204
 *
 * Each limb xi is a 64-bit integer. Limbs can temporarily exceed 2^51 during
 * computation; we "reduce" (carry) periodically.
 *
 * Why 2^51? Because:
 *   - 51 * 5 = 255 bits (perfect for our 255-bit field)
 *   - Two 51-bit numbers multiplied fit in 102 bits
 *   - Sum of 5 such products fits in ~105 bits, still within uint64_t range
 *
 * MONTGOMERY LADDER:
 *
 * To compute n*P (scalar n times point P), we process bits of n from high to low.
 * At each step we maintain two points: (x2, z2) and (x3, z3).
 *
 * The key insight: we can compute the next pair from the current pair using
 * only additions, subtractions, multiplications, and squarings - no conditionals
 * that depend on secret data.
 *
 * REFERENCE: RFC 7748 - Elliptic Curves for Security
 */

#include "curve25519.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ===========================================================================
 * Field Element Representation
 * ===========================================================================
 *
 * A field element in F_p is represented as 5 64-bit limbs in radix 2^51.
 * We allow limbs to be slightly larger than 2^51 during computation.
 */

typedef int64_t fe[5];  /* Field element: 5 limbs in radix 2^51 */

/*
 * Curve constant: a24 = (486662 - 2) / 4 = 121665
 *
 * This constant appears in the Montgomery ladder formulas.
 * 486662 is the 'A' coefficient of the Montgomery curve equation.
 */
static const int64_t A24 = 121665;

/*
 * ===========================================================================
 * Field Arithmetic
 * ===========================================================================
 */

/*
 * fe_copy - Copy a field element
 */
static void fe_copy(fe h, const fe f)
{
    h[0] = f[0];
    h[1] = f[1];
    h[2] = f[2];
    h[3] = f[3];
    h[4] = f[4];
}

/*
 * fe_0 - Set field element to zero
 */
static void fe_0(fe h)
{
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

/*
 * fe_1 - Set field element to one
 */
static void fe_1(fe h)
{
    h[0] = 1;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

/*
 * fe_add - Add two field elements: h = f + g
 *
 * Simple limb-by-limb addition. No reduction needed here; limbs can grow
 * and we'll reduce later.
 */
static void fe_add(fe h, const fe f, const fe g)
{
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

/*
 * fe_sub - Subtract field elements: h = f - g
 *
 * We add a multiple of p first to ensure no underflow.
 * 2*p in radix 2^51 is approximately 2^52 per limb.
 */
static void fe_sub(fe h, const fe f, const fe g)
{
    /*
     * Add 2*p before subtracting to avoid negative numbers.
     * 2*p = 2*(2^255 - 19) = 2^256 - 38
     *
     * In radix 2^51:
     *   2*p ≈ [0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE,
     *          0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE]
     *
     * Simplified: we add enough to each limb to ensure positivity.
     */
    h[0] = f[0] + 0x1FFFFFFFFFFFDA - g[0];  /* 2*p₀ - 38 */
    h[1] = f[1] + 0x1FFFFFFFFFFFFE - g[1];  /* 2*p₁ */
    h[2] = f[2] + 0x1FFFFFFFFFFFFE - g[2];
    h[3] = f[3] + 0x1FFFFFFFFFFFFE - g[3];
    h[4] = f[4] + 0x1FFFFFFFFFFFFE - g[4];
}

/*
 * fe_mul - Multiply two field elements: h = f * g mod p
 *
 * This is the core expensive operation. We compute the full product
 * (which requires 10 limbs) then reduce modulo p.
 *
 * The key trick: when reducing, we use 2^255 ≡ 19 (mod p).
 * So high limbs get multiplied by 19 and added to low limbs.
 */
static void fe_mul(fe h, const fe f, const fe g)
{
    /*
     * Full product expansion:
     *
     * (f0 + f1*B + f2*B² + f3*B³ + f4*B⁴) * (g0 + g1*B + ... + g4*B⁴)
     * where B = 2^51
     *
     * Result has terms from B⁰ to B⁸, which we store in d0 through d4
     * after folding high terms back using 2^255 ≡ 19.
     *
     * Specifically: B⁵ = 2^255 ≡ 19, so fᵢ*gⱼ*B^(i+j) for i+j ≥ 5
     * contributes to limb (i+j-5) with a factor of 19.
     */
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];

    /*
     * Precompute 19*gᵢ for reduction.
     * Terms like f3*g4 contribute at position B⁷ = 19²*B² ≡ 361*B²,
     * but we actually need 19*g4 because we process one reduction step.
     *
     * More precisely: we're computing modulo 2^255-19, and 2^255 ≡ 19,
     * so any overflow from limb 4 to limb 5 gets multiplied by 19 and
     * added back to limb 0.
     */
    int64_t g1_19 = 19 * g1;
    int64_t g2_19 = 19 * g2;
    int64_t g3_19 = 19 * g3;
    int64_t g4_19 = 19 * g4;

    /*
     * Compute product limbs. Each dᵢ collects contributions from all
     * fⱼ*gₖ where (j+k) mod 5 = i.
     *
     * For j+k < 5: coefficient is 1
     * For j+k >= 5: coefficient is 19 (from reduction)
     */
    int64_t d0 = f0*g0 + f1*g4_19 + f2*g3_19 + f3*g2_19 + f4*g1_19;
    int64_t d1 = f0*g1 + f1*g0 + f2*g4_19 + f3*g3_19 + f4*g2_19;
    int64_t d2 = f0*g2 + f1*g1 + f2*g0 + f3*g4_19 + f4*g3_19;
    int64_t d3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g4_19;
    int64_t d4 = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0;

    /*
     * Carry propagation
     *
     * Each limb should be < 2^51. Excess bits carry to the next limb.
     * Carry from d4 wraps around to d0, multiplied by 19.
     */
    int64_t c;

    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;  /* 2^51 - 1 */
    c = d1 >> 51; d2 += c; d1 &= 0x7FFFFFFFFFFFF;
    c = d2 >> 51; d3 += c; d2 &= 0x7FFFFFFFFFFFF;
    c = d3 >> 51; d4 += c; d3 &= 0x7FFFFFFFFFFFF;
    c = d4 >> 51; d0 += c * 19; d4 &= 0x7FFFFFFFFFFFF;

    /* One more carry (c*19 might have pushed d0 over) */
    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;

    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
}

/*
 * fe_sq - Square a field element: h = f² mod p
 *
 * Squaring is faster than multiplication because fᵢ*fⱼ = fⱼ*fᵢ,
 * so we can compute half the cross terms and double them.
 */
static void fe_sq(fe h, const fe f)
{
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];

    /* Precompute 2*fᵢ for cross terms */
    int64_t f0_2 = 2 * f0;
    int64_t f1_2 = 2 * f1;
    int64_t f2_2 = 2 * f2;
    int64_t f3_2 = 2 * f3;

    /* Precompute 19*fᵢ for reduction */
    int64_t f1_19 = 19 * f1;
    int64_t f2_19 = 19 * f2;
    int64_t f3_19 = 19 * f3;
    int64_t f4_19 = 19 * f4;

    /*
     * Compute square terms and cross terms.
     * Cross terms appear twice (fᵢfⱼ + fⱼfᵢ), handled by the f*_2 factors.
     */
    int64_t d0 = f0*f0 + f1_2*f4_19 + f2_2*f3_19;
    int64_t d1 = f0_2*f1 + f2*f4_19 + f3*f3_19;
    int64_t d2 = f0_2*f2 + f1*f1 + f3_2*f4_19;
    int64_t d3 = f0_2*f3 + f1_2*f2 + f4*f4_19;
    int64_t d4 = f0_2*f4 + f1_2*f3 + f2*f2;

    /* Carry propagation (same as fe_mul) */
    int64_t c;

    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;
    c = d1 >> 51; d2 += c; d1 &= 0x7FFFFFFFFFFFF;
    c = d2 >> 51; d3 += c; d2 &= 0x7FFFFFFFFFFFF;
    c = d3 >> 51; d4 += c; d3 &= 0x7FFFFFFFFFFFF;
    c = d4 >> 51; d0 += c * 19; d4 &= 0x7FFFFFFFFFFFF;
    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;

    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
}

/*
 * fe_mul121666 - Multiply by constant 121666
 *
 * This specific constant (a24 + 1 = 121666) appears in the Montgomery ladder.
 * Having a dedicated function is slightly faster than general multiplication.
 */
static void fe_mul121666(fe h, const fe f)
{
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];

    int64_t d0 = f0 * 121666;
    int64_t d1 = f1 * 121666;
    int64_t d2 = f2 * 121666;
    int64_t d3 = f3 * 121666;
    int64_t d4 = f4 * 121666;

    /* Carry propagation */
    int64_t c;

    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;
    c = d1 >> 51; d2 += c; d1 &= 0x7FFFFFFFFFFFF;
    c = d2 >> 51; d3 += c; d2 &= 0x7FFFFFFFFFFFF;
    c = d3 >> 51; d4 += c; d3 &= 0x7FFFFFFFFFFFF;
    c = d4 >> 51; d0 += c * 19; d4 &= 0x7FFFFFFFFFFFF;
    c = d0 >> 51; d1 += c; d0 &= 0x7FFFFFFFFFFFF;

    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
}

/*
 * fe_invert - Compute multiplicative inverse: h = f^(-1) mod p
 *
 * By Fermat's little theorem: f^(-1) = f^(p-2) mod p
 *
 * p-2 = 2^255 - 21 = 2^255 - 19 - 2 = p - 2
 *
 * We compute this using repeated squaring, with a specific addition chain
 * that minimizes the number of multiplications.
 */
static void fe_invert(fe h, const fe f)
{
    fe t0, t1, t2, t3;
    int i;

    /*
     * Addition chain for p-2 = 2^255 - 21:
     *
     * We build up powers of f using squares and multiplications.
     * The specific chain here computes f^(p-2) in ~254 squarings + 11 multiplications.
     */

    /* t0 = f^(2^1) */
    fe_sq(t0, f);

    /* t1 = f^(2^2) */
    fe_sq(t1, t0);
    fe_sq(t1, t1);

    /* t1 = f^(2^2) * f = f^(2^2 + 1) */
    fe_mul(t1, t1, f);

    /* t0 = f^(2^1) * f^(2^2 + 1) = f^(2^2 + 2^1 + 1) */
    fe_mul(t0, t0, t1);

    /* t2 = f^(2^3 + 2^2 + 2^1) */
    fe_sq(t2, t0);

    /* t1 = f^(2^3 + 2^2 + 2^1 + 2^2 + 1) = f^(2^3 + 2*2^2 + 2^1 + 1) */
    fe_mul(t1, t2, t1);

    /* t2 = f^(2^5 * (2^3 + 2*2^2 + 2^1 + 1)) */
    fe_sq(t2, t1);
    for (i = 0; i < 4; i++) { fe_sq(t2, t2); }

    /* Continue building up the exponent... */
    fe_mul(t1, t2, t1);  /* t1 = f^(...) */

    fe_sq(t2, t1);
    for (i = 0; i < 9; i++) { fe_sq(t2, t2); }
    fe_mul(t2, t2, t1);

    fe_sq(t3, t2);
    for (i = 0; i < 19; i++) { fe_sq(t3, t3); }
    fe_mul(t2, t3, t2);

    fe_sq(t2, t2);
    for (i = 0; i < 9; i++) { fe_sq(t2, t2); }
    fe_mul(t1, t2, t1);

    fe_sq(t2, t1);
    for (i = 0; i < 49; i++) { fe_sq(t2, t2); }
    fe_mul(t2, t2, t1);

    fe_sq(t3, t2);
    for (i = 0; i < 99; i++) { fe_sq(t3, t3); }
    fe_mul(t2, t3, t2);

    fe_sq(t2, t2);
    for (i = 0; i < 49; i++) { fe_sq(t2, t2); }
    fe_mul(t1, t2, t1);

    fe_sq(t1, t1);
    for (i = 0; i < 4; i++) { fe_sq(t1, t1); }

    fe_mul(h, t1, t0);
}

/*
 * fe_tobytes - Convert field element to 32-byte array (little-endian)
 *
 * This performs final reduction to ensure the value is in [0, p).
 */
static void fe_tobytes(uint8_t s[32], const fe h)
{
    int64_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    int64_t c;

    /* Full carry chain to normalize */
    c = h0 >> 51; h1 += c; h0 &= 0x7FFFFFFFFFFFF;
    c = h1 >> 51; h2 += c; h1 &= 0x7FFFFFFFFFFFF;
    c = h2 >> 51; h3 += c; h2 &= 0x7FFFFFFFFFFFF;
    c = h3 >> 51; h4 += c; h3 &= 0x7FFFFFFFFFFFF;
    c = h4 >> 51; h0 += c * 19; h4 &= 0x7FFFFFFFFFFFF;
    c = h0 >> 51; h1 += c; h0 &= 0x7FFFFFFFFFFFF;

    /*
     * Reduce to canonical form [0, p)
     *
     * If h >= p, subtract p. We check by adding 19 and seeing if bit 255 is set.
     * p = 2^255 - 19, so h >= p iff h + 19 >= 2^255.
     */
    int64_t g0 = h0 + 19;
    c = g0 >> 51;
    int64_t g1 = h1 + c; c = g1 >> 51;
    int64_t g2 = h2 + c; c = g2 >> 51;
    int64_t g3 = h3 + c; c = g3 >> 51;
    int64_t g4 = h4 + c - (1LL << 51);

    /* If g4 >= 0, we need to subtract p (use g); otherwise use h */
    c = g4 >> 63;  /* -1 if g4 < 0 (use h), 0 if g4 >= 0 (use g) */
    int64_t mask = c;

    h0 = (h0 & mask) | (g0 & ~mask & 0x7FFFFFFFFFFFF);
    h1 = (h1 & mask) | (g1 & ~mask & 0x7FFFFFFFFFFFF);
    h2 = (h2 & mask) | (g2 & ~mask & 0x7FFFFFFFFFFFF);
    h3 = (h3 & mask) | (g3 & ~mask & 0x7FFFFFFFFFFFF);
    h4 = (h4 & mask) | (g4 & ~mask & 0x7FFFFFFFFFFFF);

    /* Pack into 32 bytes, little-endian */
    s[0]  = (uint8_t)(h0);
    s[1]  = (uint8_t)(h0 >> 8);
    s[2]  = (uint8_t)(h0 >> 16);
    s[3]  = (uint8_t)(h0 >> 24);
    s[4]  = (uint8_t)(h0 >> 32);
    s[5]  = (uint8_t)(h0 >> 40);
    s[6]  = (uint8_t)((h0 >> 48) | (h1 << 3));
    s[7]  = (uint8_t)(h1 >> 5);
    s[8]  = (uint8_t)(h1 >> 13);
    s[9]  = (uint8_t)(h1 >> 21);
    s[10] = (uint8_t)(h1 >> 29);
    s[11] = (uint8_t)(h1 >> 37);
    s[12] = (uint8_t)((h1 >> 45) | (h2 << 6));
    s[13] = (uint8_t)(h2 >> 2);
    s[14] = (uint8_t)(h2 >> 10);
    s[15] = (uint8_t)(h2 >> 18);
    s[16] = (uint8_t)(h2 >> 26);
    s[17] = (uint8_t)(h2 >> 34);
    s[18] = (uint8_t)(h2 >> 42);
    s[19] = (uint8_t)((h2 >> 50) | (h3 << 1));
    s[20] = (uint8_t)(h3 >> 7);
    s[21] = (uint8_t)(h3 >> 15);
    s[22] = (uint8_t)(h3 >> 23);
    s[23] = (uint8_t)(h3 >> 31);
    s[24] = (uint8_t)(h3 >> 39);
    s[25] = (uint8_t)((h3 >> 47) | (h4 << 4));
    s[26] = (uint8_t)(h4 >> 4);
    s[27] = (uint8_t)(h4 >> 12);
    s[28] = (uint8_t)(h4 >> 20);
    s[29] = (uint8_t)(h4 >> 28);
    s[30] = (uint8_t)(h4 >> 36);
    s[31] = (uint8_t)(h4 >> 44);
}

/*
 * fe_frombytes - Convert 32-byte array to field element
 */
static void fe_frombytes(fe h, const uint8_t s[32])
{
    int64_t h0 = (int64_t)s[0] | ((int64_t)s[1] << 8) | ((int64_t)s[2] << 16) |
                 ((int64_t)s[3] << 24) | ((int64_t)s[4] << 32) | ((int64_t)s[5] << 40) |
                 (((int64_t)s[6] & 0x07) << 48);

    int64_t h1 = ((int64_t)s[6] >> 3) | ((int64_t)s[7] << 5) | ((int64_t)s[8] << 13) |
                 ((int64_t)s[9] << 21) | ((int64_t)s[10] << 29) | ((int64_t)s[11] << 37) |
                 (((int64_t)s[12] & 0x3f) << 45);

    int64_t h2 = ((int64_t)s[12] >> 6) | ((int64_t)s[13] << 2) | ((int64_t)s[14] << 10) |
                 ((int64_t)s[15] << 18) | ((int64_t)s[16] << 26) | ((int64_t)s[17] << 34) |
                 ((int64_t)s[18] << 42) | (((int64_t)s[19] & 0x01) << 50);

    int64_t h3 = ((int64_t)s[19] >> 1) | ((int64_t)s[20] << 7) | ((int64_t)s[21] << 15) |
                 ((int64_t)s[22] << 23) | ((int64_t)s[23] << 31) | ((int64_t)s[24] << 39) |
                 (((int64_t)s[25] & 0x0f) << 47);

    int64_t h4 = ((int64_t)s[25] >> 4) | ((int64_t)s[26] << 4) | ((int64_t)s[27] << 12) |
                 ((int64_t)s[28] << 20) | ((int64_t)s[29] << 28) | ((int64_t)s[30] << 36) |
                 ((int64_t)s[31] << 44);

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
}

/*
 * ===========================================================================
 * Conditional Swap (Constant-Time)
 * ===========================================================================
 *
 * cswap swaps two field elements if swap=1, does nothing if swap=0.
 * This is done in constant time - no branching on the swap value.
 */
static void fe_cswap(fe f, fe g, int64_t swap)
{
    /*
     * Convert swap (0 or 1) to a mask:
     *   swap=0 -> mask=0x0000000000000000
     *   swap=1 -> mask=0xFFFFFFFFFFFFFFFF
     *
     * Then XOR-swap: if mask is all-1s, swapping occurs; if all-0s, no-op.
     */
    swap = -swap;  /* 0 -> 0, 1 -> -1 = 0xFFFF... */

    int64_t x0 = (f[0] ^ g[0]) & swap;
    int64_t x1 = (f[1] ^ g[1]) & swap;
    int64_t x2 = (f[2] ^ g[2]) & swap;
    int64_t x3 = (f[3] ^ g[3]) & swap;
    int64_t x4 = (f[4] ^ g[4]) & swap;

    f[0] ^= x0; g[0] ^= x0;
    f[1] ^= x1; g[1] ^= x1;
    f[2] ^= x2; g[2] ^= x2;
    f[3] ^= x3; g[3] ^= x3;
    f[4] ^= x4; g[4] ^= x4;
}

/*
 * ===========================================================================
 * Montgomery Ladder
 * ===========================================================================
 *
 * This computes scalar multiplication: result = scalar * point
 * using the Montgomery ladder algorithm.
 */

/*
 * The base point for Curve25519 has x-coordinate 9.
 */
static const uint8_t BASE_POINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * curve25519_scalarmult - Scalar multiplication using Montgomery ladder
 *
 * Computes q = n * p where n is a scalar (private key) and p is a point
 * (x-coordinate only, since we use Montgomery form).
 */
static void curve25519_scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32])
{
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    uint8_t e[32];
    int i;

    /* Copy and clamp scalar */
    vpn_memcpy(e, n, 32);
    e[0] &= 248;   /* Clear bits 0, 1, 2 */
    e[31] &= 127;  /* Clear bit 255 */
    e[31] |= 64;   /* Set bit 254 */

    /* Initialize: x1 = p, x2 = 1, z2 = 0, x3 = p, z3 = 1 */
    fe_frombytes(x1, p);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    /*
     * Montgomery ladder: process bits from high to low.
     *
     * At each step, we maintain:
     *   (x2:z2) represents some point Q
     *   (x3:z3) represents Q + P (where P is the input point)
     *
     * If current bit is 0: Q' = 2Q, (Q+P)' = Q + (Q+P)
     * If current bit is 1: Q' = Q + (Q+P), (Q+P)' = 2(Q+P)
     *
     * The conditional swap at the start of each iteration makes this constant-time.
     */
    int64_t swap = 0;

    for (i = 254; i >= 0; i--) {
        int64_t bit = (e[i / 8] >> (i % 8)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        /*
         * Montgomery ladder step (optimized formulas):
         *
         * A = x2 + z2
         * B = x2 - z2
         * AA = A²
         * BB = B²
         * C = x3 + z3
         * D = x3 - z3
         * DA = D * A
         * CB = C * B
         * x3 = (DA + CB)²
         * z3 = x1 * (DA - CB)²
         * x2 = AA * BB
         * E = AA - BB
         * z2 = E * (AA + a24 * E)
         *
         * where a24 = (A-2)/4 = 121665 for Curve25519.
         */
        fe A, B, AA, BB, C, D, DA, CB, E;

        fe_add(A, x2, z2);   /* A = x2 + z2 */
        fe_sub(B, x2, z2);   /* B = x2 - z2 */
        fe_sq(AA, A);        /* AA = A² */
        fe_sq(BB, B);        /* BB = B² */

        fe_add(C, x3, z3);   /* C = x3 + z3 */
        fe_sub(D, x3, z3);   /* D = x3 - z3 */
        fe_mul(DA, D, A);    /* DA = D * A */
        fe_mul(CB, C, B);    /* CB = C * B */

        fe_add(tmp0, DA, CB);
        fe_sq(x3, tmp0);     /* x3 = (DA + CB)² */

        fe_sub(tmp1, DA, CB);
        fe_sq(tmp1, tmp1);
        fe_mul(z3, x1, tmp1); /* z3 = x1 * (DA - CB)² */

        fe_mul(x2, AA, BB);  /* x2 = AA * BB */

        fe_sub(E, AA, BB);   /* E = AA - BB */
        fe_mul121666(tmp0, E); /* tmp0 = a24 * E */
        fe_add(tmp0, tmp0, AA); /* tmp0 = AA + a24 * E */
        fe_mul(z2, E, tmp0); /* z2 = E * (AA + a24 * E) */
    }

    /* Final conditional swap */
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    /* Convert projective to affine: q = x2 / z2 = x2 * z2^(-1) */
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    /* Clear sensitive data */
    vpn_memzero(e, sizeof(e));
}

/*
 * ===========================================================================
 * Public API
 * ===========================================================================
 */

void curve25519_clamp(uint8_t key[CURVE25519_KEY_SIZE])
{
    key[0] &= 248;   /* Clear bits 0, 1, 2 */
    key[31] &= 127;  /* Clear bit 255 */
    key[31] |= 64;   /* Set bit 254 */
}

void curve25519_keygen(uint8_t public_key[CURVE25519_KEY_SIZE],
                       const uint8_t private_key[CURVE25519_KEY_SIZE])
{
    curve25519_scalarmult(public_key, private_key, BASE_POINT);
}

vpn_error_t curve25519_shared(uint8_t shared[CURVE25519_SHARED_SIZE],
                              const uint8_t their_public[CURVE25519_KEY_SIZE],
                              const uint8_t my_private[CURVE25519_KEY_SIZE])
{
    curve25519_scalarmult(shared, my_private, their_public);

    /*
     * Check for all-zeros result (small-subgroup attack).
     *
     * If the peer sends a malicious public key from a small subgroup,
     * the shared secret will be all zeros. A real implementation should
     * reject this.
     */
    uint8_t zeros[32] = {0};
    if (vpn_memeq(shared, zeros, 32)) {
        vpn_memzero(shared, 32);
        return VPN_ERR_CRYPTO;
    }

    return VPN_OK;
}
