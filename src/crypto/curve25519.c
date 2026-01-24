/*
 * curve25519.c - Elliptic Curve Diffie-Hellman Implementation
 * ============================================================
 *
 * This is an adaptation of curve25519-donna-c64.c by Adam Langley,
 * which was derived from Daniel J. Bernstein's reference implementation.
 *
 * Original code: https://github.com/agl/curve25519-donna
 * Released into the public domain.
 *
 * OVERVIEW:
 *
 * Curve25519 is a Montgomery curve: y² = x³ + 486662x² + x
 * All arithmetic is done modulo p = 2²⁵⁵ - 19 (a prime).
 *
 * We represent field elements as 5 limbs of 51 bits each in radix 2^51.
 * The Montgomery ladder computes scalar multiplication using only
 * the x-coordinate, which is naturally constant-time.
 *
 * REFERENCE: RFC 7748 - Elliptic Curves for Security
 */

#include "curve25519.h"
#include "../util/memory.h"
#include <string.h>

/*
 * ===========================================================================
 * Type Definitions
 * ===========================================================================
 */

typedef uint64_t limb;
typedef limb felem[5];

/* 128-bit integer for intermediate products */
#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
#else
#error "This implementation requires __int128 support"
#endif

/*
 * ===========================================================================
 * Field Arithmetic (from curve25519-donna)
 * ===========================================================================
 */

/* Sum two numbers: output += in */
static inline void
fsum(limb *output, const limb *in)
{
    output[0] += in[0];
    output[1] += in[1];
    output[2] += in[2];
    output[3] += in[3];
    output[4] += in[4];
}

/* Find the difference: output = in - output (note argument order!) */
static inline void
fdifference_backwards(felem out, const felem in)
{
    static const limb two54m152 = (((limb)1) << 54) - 152;
    static const limb two54m8 = (((limb)1) << 54) - 8;

    out[0] = in[0] + two54m152 - out[0];
    out[1] = in[1] + two54m8 - out[1];
    out[2] = in[2] + two54m8 - out[2];
    out[3] = in[3] + two54m8 - out[3];
    out[4] = in[4] + two54m8 - out[4];
}

/* Multiply by scalar: output = in * scalar */
static inline void
fscalar_product(felem output, const felem in, const limb scalar)
{
    uint128_t a;

    a = ((uint128_t)in[0]) * scalar;
    output[0] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[1]) * scalar + ((limb)(a >> 51));
    output[1] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[2]) * scalar + ((limb)(a >> 51));
    output[2] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[3]) * scalar + ((limb)(a >> 51));
    output[3] = ((limb)a) & 0x7ffffffffffff;

    a = ((uint128_t)in[4]) * scalar + ((limb)(a >> 51));
    output[4] = ((limb)a) & 0x7ffffffffffff;

    output[0] += (a >> 51) * 19;
}

/* Multiply two field elements: output = in2 * in */
static inline void
fmul(felem output, const felem in2, const felem in)
{
    uint128_t t[5];
    limb r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

    r0 = in[0];
    r1 = in[1];
    r2 = in[2];
    r3 = in[3];
    r4 = in[4];

    s0 = in2[0];
    s1 = in2[1];
    s2 = in2[2];
    s3 = in2[3];
    s4 = in2[4];

    t[0] = ((uint128_t)r0) * s0;
    t[1] = ((uint128_t)r0) * s1 + ((uint128_t)r1) * s0;
    t[2] = ((uint128_t)r0) * s2 + ((uint128_t)r2) * s0 + ((uint128_t)r1) * s1;
    t[3] = ((uint128_t)r0) * s3 + ((uint128_t)r3) * s0 + ((uint128_t)r1) * s2 + ((uint128_t)r2) * s1;
    t[4] = ((uint128_t)r0) * s4 + ((uint128_t)r4) * s0 + ((uint128_t)r3) * s1 + ((uint128_t)r1) * s3 + ((uint128_t)r2) * s2;

    r4 *= 19;
    r1 *= 19;
    r2 *= 19;
    r3 *= 19;

    t[0] += ((uint128_t)r4) * s1 + ((uint128_t)r1) * s4 + ((uint128_t)r2) * s3 + ((uint128_t)r3) * s2;
    t[1] += ((uint128_t)r4) * s2 + ((uint128_t)r2) * s4 + ((uint128_t)r3) * s3;
    t[2] += ((uint128_t)r4) * s3 + ((uint128_t)r3) * s4;
    t[3] += ((uint128_t)r4) * s4;

    r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
    t[1] += c; r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
    t[2] += c; r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
    t[3] += c; r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
    t[4] += c; r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
    r0 += c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
    r1 += c; c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
    r2 += c;

    output[0] = r0;
    output[1] = r1;
    output[2] = r2;
    output[3] = r3;
    output[4] = r4;
}

/* Square a field element (repeated count times) */
static inline void
fsquare_times(felem output, const felem in, limb count)
{
    uint128_t t[5];
    limb r0, r1, r2, r3, r4, c;
    limb d0, d1, d2, d4, d419;

    r0 = in[0];
    r1 = in[1];
    r2 = in[2];
    r3 = in[3];
    r4 = in[4];

    do {
        d0 = r0 * 2;
        d1 = r1 * 2;
        d2 = r2 * 2 * 19;
        d419 = r4 * 19;
        d4 = d419 * 2;

        t[0] = ((uint128_t)r0) * r0 + ((uint128_t)d4) * r1 + (((uint128_t)d2) * (r3));
        t[1] = ((uint128_t)d0) * r1 + ((uint128_t)d4) * r2 + (((uint128_t)r3) * (r3 * 19));
        t[2] = ((uint128_t)d0) * r2 + ((uint128_t)r1) * r1 + (((uint128_t)d4) * (r3));
        t[3] = ((uint128_t)d0) * r3 + ((uint128_t)d1) * r2 + (((uint128_t)r4) * (d419));
        t[4] = ((uint128_t)d0) * r4 + ((uint128_t)d1) * r3 + (((uint128_t)r2) * (r2));

        r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
        t[1] += c; r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
        t[2] += c; r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
        t[3] += c; r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
        t[4] += c; r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
        r0 += c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
        r1 += c; c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
        r2 += c;
    } while (--count);

    output[0] = r0;
    output[1] = r1;
    output[2] = r2;
    output[3] = r3;
    output[4] = r4;
}

/*
 * ===========================================================================
 * Byte Conversion
 * ===========================================================================
 */

/* Load a little-endian 64-bit number */
static limb
load_limb(const uint8_t *in)
{
    return ((limb)in[0]) |
           (((limb)in[1]) << 8) |
           (((limb)in[2]) << 16) |
           (((limb)in[3]) << 24) |
           (((limb)in[4]) << 32) |
           (((limb)in[5]) << 40) |
           (((limb)in[6]) << 48) |
           (((limb)in[7]) << 56);
}

/* Store a little-endian 64-bit number */
static void
store_limb(uint8_t *out, limb in)
{
    out[0] = in & 0xff;
    out[1] = (in >> 8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

/* Expand 32-byte little-endian to polynomial form */
static void
fexpand(limb *output, const uint8_t *in)
{
    output[0] = load_limb(in) & 0x7ffffffffffff;
    output[1] = (load_limb(in + 6) >> 3) & 0x7ffffffffffff;
    output[2] = (load_limb(in + 12) >> 6) & 0x7ffffffffffff;
    output[3] = (load_limb(in + 19) >> 1) & 0x7ffffffffffff;
    output[4] = (load_limb(in + 24) >> 12) & 0x7ffffffffffff;
}

/* Contract polynomial form to 32-byte little-endian (fully reduced) */
static void
fcontract(uint8_t *output, const felem input)
{
    uint128_t t[5];

    t[0] = input[0];
    t[1] = input[1];
    t[2] = input[2];
    t[3] = input[3];
    t[4] = input[4];

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    /* now t is between 0 and 2^255-1, properly carried. */
    t[0] += 19;

    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

    /* now between 19 and 2^255-1 in both cases, and offset by 19. */
    t[0] += 0x8000000000000 - 19;
    t[1] += 0x8000000000000 - 1;
    t[2] += 0x8000000000000 - 1;
    t[3] += 0x8000000000000 - 1;
    t[4] += 0x8000000000000 - 1;

    /* now between 2^255 and 2^256-20, and offset by 2^255. */
    t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[4] &= 0x7ffffffffffff;

    store_limb(output,     t[0] | (t[1] << 51));
    store_limb(output + 8,  (t[1] >> 13) | (t[2] << 38));
    store_limb(output + 16, (t[2] >> 26) | (t[3] << 25));
    store_limb(output + 24, (t[3] >> 39) | (t[4] << 12));
}

/*
 * ===========================================================================
 * Montgomery Ladder
 * ===========================================================================
 */

/* Constant-time conditional swap */
static void
swap_conditional(limb a[5], limb b[5], limb iswap)
{
    unsigned i;
    const limb swap = -iswap;

    for (i = 0; i < 5; ++i) {
        const limb x = swap & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

/*
 * Montgomery ladder step.
 *
 * Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 */
static void
fmonty(limb *x2, limb *z2,    /* output 2Q */
       limb *x3, limb *z3,    /* output Q + Q' */
       limb *x, limb *z,      /* input Q (destroyed) */
       limb *xprime, limb *zprime, /* input Q' (destroyed) */
       const limb *qmqp)      /* input Q - Q' */
{
    limb origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5],
         zzprime[5], zzzprime[5];

    memcpy(origx, x, 5 * sizeof(limb));
    fsum(x, z);
    fdifference_backwards(z, origx);

    memcpy(origxprime, xprime, sizeof(limb) * 5);
    fsum(xprime, zprime);
    fdifference_backwards(zprime, origxprime);
    fmul(xxprime, xprime, z);
    fmul(zzprime, x, zprime);
    memcpy(origxprime, xxprime, sizeof(limb) * 5);
    fsum(xxprime, zzprime);
    fdifference_backwards(zzprime, origxprime);
    fsquare_times(x3, xxprime, 1);
    fsquare_times(zzzprime, zzprime, 1);
    fmul(z3, zzzprime, qmqp);

    fsquare_times(xx, x, 1);
    fsquare_times(zz, z, 1);
    fmul(x2, xx, zz);
    fdifference_backwards(zz, xx);
    fscalar_product(zzz, zz, 121665);
    fsum(zzz, xx);
    fmul(z2, zz, zzz);
}

/*
 * Scalar multiplication: resultx/resultz = n * q
 *
 * n: 32-byte scalar (little-endian)
 * q: input point (polynomial form)
 */
static void
cmult(limb *resultx, limb *resultz, const uint8_t *n, const limb *q)
{
    limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
    limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
    limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
    limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

    unsigned i, j;

    memcpy(nqpqx, q, sizeof(limb) * 5);

    for (i = 0; i < 32; ++i) {
        uint8_t byte = n[31 - i];
        for (j = 0; j < 8; ++j) {
            const limb bit = byte >> 7;

            swap_conditional(nqx, nqpqx, bit);
            swap_conditional(nqz, nqpqz, bit);
            fmonty(nqx2, nqz2,
                   nqpqx2, nqpqz2,
                   nqx, nqz,
                   nqpqx, nqpqz,
                   q);
            swap_conditional(nqx2, nqpqx2, bit);
            swap_conditional(nqz2, nqpqz2, bit);

            t = nqx;
            nqx = nqx2;
            nqx2 = t;
            t = nqz;
            nqz = nqz2;
            nqz2 = t;
            t = nqpqx;
            nqpqx = nqpqx2;
            nqpqx2 = t;
            t = nqpqz;
            nqpqz = nqpqz2;
            nqpqz2 = t;

            byte <<= 1;
        }
    }

    memcpy(resultx, nqx, sizeof(limb) * 5);
    memcpy(resultz, nqz, sizeof(limb) * 5);
}

/*
 * Modular inversion: out = z^(-1) mod p
 *
 * Uses Fermat's little theorem: z^(-1) = z^(p-2) mod p
 * where p = 2^255 - 19, so p-2 = 2^255 - 21
 */
static void
crecip(felem out, const felem z)
{
    felem a, t0, b, c;

    /* 2 */ fsquare_times(a, z, 1);
    /* 8 */ fsquare_times(t0, a, 2);
    /* 9 */ fmul(b, t0, z);
    /* 11 */ fmul(a, b, a);
    /* 22 */ fsquare_times(t0, a, 1);
    /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
    /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
    /* 2^10 - 2^0 */ fmul(b, t0, b);
    /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
    /* 2^20 - 2^0 */ fmul(c, t0, b);
    /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
    /* 2^40 - 2^0 */ fmul(t0, t0, c);
    /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
    /* 2^50 - 2^0 */ fmul(b, t0, b);
    /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
    /* 2^100 - 2^0 */ fmul(c, t0, b);
    /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
    /* 2^200 - 2^0 */ fmul(t0, t0, c);
    /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
    /* 2^250 - 2^0 */ fmul(t0, t0, b);
    /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
    /* 2^255 - 21 */ fmul(out, t0, a);
}

/*
 * ===========================================================================
 * Core Scalar Multiplication
 * ===========================================================================
 */

/*
 * The base point for Curve25519 has x-coordinate 9.
 */
static const uint8_t BASE_POINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * curve25519_donna - Core scalar multiplication
 *
 * mypublic = secret * basepoint
 */
static int
curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint)
{
    limb bp[5], x[5], z[5], zmone[5];
    uint8_t e[32];
    int i;

    /* Clamp the scalar */
    for (i = 0; i < 32; ++i)
        e[i] = secret[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    /* Expand basepoint, compute scalar mult, convert to affine */
    fexpand(bp, basepoint);
    cmult(x, z, e, bp);
    crecip(zmone, z);
    fmul(z, x, zmone);
    fcontract(mypublic, z);

    /* Clear sensitive data */
    vpn_memzero(e, sizeof(e));

    return 0;
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
    curve25519_donna(public_key, private_key, BASE_POINT);
}

vpn_error_t curve25519_shared(uint8_t shared[CURVE25519_SHARED_SIZE],
                              const uint8_t their_public[CURVE25519_KEY_SIZE],
                              const uint8_t my_private[CURVE25519_KEY_SIZE])
{
    curve25519_donna(shared, my_private, their_public);

    /*
     * Check for all-zeros result (small-subgroup attack).
     *
     * If the peer sends a malicious public key from a small subgroup,
     * the shared secret will be all zeros. Reject this.
     */
    uint8_t zeros[32] = {0};
    if (vpn_memeq(shared, zeros, 32)) {
        vpn_memzero(shared, 32);
        return VPN_ERR_CRYPTO;
    }

    return VPN_OK;
}
