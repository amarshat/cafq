/* Compiled-kernel study: the 2x2 Karatsuba multiplier with evaluation
 * fingerprint, instruction for instruction the toy-ir-v1 program
 * `polymul_karatsuba2` (src/cafq/circuits.py), over GF(2^8) mod 0x11B.
 *
 *   in  = { a0, a1, b0, b1, R }
 *   out = { p0, p1, p2, disc }      disc == 0  <=>  check passed
 *
 * gf_mul is branch-free so that the dynamic instruction trace does not
 * depend on the data. RESEARCH ARTEFACT: not constant-time-audited, not a
 * countermeasure recommendation.
 */
#include <stdint.h>

static inline uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        r ^= (uint8_t)(-(b & 1)) & a;
        uint8_t hi = (uint8_t)(-(a >> 7));
        a = (uint8_t)((a << 1) ^ (hi & 0x1B));
        b >>= 1;
    }
    return r;
}

void kernel(const uint8_t *in, uint8_t *out)
{
    uint8_t a0 = in[0], a1 = in[1], b0 = in[2], b1 = in[3], R = in[4];

    /* data region */
    uint8_t m0 = gf_mul(a0, b0);
    uint8_t m2 = gf_mul(a1, b1);
    uint8_t sa = a0 ^ a1;
    uint8_t sb = b0 ^ b1;
    uint8_t m1 = gf_mul(sa, sb);
    uint8_t p0 = m0;
    uint8_t p1 = m1 ^ m0 ^ m2;
    uint8_t p2 = m2;
    out[0] = p0;
    out[1] = p1;
    out[2] = p2;

    /* check region: a(R) * b(R) + p(R) */
    uint8_t ea = gf_mul(a1, R) ^ a0;
    uint8_t eb = gf_mul(b1, R) ^ b0;
    uint8_t ep = gf_mul(gf_mul(p2, R) ^ p1, R) ^ p0;
    out[3] = gf_mul(ea, eb) ^ ep;
}
