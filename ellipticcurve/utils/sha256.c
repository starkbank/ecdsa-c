/*
 * SHA-256, FIPS 180-4.
 *
 * Implemented here rather than pulled from a dependency: it is fixed-width integer
 * work with no secret-dependent branching and official NIST vectors, so the
 * risk profile is nothing like modular arithmetic, and it keeps the library at
 * a single link-time dependency. tests/test.c checks it against the FIPS 180-4
 * example digests for the empty string, "abc" and one million 'a'.
 */

#include <stdint.h>
#include <string.h>
#include "../internal.h"

#define ROTR(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void compress(uint32_t *state, const unsigned char *block)
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t temp1, temp2;
    int index;

    for (index = 0; index < 16; index++) {
        w[index] = ((uint32_t)block[index * 4] << 24)
                 | ((uint32_t)block[index * 4 + 1] << 16)
                 | ((uint32_t)block[index * 4 + 2] << 8)
                 | ((uint32_t)block[index * 4 + 3]);
    }
    for (index = 16; index < 64; index++) {
        w[index] = SSIG1(w[index - 2]) + w[index - 7] + SSIG0(w[index - 15]) + w[index - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (index = 0; index < 64; index++) {
        temp1 = h + BSIG1(e) + CH(e, f, g) + K[index] + w[index];
        temp2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + temp1;
        d = c; c = b; b = a;
        a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    starkecdsaScrub(w, sizeof(w));
}

void starkecdsaSha256(const unsigned char *message, size_t length, unsigned char *digest)
{
    uint32_t state[8];
    unsigned char block[64];
    size_t remaining = length;
    const unsigned char *cursor = message;
    size_t tail;
    int index;

    state[0] = 0x6a09e667u; state[1] = 0xbb67ae85u; state[2] = 0x3c6ef372u; state[3] = 0xa54ff53au;
    state[4] = 0x510e527fu; state[5] = 0x9b05688cu; state[6] = 0x1f83d9abu; state[7] = 0x5be0cd19u;

    while (remaining >= 64) {
        compress(state, cursor);
        cursor += 64;
        remaining -= 64;
    }

    /* Final block or blocks: the message tail, 0x80, zero padding, then the
       length in bits as a 64-bit big-endian value. */
    memset(block, 0, sizeof(block));
    if (remaining > 0) {
        memcpy(block, cursor, remaining);
    }
    block[remaining] = 0x80;
    tail = remaining + 1;

    if (tail > 56) {
        compress(state, block);
        memset(block, 0, sizeof(block));
    }

    {
        unsigned long long bits = (unsigned long long)length * 8ull;
        int position;
        for (position = 0; position < 8; position++) {
            block[63 - position] = (unsigned char)((bits >> (position * 8)) & 0xffu);
        }
    }

    compress(state, block);

    for (index = 0; index < 8; index++) {
        digest[index * 4] = (unsigned char)((state[index] >> 24) & 0xffu);
        digest[index * 4 + 1] = (unsigned char)((state[index] >> 16) & 0xffu);
        digest[index * 4 + 2] = (unsigned char)((state[index] >> 8) & 0xffu);
        digest[index * 4 + 3] = (unsigned char)(state[index] & 0xffu);
    }

    starkecdsaScrub(state, sizeof(state));
    starkecdsaScrub(block, sizeof(block));
}
