/*
 * BLAKE3 hash function - minimal implementation for Decred PoW mining
 * Supports single-chunk messages up to 1024 bytes (180-byte Decred headers)
 *
 * Based on the BLAKE3 specification:
 * https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
 */

#include <string.h>
#include <stdint.h>

static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

#define BLAKE3_CHUNK_START 1
#define BLAKE3_CHUNK_END   2
#define BLAKE3_ROOT        8

static inline uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load32_le(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void blake3_g(uint32_t *state, int a, int b, int c, int d,
                     uint32_t mx, uint32_t my)
{
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void blake3_round(uint32_t *state, const uint32_t *m)
{
    /* Column step */
    blake3_g(state, 0, 4,  8, 12, m[0],  m[1]);
    blake3_g(state, 1, 5,  9, 13, m[2],  m[3]);
    blake3_g(state, 2, 6, 10, 14, m[4],  m[5]);
    blake3_g(state, 3, 7, 11, 15, m[6],  m[7]);
    /* Diagonal step */
    blake3_g(state, 0, 5, 10, 15, m[8],  m[9]);
    blake3_g(state, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(state, 2, 7,  8, 13, m[12], m[13]);
    blake3_g(state, 3, 4,  9, 14, m[14], m[15]);
}

static void blake3_compress(const uint32_t cv[8], const uint32_t block_words[16],
                            uint64_t counter, uint32_t block_len, uint32_t flags,
                            uint32_t out[8])
{
    uint32_t state[16];
    uint32_t m[16], m_tmp[16];
    int i;

    /* Initialize state */
    for (i = 0; i < 8; i++)
        state[i] = cv[i];
    state[8]  = BLAKE3_IV[0];
    state[9]  = BLAKE3_IV[1];
    state[10] = BLAKE3_IV[2];
    state[11] = BLAKE3_IV[3];
    state[12] = (uint32_t)(counter & 0xFFFFFFFF);
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;

    for (i = 0; i < 16; i++)
        m[i] = block_words[i];

    /* 7 rounds */
    for (int r = 0; r < 7; r++) {
        blake3_round(state, m);
        /* Permute message words */
        for (i = 0; i < 16; i++)
            m_tmp[i] = m[MSG_PERMUTATION[i]];
        for (i = 0; i < 16; i++)
            m[i] = m_tmp[i];
    }

    /* Output: state[i] XOR state[i+8] */
    for (i = 0; i < 8; i++)
        out[i] = state[i] ^ state[i + 8];
}

/*
 * blake3_compress_host - Public wrapper for BLAKE3 compression
 * Takes uint32 arrays directly (for host-side precompute).
 */
void blake3_compress_host(const uint32_t cv[8], const uint32_t block_words[16],
                          uint64_t counter, uint32_t block_len, uint32_t flags,
                          uint32_t out[8])
{
    blake3_compress(cv, block_words, counter, block_len, flags, out);
}

/*
 * blake3_hash_180 - Hash a 180-byte Decred block header with BLAKE3
 *
 * input: 180 bytes (Decred block header, LE format)
 * output: 32 bytes (256-bit hash, 8 x LE uint32)
 *
 * 180 bytes = 3 blocks:
 *   Block 0: bytes 0-63   (64 bytes, flags=CHUNK_START)
 *   Block 1: bytes 64-127 (64 bytes, flags=0)
 *   Block 2: bytes 128-179 (52 bytes zero-padded, flags=CHUNK_END|ROOT)
 */
void blake3_hash_180(const void *input, void *output)
{
    const uint8_t *data = (const uint8_t *)input;
    uint32_t *hash = (uint32_t *)output;
    uint32_t cv[8], block_words[16];
    uint8_t padded[64];
    int i;

    /* Block 0: bytes 0-63 */
    for (i = 0; i < 16; i++)
        block_words[i] = load32_le(data + i * 4);
    blake3_compress(BLAKE3_IV, block_words, 0, 64, BLAKE3_CHUNK_START, cv);

    /* Block 1: bytes 64-127 */
    for (i = 0; i < 16; i++)
        block_words[i] = load32_le(data + 64 + i * 4);
    blake3_compress(cv, block_words, 0, 64, 0, cv);

    /* Block 2: bytes 128-179 (52 bytes, pad to 64) */
    memcpy(padded, data + 128, 52);
    memset(padded + 52, 0, 12);
    for (i = 0; i < 16; i++)
        block_words[i] = load32_le(padded + i * 4);
    blake3_compress(cv, block_words, 0, 52, BLAKE3_CHUNK_END | BLAKE3_ROOT, hash);
}
