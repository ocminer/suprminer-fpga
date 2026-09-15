/*
 * sha3t.c - SHA3-256t (triple SHA3-256) for BitcoinIII (BC3)
 *
 * PoW = SHA3-256(SHA3-256(SHA3-256(80-byte header)))
 * Matches BitcoinIII-Core src/hash.h HashWriterSHA3::GetHash()
 * (standard FIPS-202 SHA3-256, 0x06 domain padding).
 *
 * Input convention: same as groestl/odo — caller passes the 80-byte
 * serialized header (i.e. swap_endian'd work->data).
 * Output: 32-byte digest; hash[7] (LE word 7) is the high word compared
 * against the target.
 */

#include <stdint.h>
#include <string.h>
#include "miner.h"

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccak_rot[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

#define KROTL64(v, n) ((n) == 0 ? (v) : (((v) << (n)) | ((v) >> (64 - (n)))))

static void keccakf1600(uint64_t st[25])
{
    uint64_t c[5], d[5], b[25];
    int r, x, y, i;
    for (r = 0; r < 24; r++) {
        for (x = 0; x < 5; x++)
            c[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        for (x = 0; x < 5; x++)
            d[x] = c[(x+4)%5] ^ KROTL64(c[(x+1)%5], 1);
        for (i = 0; i < 25; i++)
            st[i] ^= d[i%5];
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                b[y + 5*((2*x + 3*y) % 5)] = KROTL64(st[x + 5*y], keccak_rot[x + 5*y]);
        for (y = 0; y < 5; y++)
            for (x = 0; x < 5; x++)
                st[x+5*y] = b[x+5*y] ^ (~b[((x+1)%5)+5*y] & b[((x+2)%5)+5*y]);
        st[0] ^= keccak_rc[r];
    }
}

/* SHA3-256 for messages <= 135 bytes (single rate block) */
static void sha3_256_short(const unsigned char *msg, size_t len, unsigned char out[32])
{
    uint64_t st[25];
    unsigned char blk[136];
    int i, j;

    memset(st, 0, sizeof(st));
    memset(blk, 0, sizeof(blk));
    memcpy(blk, msg, len);
    blk[len]  ^= 0x06;
    blk[135] ^= 0x80;
    for (i = 0; i < 17; i++) {
        uint64_t v = 0;
        for (j = 7; j >= 0; j--) v = (v << 8) | blk[8*i + j];
        st[i] = v;
    }
    keccakf1600(st);
    for (i = 0; i < 32; i++)
        out[i] = (unsigned char)(st[i/8] >> (8*(i%8)));
}

void sha3256t_hash(void *output, const void *input)
{
    unsigned char d[32];
    sha3_256_short((const unsigned char *)input, 80, d);
    sha3_256_short(d, 32, d);
    sha3_256_short(d, 32, d);
    memcpy(output, d, 32);
}

int scanhash_sha3t(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
    uint32_t max_nonce, uint64_t *hashes_done)
{
    uint32_t _ALIGN(64) endiandata[20];
    uint32_t _ALIGN(64) hash[8];
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;
    const uint32_t Htarg = ptarget[7];
    int k;

    for (k = 0; k < 20; k++)
        be32enc(&endiandata[k], pdata[k]);

    do {
        be32enc(&endiandata[19], nonce);
        sha3256t_hash(hash, endiandata);
        if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
            pdata[19] = nonce;
            *hashes_done = nonce - first_nonce + 1;
            return 1;
        }
        nonce++;
    } while (nonce < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = nonce;
    *hashes_done = nonce - first_nonce + 1;
    return 0;
}
