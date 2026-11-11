/* proxima.c - Proxima txid-blake2b reference hash and FPGA job precompute.
 * Mirrors the golden model the b2b bitstream was verified against. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "miner.h"
#include "proxima.h"

static const uint64_t IV[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};
#define PARAM_BLOCK 0x01010020ULL     /* digest 32 bytes, no key, fanout 1, depth 1 */

static const uint8_t SIGMA[12][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
	{14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
	{11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
	{ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
	{ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
	{ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
	{12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
	{13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
	{ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
	{14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static inline uint64_t load_le64(const uint8_t *p)
{
	uint64_t v = 0; int i;
	for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
	return v;
}
static inline void store_le64(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++) { p[i] = (uint8_t) v; v >>= 8; }
}

#define G(a, b, c, d, x, y) do {                       \
	v[a] += v[b] + (x); v[d] = rotr64(v[d] ^ v[a], 32); \
	v[c] += v[d];       v[b] = rotr64(v[b] ^ v[c], 24); \
	v[a] += v[b] + (y); v[d] = rotr64(v[d] ^ v[a], 16); \
	v[c] += v[d];       v[b] = rotr64(v[b] ^ v[c], 63); } while (0)

static void rounds(uint64_t v[16], const uint64_t m[16])
{
	int r;
	for (r = 0; r < 12; r++) {
		const uint8_t *s = SIGMA[r];
		G(0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
		G(1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
		G(2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
		G(3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
		G(0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
		G(1, 6, 11, 12, m[s[10]], m[s[11]]);
		G(2, 7,  8, 13, m[s[12]], m[s[13]]);
		G(3, 4,  9, 14, m[s[14]], m[s[15]]);
	}
}

static void compress(uint64_t h[8], const uint64_t m[16], uint64_t t, int last)
{
	uint64_t v[16]; int i;
	memcpy(v, h, 64); memcpy(v + 8, IV, 64);
	v[12] ^= t;
	if (last) v[14] = ~v[14];
	rounds(v, m);
	for (i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

void proxi_blake2b256(uint8_t out[32], const uint8_t *msg, size_t len)
{
	uint64_t h[8], m[16];
	uint8_t blk[128];
	size_t off = 0; int i;

	memcpy(h, IV, 64); h[0] ^= PARAM_BLOCK;
	while (len - off > 128) {
		for (i = 0; i < 16; i++) m[i] = load_le64(msg + off + 8 * i);
		off += 128;
		compress(h, m, off, 0);
	}
	memset(blk, 0, 128); memcpy(blk, msg + off, len - off);
	for (i = 0; i < 16; i++) m[i] = load_le64(blk + 8 * i);
	compress(h, m, len, 1);
	for (i = 0; i < 4; i++) store_le64(out + 8 * i, h[i]);
}

int proxi_job_init(struct proxi_job *j, const uint8_t *prefix, size_t prefix_len, const uint8_t en1[PROXI_EN1_LEN])
{
	size_t L = prefix_len + PROXI_EN1_LEN + PROXI_EN2_LEN;
	size_t nblocks = (L + 127) / 128, block = prefix_len / 128, o = prefix_len % 128, b;
	uint64_t m[16], t;
	uint8_t blk[128];
	int i, k;

	if (prefix_len > PROXI_MAX_PREFIX) return -1;
	memset(j, 0, sizeof(*j));
	j->prefix_len = prefix_len; memcpy(j->en1, en1, PROXI_EN1_LEN);
	j->straddle = (block != nblocks - 1);
	j->W = (int)(o / 8); j->r = (int)(o % 8); j->s1 = (8 * (j->r + 2)) % 64;
	for (k = 0; k < 48; k++) {
		int p = 8 * (j->r + 2) + k, wi = j->W + p / 64, bit = p % 64;
		if (wi < 16) j->M[wi] |= 1ULL << bit;
	}
	memcpy(j->cv, IV, 64); j->cv[0] ^= PARAM_BLOCK;
	for (b = 0; b < block; b++) {
		for (i = 0; i < 16; i++) m[i] = load_le64(prefix + 128 * b + 8 * i);
		compress(j->cv, m, 128 * (b + 1), 0);
	}
	memset(blk, 0, 128);
	memcpy(blk, prefix + 128 * block, prefix_len - 128 * block);
	if (!j->straddle) memcpy(blk + o, en1, PROXI_EN1_LEN);      /* extranonce2 bytes stay 0 */
	for (i = 0; i < 16; i++) j->cst[i] = load_le64(blk + 8 * i);
	t = j->straddle ? 128 * (block + 1) : L;
	memcpy(j->vi, j->cv, 64); memcpy(j->vi + 8, IV, 64);
	j->vi[12] ^= t;
	if (!j->straddle) j->vi[14] = ~j->vi[14];
	return 0;
}

uint64_t proxi_hw_h3(const struct proxi_job *j, uint64_t C)
{
	uint64_t U = rotl64(C & PROXI_C48_MASK, j->s1), m[16], v[16];
	int i;
	for (i = 0; i < 16; i++) m[i] = j->cst[i] ^ (U & j->M[i]);
	memcpy(v, j->vi, 128);
	rounds(v, m);
	return j->cv[3] ^ v[3] ^ v[11];
}

void proxi_hash_attempt(const struct proxi_job *j, const uint8_t *prefix, uint64_t C, uint8_t out[32])
{
	uint8_t *msg = (uint8_t *) malloc(j->prefix_len + PROXI_EN1_LEN + PROXI_EN2_LEN);
	memcpy(msg, prefix, j->prefix_len);
	memcpy(msg + j->prefix_len, j->en1, PROXI_EN1_LEN);
	proxi_en2_from_c48(C, msg + j->prefix_len + PROXI_EN1_LEN);
	proxi_blake2b256(out, msg, j->prefix_len + PROXI_EN1_LEN + PROXI_EN2_LEN);
	free(msg);
}

int proxi_work_bits(const uint8_t digest[32])
{
	uint64_t w = 0; int i, n = 0;
	for (i = 24; i < 32; i++) w = (w << 8) | digest[i];     /* big-endian work word */
	if (w == 0) return 64;
	while (!(w & 1)) { w >>= 1; n++; }
	return n;
}

uint64_t proxi_kmask(int k)
{
	uint64_t m, r = 0; int i;
	if (k <= 0) return 0;
	if (k > 64) k = 64;
	m = (k == 64) ? ~0ULL : ((1ULL << k) - 1);
	for (i = 0; i < 8; i++) r = (r << 8) | ((m >> (8 * i)) & 0xff);  /* bswap64 */
	return r;
}

uint64_t proxi_h3_of_digest(const uint8_t digest[32]) { return load_le64(digest + 24); }

int proxi_k_from_difficulty(double diff)
{
	/* The pool sends 2^k as a number (e.g. 68719476736 for k = 36). */
	if (diff >= 1.0) {
		int k = 0; uint64_t d = (uint64_t) diff;
		while (d > 1) { d >>= 1; k++; }
		return k;
	}
	return (int) diff;
}

uint64_t proxi_c48_from_en2(const uint8_t en2[PROXI_EN2_LEN])
{
	uint64_t C = 0; int i;
	for (i = PROXI_EN2_LEN - 1; i >= 0; i--) C = (C << 8) | en2[i];
	return C;
}

void proxi_en2_from_c48(uint64_t C, uint8_t en2[PROXI_EN2_LEN])
{
	int i;
	for (i = 0; i < PROXI_EN2_LEN; i++) { en2[i] = (uint8_t) C; C >>= 8; }
}

/* ---- known-answer vectors ------------------------------------------------ */
const struct proxi_vector proxi_vectors[] = {
	/* library upgrade 6 vectors: prefix[i] = (i*7+3) & 0xff */
	{112, 0, "0102", "030405060708", "179ad8f3e27dbb840cd3431294e9a2f73c7cfce68ffc04932e27abb51ba07cc1"},
	{119, 0, "0102", "030405060708", "23a9821464e185ca4df71624cb7b434bc72cbcf630bedab34e9a25d59ecb91f6"},
	{120, 0, "0102", "030405060708", "4778e9ff057e689d7aee7144b9175e717c3d985f8233917541232fdb75a55023"},
	{121, 0, "0102", "030405060708", "5ec330b79c9c4ed06b0b6cf10576a894c58db00a01393750881f0102955e710f"},
	{128, 0, "0102", "030405060708", "27ed09864fa792b64db6d36de8201a89697bf8684c518cd32885ef0ed1b7942b"},
	{247, 0, "0102", "030405060708", "29380018b185cf6dd857527e73909346313b5f73f83c77cc8342488a6a69ac7b"},
	{248, 0, "0102", "030405060708", "39a22194d7350d6f401628dc3a31792204dc12d316e923d76c142c28da250a1c"},
	{600, 0, "0102", "030405060708", "56543577bce2ecc81ab261b2b5bc841941c78e6307af6c636aa36377b7cf641b"},
	{632, 0, "0102", "030405060708", "45ced55f04f3140fc6d2f574259e66bb99b0ba3dcd14f19bb51e109b9be461c1"},
	/* first extranonce2 with >= 12 trailing zero bits for the same prefixes */
	{112, 0, "0102", "000000000350", "a661435c637d9b28fc47b8b390e6ecec8ac5ca3c8c273842f89e22344ce16000"},
	{119, 0, "0102", "0000000009c6", "023a51c6679aabd48733188f458778a62cc4dd1e1d6b578c519bf3ef8f7c6000"},
	{120, 0, "0102", "000000000235", "7057dd648a1775b3aa1909ecf3fbffc0af2ba2c1a8e21e69f4312fd2a9516000"},
	{121, 0, "0102", "000000002de1", "bce335dbccff946c0203c948825f4ba68861f56baf9d06a1f5efb67f16a20000"},
	{128, 0, "0102", "000000001fc1", "f195fc9eebe52e53167f81f3fc228591b2b11c03c92789711c4a822c82618000"},
	{247, 0, "0102", "000000000c51", "4be244741a35f52511b09c11ce428f84c75286dd6d9b56595b48233e8aa02000"},
	{248, 0, "0102", "000000002e78", "6f960ba0d5a1a1df655eaf8b52a04afa6a2f72c0ca951c26a13440a7deb67000"},
	{600, 0, "0102", "0000000027a1", "afed267c4da16f68f56554abde97eb147829d21d788c2f512b1f69890be20000"},
	{632, 0, "0102", "00000000094f", "a98abb80b99b9d3e4484997acd7a96ab81f60839b8770454a15a83ba0d83d000"},
	/* node vectors (mine_hash_vectors_test.go): prefix[i] = i & 0xff, nonce 0102 030405060708 */
	{100, 1, "0102", "030405060708", "b7af2281301d649b893e3673679fdf7e61d74dd7347365c17518dc69253506c8"},
	{119, 1, "0102", "030405060708", "a3687092de02840d3e8c30e5025d320ac20cc1feb342ba1fba78c60c41c07d3c"},
	{120, 1, "0102", "030405060708", "bae38c5df1e42849a52915f23f758ec092485b76e3e5c8ec4e6204c2bef1e6ca"},
	{127, 1, "0102", "030405060708", "a1443e852985373cdba3b004be8ab05e20610b869f8389f919b01f537e0c9646"},
	{128, 1, "0102", "030405060708", "aaf45eb2daad328c85f92c61f87154454b369f6fbb7c6bffff43d1a305518259"},
	{129, 1, "0102", "030405060708", "3f8e4f06a0c13899d168aeb96a93e857a65141a0cf4dee9748324029ecccf17c"},
	{200, 1, "0102", "030405060708", "82eba8169dd58a9e6042487be103689d728a36cff1035e2ab1da07196dec3d3d"},
	{247, 1, "0102", "030405060708", "20b9eef755e709fd11307bffc52e773d05c058a63134f65166af9c1744d8febc"},
	{248, 1, "0102", "030405060708", "ddddc25892c55fe25c48c9660493f7830aa7ae43f29efabcfce2a329c71e2583"},
	{256, 1, "0102", "030405060708", "307a1a5b84ff17649608b11a3c701f04ef39548b42e9c432ae1d889fbc56b296"},
	{300, 1, "0102", "030405060708", "3a8a0f43b3c3d96fe5466a2f1c751ff06308d08ed409b5a5f4d7d069ef14c604"},
};
const int proxi_nvectors = (int)(sizeof(proxi_vectors) / sizeof(proxi_vectors[0]));

void proxi_vector_prefix(const struct proxi_vector *v, uint8_t *prefix)
{
	int i;
	for (i = 0; i < v->prefix_len; i++)
		prefix[i] = v->rule ? (uint8_t)(i & 0xff) : (uint8_t)((i * 7 + 3) & 0xff);
}

int proxi_cpu_selfcheck(int verbose)
{
	int i, fails = 0;
	uint8_t prefix[PROXI_MAX_PREFIX], en1[2], en2[6], exp[32], got[32];
	struct proxi_job j;

	for (i = 0; i < proxi_nvectors; i++) {
		const struct proxi_vector *v = &proxi_vectors[i];
		uint64_t C, h3_ref, h3_hw;
		proxi_vector_prefix(v, prefix);
		hex2bin(en1, v->en1_hex, 2); hex2bin(en2, v->en2_hex, 6); hex2bin(exp, v->hash_hex, 32);
		C = proxi_c48_from_en2(en2);
		if (proxi_job_init(&j, prefix, v->prefix_len, en1)) { fails++; continue; }
		proxi_hash_attempt(&j, prefix, C, got);
		h3_ref = proxi_h3_of_digest(got);
		h3_hw = j.straddle ? h3_ref : proxi_hw_h3(&j, C);
		if (memcmp(got, exp, 32) || h3_hw != h3_ref) {
			fails++;
			applog(LOG_ERR, "proxima vector %d (prefix_len %d, rule %d): %s", i, v->prefix_len, v->rule,
			       memcmp(got, exp, 32) ? "reference hash MISMATCH" : "datapath model MISMATCH");
		} else if (verbose) {
			applog(LOG_DEBUG, "proxima vector %d: prefix_len %d shape W=%d r=%d%s ok", i, v->prefix_len, j.W, j.r,
			       j.straddle ? " (straddle)" : "");
		}
	}
	if (verbose)
		applog(fails ? LOG_ERR : LOG_INFO, "proxima CPU self-check: %d vectors, %d failures", proxi_nvectors, fails);
	return fails;
}
