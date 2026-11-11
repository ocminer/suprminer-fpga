/* proxima.h - Proxima txid-blake2b: BLAKE2b-256 reference plus the per-job
 * constants the FPGA search core needs.  Pure math, no I/O, no platform code.
 *
 * One attempt hashes   prefix || extranonce1 (2 bytes) || extranonce2 (6 bytes)
 * with BLAKE2b-256.  The FPGA enumerates a 48-bit counter C (= little-endian
 * extranonce2) and reports every C whose digest tail h3 satisfies
 * (h3 & kmask) == 0, i.e. the big-endian 64-bit "work" word ends in >= k zero
 * bits.  Everything except C is a per-job constant computed here on the host.
 */
#ifndef PROXIMA_H
#define PROXIMA_H

#include <stdint.h>
#include <stddef.h>

#define PROXI_EN1_LEN     2
#define PROXI_EN2_LEN     6
#define PROXI_MAX_PREFIX  8192
#define PROXI_C48_MASK    0xFFFFFFFFFFFFULL

struct proxi_job {
	size_t   prefix_len;
	uint8_t  en1[PROXI_EN1_LEN];
	int      straddle;        /* nonce crosses a 128-byte block boundary: not supported by the v1 core */
	int      W, r, s1;        /* nonce position inside the final block: word W, byte r; counter rotation s1 */
	uint64_t cst[16];         /* final block with extranonce1 spliced in, extranonce2 bytes zero */
	uint64_t M[16];           /* bit masks of the extranonce2 bits inside the final block */
	uint64_t vi[16];          /* initial compression state (cv, IV, t, final flag) */
	uint64_t cv[8];           /* chaining value before the final block */
};

/* BLAKE2b with a 32-byte digest, no key (the Proxima txid hash). */
void proxi_blake2b256(uint8_t out[32], const uint8_t *msg, size_t len);

/* Per-job constants.  Returns 0 on success, -1 if the prefix is too long. */
int proxi_job_init(struct proxi_job *j, const uint8_t *prefix, size_t prefix_len,
                   const uint8_t en1[PROXI_EN1_LEN]);

/* Software model of the FPGA datapath: the digest tail (little-endian u64 of
 * digest bytes 24..31) for counter C.  Only valid for !straddle jobs. */
uint64_t proxi_hw_h3(const struct proxi_job *j, uint64_t C);

/* Full host hash for counter C: prefix || en1 || le48(C). */
void proxi_hash_attempt(const struct proxi_job *j, const uint8_t *prefix, uint64_t C, uint8_t out[32]);

/* Number of trailing zero bits of the big-endian work word (digest bytes 24..31); 64 for zero. */
int proxi_work_bits(const uint8_t digest[32]);

/* Mask the FPGA applies to h3 for difficulty 2^k: bswap64(2^k - 1); 0 for k <= 0. */
uint64_t proxi_kmask(int k);

/* Little-endian u64 of digest bytes 24..31 (what the FPGA reports as h3). */
uint64_t proxi_h3_of_digest(const uint8_t digest[32]);

/* Difficulty value from mining.set_difficulty -> k (number of required zero bits). */
int proxi_k_from_difficulty(double diff);

/* Known-answer vectors (Proxima library upgrade 6 + node mine_hash_vectors_test.go). */
struct proxi_vector {
	int         prefix_len;
	int         rule;         /* 0: prefix[i] = (i*7+3) & 0xff, 1: prefix[i] = i & 0xff */
	const char *en1_hex;      /* 4 hex chars */
	const char *en2_hex;      /* 12 hex chars, byte order as on the wire */
	const char *hash_hex;     /* 64 hex chars */
};
extern const struct proxi_vector proxi_vectors[];
extern const int proxi_nvectors;

void proxi_vector_prefix(const struct proxi_vector *v, uint8_t *prefix);
/* Counter value of a wire-order extranonce2 (little-endian 48-bit). */
uint64_t proxi_c48_from_en2(const uint8_t en2[PROXI_EN2_LEN]);
void proxi_en2_from_c48(uint64_t C, uint8_t en2[PROXI_EN2_LEN]);

/* CPU self-check: the reference hash and the datapath model against every
 * vector.  Returns the number of failures (0 = pass).  Prints with applog when
 * verbose. */
int proxi_cpu_selfcheck(int verbose);

#endif /* PROXIMA_H */
