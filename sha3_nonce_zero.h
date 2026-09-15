#ifndef SUPRMINER_SHA3_NONCE_ZERO_H
#define SUPRMINER_SHA3_NONCE_ZERO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHA3_NONCE_ZERO_HEADER_WORDS 20
#define SHA3_NONCE_ZERO_TARGET_WORDS 8
#define SHA3_NONCE_ZERO_NONCE_WORD 19

/* Match calc_hash's mutable private-input and output-buffer contract. */
typedef void (*sha3_nonce_zero_hash_fn)(unsigned char *data,
		unsigned char *hash_out);
typedef bool (*sha3_nonce_zero_fulltest_fn)(const uint32_t *hash,
		const uint32_t *target);

struct sha3_nonce_zero_key {
	bool valid;
	uint32_t header[SHA3_NONCE_ZERO_HEADER_WORDS];
	uint32_t target[SHA3_NONCE_ZERO_TARGET_WORDS];
};

/* The nonce word is normalized because readback updates the thread-local work
 * object after publication.  A target-only change is deliberately a new key. */
static inline bool sha3_nonce_zero_key_matches(
		const struct sha3_nonce_zero_key *key, const uint32_t *data,
		const uint32_t *target)
{
	uint32_t normalized[SHA3_NONCE_ZERO_HEADER_WORDS];

	if (!key || !key->valid || !data || !target)
		return false;
	memcpy(normalized, data, sizeof(normalized));
	normalized[SHA3_NONCE_ZERO_NONCE_WORD] = 0;
	return memcmp(key->header, normalized, sizeof(normalized)) == 0 &&
		memcmp(key->target, target, sizeof(key->target)) == 0;
}

static inline bool sha3_nonce_zero_key_store(struct sha3_nonce_zero_key *key,
		const uint32_t *data, const uint32_t *target)
{
	if (!key || !data || !target)
		return false;
	memcpy(key->header, data, sizeof(key->header));
	key->header[SHA3_NONCE_ZERO_NONCE_WORD] = 0;
	memcpy(key->target, target, sizeof(key->target));
	key->valid = true;
	return true;
}

/* Nonce 0 is reserved for the host in successor SHA3T bitstreams.  Hash a
 * private 80-byte header so neither this helper nor its callback can mutate
 * the thread-local work that will later be published to the FPGA. */
static inline bool sha3_nonce_zero_check(const uint32_t *data,
		const uint32_t *target, uint32_t hash_out[8],
		sha3_nonce_zero_hash_fn hash_fn,
		sha3_nonce_zero_fulltest_fn fulltest_fn)
{
	uint32_t private_header[SHA3_NONCE_ZERO_HEADER_WORDS];

	if (!data || !target || !hash_out || !hash_fn || !fulltest_fn)
		return false;

	memcpy(private_header, data, sizeof(private_header));
	private_header[SHA3_NONCE_ZERO_NONCE_WORD] = 0;
	hash_fn((unsigned char *)private_header,
		(unsigned char *)hash_out);

	return fulltest_fn(hash_out, target);
}

#endif
