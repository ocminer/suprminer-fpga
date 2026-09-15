#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha3_nonce_zero.h"

#define TEST_WORDS 48

static unsigned hash_calls;
static unsigned fulltest_calls;
static bool saw_zero_nonce;
static bool accept_hash;

static void mock_hash(unsigned char *data_bytes,
		unsigned char *hash_out_bytes)
{
	uint32_t *data = (uint32_t *)data_bytes;
	uint32_t *hash_out = (uint32_t *)hash_out_bytes;

	hash_calls++;
	saw_zero_nonce = data[SHA3_NONCE_ZERO_NONCE_WORD] == 0;
	/* Prove callback writes cannot escape the helper's private header. */
	data[0] ^= 0xffffffffU;
	memset(hash_out, 0, 8 * sizeof(*hash_out));
	hash_out[0] = 0x13579bdfU;
}

static bool mock_fulltest(const uint32_t *hash, const uint32_t *target)
{
	fulltest_calls++;
	return accept_hash && hash[0] == 0x13579bdfU &&
		target[0] == 0x2468ace0U;
}

static void reset_mocks(bool accept)
{
	hash_calls = 0;
	fulltest_calls = 0;
	saw_zero_nonce = false;
	accept_hash = accept;
}

static int expect_true(const char *name, bool condition)
{
	if (!condition) {
		fprintf(stderr, "%s: failed\n", name);
		return 1;
	}
	return 0;
}

int main(void)
{
	uint32_t data[TEST_WORDS] = { 0 };
	uint32_t original[TEST_WORDS] = { 0 };
	uint32_t target[8] = { 0 };
	uint32_t target_changed[8] = { 0 };
	uint32_t hash[8] = { 0 };
	struct sha3_nonce_zero_key key = { 0 };
	unsigned calls_before;
	int failures = 0;

	target[0] = 0x2468ace0U;
	data[0] = 0x01020304U;
	data[SHA3_NONCE_ZERO_NONCE_WORD] = 0xa5a5a5a5U;
	memcpy(original, data, sizeof(original));
	reset_mocks(true);
	failures += expect_true("qualifying-zero",
		sha3_nonce_zero_check(data, target, hash, mock_hash,
			mock_fulltest));
	failures += expect_true("hash-saw-zero", saw_zero_nonce);
	failures += expect_true("qualifying-hash-called", hash_calls == 1);
	failures += expect_true("qualifying-fulltest-called", fulltest_calls == 1);
	failures += expect_true("qualifying-input-immutable",
		memcmp(data, original, sizeof(original)) == 0);
	failures += expect_true("hash-output-preserved", hash[0] == 0x13579bdfU);

	data[SHA3_NONCE_ZERO_NONCE_WORD] = 0x5a5a5a5aU;
	memcpy(original, data, sizeof(original));
	reset_mocks(false);
	failures += expect_true("nonqualifying-zero",
		!sha3_nonce_zero_check(data, target, hash, mock_hash,
			mock_fulltest));
	failures += expect_true("nonqualifying-hash-saw-zero", saw_zero_nonce);
	failures += expect_true("nonqualifying-input-immutable",
		memcmp(data, original, sizeof(original)) == 0);

	data[SHA3_NONCE_ZERO_NONCE_WORD] = 0;
	reset_mocks(true);
	failures += expect_true("initial-zero-qualifies",
		sha3_nonce_zero_check(data, target, hash, mock_hash,
			mock_fulltest));
	failures += expect_true("initial-zero-unchanged",
		data[SHA3_NONCE_ZERO_NONCE_WORD] == 0);

	/* Cache identity includes all 80 header bytes with the nonce normalized,
	 * plus all 256 target bits. */
	failures += expect_true("empty-key-misses",
		!sha3_nonce_zero_key_matches(&key, data, target));
	failures += expect_true("key-store",
		sha3_nonce_zero_key_store(&key, data, target));
	failures += expect_true("exact-duplicate-hits",
		sha3_nonce_zero_key_matches(&key, data, target));
	data[SHA3_NONCE_ZERO_NONCE_WORD] = 0xffffffffU;
	failures += expect_true("readback-nonce-normalized",
		sha3_nonce_zero_key_matches(&key, data, target));
	data[5] ^= 1U;
	failures += expect_true("header-only-change-misses",
		!sha3_nonce_zero_key_matches(&key, data, target));
	data[5] ^= 1U;
	memcpy(target_changed, target, sizeof(target_changed));
	target_changed[7] ^= 1U;
	failures += expect_true("target-only-change-misses",
		!sha3_nonce_zero_key_matches(&key, data, target_changed));
	failures += expect_true("null-key-store-rejected",
		!sha3_nonce_zero_key_store(NULL, data, target));

	reset_mocks(true);
	calls_before = hash_calls;
	failures += expect_true("null-data-rejected",
		!sha3_nonce_zero_check(NULL, target, hash, mock_hash,
			mock_fulltest));
	failures += expect_true("null-target-rejected",
		!sha3_nonce_zero_check(data, NULL, hash, mock_hash,
			mock_fulltest));
	failures += expect_true("null-hash-rejected",
		!sha3_nonce_zero_check(data, target, NULL, mock_hash,
			mock_fulltest));
	failures += expect_true("null-hash-fn-rejected",
		!sha3_nonce_zero_check(data, target, hash, NULL,
			mock_fulltest));
	failures += expect_true("null-fulltest-fn-rejected",
		!sha3_nonce_zero_check(data, target, hash, mock_hash, NULL));
	failures += expect_true("invalid-input-no-callback", hash_calls == calls_before);

	if (failures)
		return 1;
	puts("SHA3_NONCE_ZERO_TEST_PASS cases=24 reserved_nonce=00000000 immutable=1 keyed_target=1");
	return 0;
}
