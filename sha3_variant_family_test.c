#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha3_variant_family.h"

#define DIGEST_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST_B "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define DIGEST_C "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static int failures;
static unsigned cases;

static void expect_true(const char *name, int condition)
{
	cases++;
	if (!condition) {
		fprintf(stderr, "%s failed\n", name);
		failures++;
	}
}

int main(void)
{
	struct sha3_variant_spec family[] = {
		{
			.state_id = "example-a",
			.bitfile = "example-a.bit",
			.sha256_hex = DIGEST_A,
			.engines = 1,
			.clock_hz_numerator = 72000000,
			.clock_hz_denominator = 1,
			.expected_rate_hps_floor = 1000000,
		},
		{
			.state_id = "example-b",
			.bitfile = "example-b.bit",
			.sha256_hex = DIGEST_B,
			.engines = 2,
			.clock_hz_numerator = 72000000,
			.clock_hz_denominator = 1,
			.expected_rate_hps_floor = 2000000,
		},
		{
			.state_id = "example-c",
			.bitfile = "example-c.bit",
			.sha256_hex = DIGEST_C,
			.engines = 3,
			.clock_hz_numerator = 500000000,
			.clock_hz_denominator = 7,
			.expected_rate_hps_floor = 2976190,
		},
	};
	struct sha3_variant_spec changed[3];
	uint64_t rate = 0;
	double clock;

	expect_true("family-valid",
		sha3_variant_family_valid("example-family", family, 3, 0));
	expect_true("example-a-rate",
		sha3_variant_rate_floor(&family[0], &rate) && rate == 1000000);
	expect_true("example-b-rate",
		sha3_variant_rate_floor(&family[1], &rate) && rate == 2000000);
	expect_true("example-c-rate",
		sha3_variant_rate_floor(&family[2], &rate) && rate == 2976190);
	clock = sha3_variant_clock_mhz(&family[2]);
	expect_true("synthetic-rational-clock",
		clock > 71.428571 && clock < 71.428572);

	memcpy(changed, family, sizeof(changed));
	changed[2].sha256_hex = "ABCDEF";
	expect_true("reject-placeholder-digest",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[2].state_id = changed[1].state_id;
	expect_true("reject-duplicate-state-id",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[2].bitfile = changed[1].bitfile;
	expect_true("reject-duplicate-bitfile",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[2].bitfile = "../escape.bit";
	expect_true("reject-unsafe-bitfile",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[2].expected_rate_hps_floor++;
	expect_true("reject-rate-mismatch",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[2].clock_hz_denominator = 0;
	expect_true("reject-zero-denominator",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	memcpy(changed, family, sizeof(changed));
	changed[1] = family[2];
	changed[2] = family[1];
	expect_true("reject-unsorted-rate",
		!sha3_variant_family_valid("example-family", changed, 3, 0));
	expect_true("reject-single-rung",
		!sha3_variant_family_valid("example-family", family, 1, 0));
	expect_true("reject-bad-default",
		!sha3_variant_family_valid("example-family", family, 3, 3));
	expect_true("reject-unsafe-family-id",
		!sha3_variant_family_valid("bc3 family", family, 3, 0));
	expect_true("reject-null-rate-output",
		!sha3_variant_rate_floor(&family[0], NULL));
	expect_true("null-clock-zero", sha3_variant_clock_mhz(NULL) == 0.0);

	if (failures)
		return 1;
	printf("SHA3_VARIANT_FAMILY_TEST_PASS cases=%u\n", cases);
	return 0;
}
