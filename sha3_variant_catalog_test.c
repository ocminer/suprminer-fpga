#include <stdio.h>
#include <string.h>

#include "sha3_variant_catalog.h"

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
	const struct sha3_variant_spec *rollback = &sha3_variant_catalog[0];

	expect_true("synthetic-catalog-unbound",
		!SHA3_VARIANT_CATALOG_BOUND);
	expect_true("single-rollback-only", SHA3_VARIANT_CATALOG_COUNT == 1);
	expect_true("default-rollback",
		SHA3_VARIANT_CATALOG_DEFAULT_RUNG == 0);
	expect_true("rollback-spec-valid", sha3_variant_spec_valid(rollback));
	expect_true("rollback-state-id",
		strcmp(rollback->state_id, "example-unbound") == 0);
	expect_true("rollback-exact-filename",
		strcmp(rollback->bitfile,
			"example-unbound.bit") == 0);
	expect_true("rollback-exact-digest",
		strcmp(rollback->sha256_hex,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
	expect_true("synthetic-rate", rollback->expected_rate_hps_floor == 1000000);
	expect_true("unbound-family-rejects-auto",
		!sha3_variant_family_valid(SHA3_VARIANT_CATALOG_FAMILY_ID,
			sha3_variant_catalog, SHA3_VARIANT_CATALOG_COUNT,
			SHA3_VARIANT_CATALOG_DEFAULT_RUNG));

	if (failures)
		return 1;
	printf("SHA3_VARIANT_CATALOG_TEST_PASS cases=%u bound=0\n", cases);
	return 0;
}
