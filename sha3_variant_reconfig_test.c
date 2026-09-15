#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "sha3_variant_reconfig.h"

static int failures;
static unsigned cases;

static void expect_action(const char *name,
		enum sha3_variant_reconfig_action actual,
		enum sha3_variant_reconfig_action expected)
{
	cases++;
	if (actual != expected) {
		fprintf(stderr, "%s: expected %d, got %d\n", name,
			(int)expected, (int)actual);
		failures++;
	}
}

int main(void)
{
	const uint64_t start = UINT64_C(1000000);

	expect_action("inactive", sha3_variant_reconfig_decide(false,
		start, start, 0, 0), SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("await-work", sha3_variant_reconfig_decide(true,
		0, UINT64_C(999999999), 0, 0), SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("await-first-check", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(1000000), 0, 0),
		SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("one-clean-is-not-proof", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(1000000), 1, 0),
		SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("nineteen-clean-is-not-proof",
		sha3_variant_reconfig_decide(true, start,
			start + UINT64_C(4000000), 19, 0),
		SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("twenty-clean-proves-progress",
		sha3_variant_reconfig_decide(true, start,
			start + UINT64_C(5000000), 20, 0),
		SHA3_VARIANT_RECONFIG_PROVEN);
	expect_action("many-clean-proofs", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(2000000), 1000, 0),
		SHA3_VARIANT_RECONFIG_PROVEN);
	expect_action("first-mismatch", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(1000000), 1, 1),
		SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("mixed-checks", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(1000000), 1000, 1),
		SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("corrupt-counts", sha3_variant_reconfig_decide(true,
		start, start + UINT64_C(1000000), 1, 2),
		SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("just-before-timeout",
		sha3_variant_reconfig_decide(true, start,
			start + SHA3_VARIANT_RECONFIG_TIMEOUT_US - 1, 0, 0),
		SHA3_VARIANT_RECONFIG_WAIT);
	expect_action("timeout-boundary", sha3_variant_reconfig_decide(true,
		start, start + SHA3_VARIANT_RECONFIG_TIMEOUT_US, 0, 0),
		SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("late-clean-is-not-proof",
		sha3_variant_reconfig_decide(true, start,
			start + SHA3_VARIANT_RECONFIG_TIMEOUT_US, 1, 0),
		SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("clock-regression", sha3_variant_reconfig_decide(true,
		start, start - 1, 0, 0), SHA3_VARIANT_RECONFIG_ROLLBACK);
	expect_action("error-before-work", sha3_variant_reconfig_decide(true,
		0, 0, 1, 1), SHA3_VARIANT_RECONFIG_ROLLBACK);

	if (failures)
		return 1;
	printf("SHA3_VARIANT_RECONFIG_TEST_PASS cases=%u\n", cases);
	return 0;
}
