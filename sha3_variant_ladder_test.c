#include <stdbool.h>
#include <stdio.h>

#include "sha3_variant_ladder.h"

static int failures;
static unsigned cases;

static void expect_int(const char *name, int actual, int expected)
{
	cases++;
	if (actual != expected) {
		fprintf(stderr, "%s: expected %d, got %d\n", name, expected,
			actual);
		failures++;
	}
}

static void expect_window(const char *name,
		enum sha3_variant_window_action expected_action,
		unsigned expected_clean, unsigned checks, unsigned errors,
		bool faster_available, bool faster_tainted, unsigned initial_clean)
{
	enum sha3_variant_window_action action;
	unsigned clean = initial_clean;

	action = sha3_variant_window_decide(checks, errors, faster_available,
		faster_tainted, &clean);
	expect_int(name, (int)action, (int)expected_action);
	expect_int("clean-window-state", (int)clean, (int)expected_clean);
}

int main(void)
{
	const bool none[] = { false, false, false, false, false, false, false };
	const bool sparse[] = { true, false, true, false, true, false, true };
	const bool upper_only[] = { false, false, false, false, true, false, false };
	unsigned clean = 4;
	uint32_t tainted = 0;

	expect_int("activation-disabled",
		sha3_variant_activation_decide(false, false, 0),
		SHA3_VARIANT_DISABLED);
	expect_int("activation-reject-override",
		sha3_variant_activation_decide(true, true, 5),
		SHA3_VARIANT_REJECT_OVERRIDE);
	expect_int("activation-reject-zero-images",
		sha3_variant_activation_decide(true, false, 0),
		SHA3_VARIANT_REJECT_INSUFFICIENT_IMAGES);
	expect_int("activation-reject-one-image",
		sha3_variant_activation_decide(true, false, 1),
		SHA3_VARIANT_REJECT_INSUFFICIENT_IMAGES);
	expect_int("activation-ready",
		sha3_variant_activation_decide(true, false, 2),
		SHA3_VARIANT_READY);

	expect_int("display-variant-96",
		(int)sha3_variant_display_mhz(true, 96), 96);
	expect_int("display-legacy-m23",
		(int)sha3_variant_display_mhz(false, 23), 96);
	expect_int("display-invalid",
		(int)sha3_variant_display_mhz(true, -1), 0);
	expect_int("taint-initial-clear",
		sha3_variant_rung_is_tainted(tainted, 5, 3), false);
	expect_int("taint-valid",
		sha3_variant_taint_rung(&tainted, 5, 3), true);
	expect_int("taint-observed",
		sha3_variant_rung_is_tainted(tainted, 5, 3), true);
	expect_int("taint-neighbor-clear",
		sha3_variant_rung_is_tainted(tainted, 5, 2), false);
	expect_int("taint-invalid-rung",
		sha3_variant_taint_rung(&tainted, 5, 5), false);
	expect_int("taint-invalid-count",
		sha3_variant_taint_rung(&tainted, 33, 1), false);
	expect_int("taint-null",
		sha3_variant_taint_rung(NULL, 5, 1), false);

	expect_int("initial-exact", sha3_variant_initial_rung(sparse, 7, 4), 4);
	expect_int("initial-nearest-slower",
		sha3_variant_initial_rung(sparse, 7, 5), 4);
	expect_int("initial-faster-only",
		sha3_variant_initial_rung(upper_only, 7, 1), 4);
	expect_int("initial-no-image", sha3_variant_initial_rung(none, 7, 4), -1);
	expect_int("initial-null", sha3_variant_initial_rung(NULL, 7, 4), -1);
	expect_int("initial-bad-low", sha3_variant_initial_rung(sparse, 7, -1), -1);
	expect_int("initial-bad-high", sha3_variant_initial_rung(sparse, 7, 7), -1);

	expect_int("slower-across-hole",
		sha3_variant_next_slower(sparse, 7, 6), 4);
	expect_int("slower-lowest", sha3_variant_next_slower(sparse, 7, 0), -1);
	expect_int("slower-invalid", sha3_variant_next_slower(sparse, 7, 7), -1);
	expect_int("faster-across-hole",
		sha3_variant_next_faster(sparse, 7, 2), 4);
	expect_int("faster-highest", sha3_variant_next_faster(sparse, 7, 6), -1);
	expect_int("faster-invalid", sha3_variant_next_faster(sparse, 7, -1), -1);

	expect_window("short-window-resets", SHA3_VARIANT_HOLD, 0,
		19, 0, true, false, 4);
	expect_window("short-window-error-down", SHA3_VARIANT_STEP_DOWN, 0,
		1, 1, true, false, 4);
	expect_window("one-error-down", SHA3_VARIANT_STEP_DOWN, 0,
		1000, 1, true, false, 4);
	expect_window("all-errors-down", SHA3_VARIANT_STEP_DOWN, 0,
		20, 20, true, false, 4);
	expect_window("clean-one", SHA3_VARIANT_HOLD, 1,
		20, 0, true, false, 0);
	expect_window("clean-four", SHA3_VARIANT_HOLD, 4,
		200, 0, true, false, 3);
	expect_window("clean-five-probes", SHA3_VARIANT_PROBE_UP, 0,
		200, 0, true, false, 4);
	expect_window("top-rung-holds", SHA3_VARIANT_HOLD, 0,
		200, 0, false, false, 4);
	expect_window("tainted-faster-holds", SHA3_VARIANT_HOLD, 0,
		200, 0, true, true, 4);
	expect_int("null-clean-state",
		sha3_variant_window_decide(200, 0, true, false, NULL),
		SHA3_VARIANT_HOLD);
	expect_int("null-state-unmodified", (int)clean, 4);

	if (failures)
		return 1;
	printf("SHA3_VARIANT_LADDER_TEST_PASS cases=%u\n", cases);
	return 0;
}
