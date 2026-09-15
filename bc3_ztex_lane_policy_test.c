#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_lane_policy.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		failures++; \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
	} \
} while (0)

static void fill_sentinel(struct bc3_ztex_lane_policy *policy)
{
	memset(policy, 0xa5, sizeof(*policy));
}

static void expect_failure(unsigned lanes, const char *only,
	const char *order)
{
	struct bc3_ztex_lane_policy policy;
	struct bc3_ztex_lane_policy before;

	fill_sentinel(&policy);
	before = policy;
	CHECK(!bc3_ztex_lane_policy_parse(lanes, only, order, &policy));
	CHECK(memcmp(&policy, &before, sizeof(policy)) == 0);
}

static void check_order(const struct bc3_ztex_lane_policy *policy,
	const uint8_t *expected, unsigned count)
{
	unsigned index;

	for (index = 0u; index < count; ++index)
		CHECK(policy->order[index] == expected[index]);
}

static void test_defaults(void)
{
	struct bc3_ztex_lane_policy policy;
	static const uint8_t natural_one[] = { UINT8_C(0) };
	static const uint8_t natural_four[] = {
		UINT8_C(0), UINT8_C(1), UINT8_C(2), UINT8_C(3)
	};
	static const uint8_t natural_eight[] = {
		UINT8_C(0), UINT8_C(1), UINT8_C(2), UINT8_C(3),
		UINT8_C(4), UINT8_C(5), UINT8_C(6), UINT8_C(7)
	};

	CHECK(bc3_ztex_lane_policy_parse(1u, NULL, NULL, &policy));
	CHECK(policy.lane_count == UINT8_C(1));
	CHECK(policy.selected_count == UINT8_C(1));
	CHECK(policy.selection_mask == UINT8_C(0x01));
	check_order(&policy, natural_one, 1u);

	CHECK(bc3_ztex_lane_policy_parse(4u, NULL, NULL, &policy));
	CHECK(policy.lane_count == UINT8_C(4));
	CHECK(policy.selected_count == UINT8_C(4));
	CHECK(policy.selection_mask == UINT8_C(0x0f));
	check_order(&policy, natural_four, 4u);

	CHECK(bc3_ztex_lane_policy_parse(8u, NULL, NULL, &policy));
	CHECK(policy.lane_count == UINT8_C(8));
	CHECK(policy.selected_count == UINT8_C(8));
	CHECK(policy.selection_mask == UINT8_C(0xff));
	check_order(&policy, natural_eight, 8u);

	expect_failure(0u, NULL, NULL);
	expect_failure(9u, NULL, NULL);
	CHECK(!bc3_ztex_lane_policy_parse(4u, NULL, NULL, NULL));
}

static void test_only_forms(void)
{
	struct bc3_ztex_lane_policy policy;

	CHECK(bc3_ztex_lane_policy_parse(4u, "0", NULL, &policy));
	CHECK(policy.selection_mask == UINT8_C(0x01) &&
		policy.selected_count == UINT8_C(1));
	CHECK(bc3_ztex_lane_policy_parse(4u, "013", NULL, &policy));
	CHECK(policy.selection_mask == UINT8_C(0x0b) &&
		policy.selected_count == UINT8_C(3));
	CHECK(bc3_ztex_lane_policy_parse(4u, "3,1,0", NULL, &policy));
	CHECK(policy.selection_mask == UINT8_C(0x0b) &&
		policy.selected_count == UINT8_C(3));
	CHECK(bc3_ztex_lane_policy_parse(8u, "76543210", NULL, &policy));
	CHECK(policy.selection_mask == UINT8_C(0xff) &&
		policy.selected_count == UINT8_C(8));

	expect_failure(4u, "", NULL);
	expect_failure(4u, ",0", NULL);
	expect_failure(4u, "0,", NULL);
	expect_failure(4u, "0,,1", NULL);
	expect_failure(4u, "0;1", NULL);
	expect_failure(4u, "0 1", NULL);
	expect_failure(4u, "01,2", NULL);
	expect_failure(4u, "0,12", NULL);
	expect_failure(4u, "00", NULL);
	expect_failure(4u, "0,0", NULL);
	expect_failure(4u, "4", NULL);
	expect_failure(8u, "8", NULL);
	expect_failure(4u, "a", NULL);
}

static void test_order_forms(void)
{
	struct bc3_ztex_lane_policy policy;
	static const uint8_t order_one[] = { UINT8_C(0) };
	static const uint8_t order_four[] = {
		UINT8_C(1), UINT8_C(2), UINT8_C(3), UINT8_C(0)
	};
	static const uint8_t order_eight[] = {
		UINT8_C(7), UINT8_C(6), UINT8_C(5), UINT8_C(4),
		UINT8_C(3), UINT8_C(2), UINT8_C(1), UINT8_C(0)
	};

	CHECK(bc3_ztex_lane_policy_parse(1u, NULL, "0", &policy));
	check_order(&policy, order_one, 1u);
	CHECK(bc3_ztex_lane_policy_parse(4u, "1,3", "1230", &policy));
	CHECK(policy.selection_mask == UINT8_C(0x0a));
	check_order(&policy, order_four, 4u);
	CHECK(bc3_ztex_lane_policy_parse(8u, NULL, "76543210", &policy));
	check_order(&policy, order_eight, 8u);

	expect_failure(4u, NULL, "");
	expect_failure(4u, NULL, "012");
	expect_failure(4u, NULL, "01234");
	expect_failure(4u, NULL, "0012");
	expect_failure(4u, NULL, "0124");
	expect_failure(4u, NULL, "0,1,2,3");
	expect_failure(4u, NULL, "0 12");
	expect_failure(4u, NULL, "a123");
	expect_failure(8u, NULL, "01234568");
}

int main(void)
{
	test_defaults();
	test_only_forms();
	test_order_forms();
	if (failures != 0u) {
		fprintf(stderr, "FAIL: %u/%u BC3 ZTEX lane-policy checks failed\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u BC3 ZTEX lane-policy checks "
		"(strict selection, exact order, transactional failure)\n", checks);
	return EXIT_SUCCESS;
}
