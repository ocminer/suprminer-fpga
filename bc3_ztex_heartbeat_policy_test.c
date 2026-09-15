#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_heartbeat_policy.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		failures++; \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
	} \
} while (0)

static struct bc3_ztex_heartbeat_scope valid_scope(void)
{
	struct bc3_ztex_heartbeat_scope scope;

	memset(&scope, 0, sizeof(scope));
	scope.option_seen = true;
	scope.interval_seconds = BC3_ZTEX_HEARTBEAT_CANARY_SECONDS;
	scope.algorithm_sha3t = true;
	scope.use_ztex = true;
	scope.serial_only = BC3_ZTEX_HEARTBEAT_CANARY_SERIAL;
	scope.fpga_only = "0";
	scope.bitstream = "example-canary.bit";
	scope.api_listen = 0;
	scope.ztex_frequency_explicit = true;
	scope.ztex_frequency_exact_96 = true;
	scope.hash_clock_explicit = true;
	scope.hash_clock_exact_96 = true;
	return scope;
}

static void test_default_and_parser(void)
{
	struct bc3_ztex_heartbeat_scope scope;
	static const char *const invalid[] = {
		NULL, "", "0", "19", "21", "30", "020", "+20", "-20",
		" 20", "20 ", "20x", "20\n", "200", "99999999999999999999"
	};
	unsigned seconds;
	bool seen;
	size_t index;

	memset(&scope, 0, sizeof(scope));
	scope.interval_seconds = BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS;
	CHECK(BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS == 30u);
	CHECK(bc3_ztex_heartbeat_policy_validate(&scope) ==
		BC3_ZTEX_HEARTBEAT_POLICY_OK);
	scope.interval_seconds = BC3_ZTEX_HEARTBEAT_CANARY_SECONDS;
	CHECK(bc3_ztex_heartbeat_policy_validate(&scope) ==
		BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL);

	seconds = BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS;
	seen = false;
	CHECK(bc3_ztex_heartbeat_option_apply("20", &seen, &seconds) ==
		BC3_ZTEX_HEARTBEAT_POLICY_OK);
	CHECK(seen && seconds == BC3_ZTEX_HEARTBEAT_CANARY_SECONDS);
	CHECK(bc3_ztex_heartbeat_option_apply("20", &seen, &seconds) ==
		BC3_ZTEX_HEARTBEAT_POLICY_DUPLICATE);
	CHECK(seen && seconds == BC3_ZTEX_HEARTBEAT_CANARY_SECONDS);

	for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
		seconds = BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS;
		seen = false;
		CHECK(bc3_ztex_heartbeat_option_apply(invalid[index], &seen,
			&seconds) == BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL);
		CHECK(!seen && seconds == BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS);
	}
	CHECK(bc3_ztex_heartbeat_option_apply("20", NULL, &seconds) ==
		BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL);
	CHECK(bc3_ztex_heartbeat_option_apply("20", &seen, NULL) ==
		BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL);
}

static void test_scope(void)
{
	struct bc3_ztex_heartbeat_scope scope;
	char max_serial[] = "A1_b-C9dE0";
	char long_serial[] = "A1_b-C9dE01";
	char max_bitstream[BC3_ZTEX_CANARY_BITSTREAM_MAX + 1u];
	char long_bitstream[BC3_ZTEX_CANARY_BITSTREAM_MAX + 2u];

	scope = valid_scope();
	CHECK(bc3_ztex_heartbeat_policy_validate(&scope) ==
		BC3_ZTEX_HEARTBEAT_POLICY_OK);
	CHECK(bc3_ztex_heartbeat_serial_is_safe(max_serial));
	CHECK(!bc3_ztex_heartbeat_serial_is_safe(long_serial));
	CHECK(!bc3_ztex_heartbeat_serial_is_safe("BAD!"));
	memset(max_bitstream, 'a', sizeof(max_bitstream));
	max_bitstream[sizeof(max_bitstream) - 1u] = '\0';
	CHECK(bc3_ztex_heartbeat_bitstream_is_safe(max_bitstream));
	memset(long_bitstream, 'a', sizeof(long_bitstream));
	long_bitstream[sizeof(long_bitstream) - 1u] = '\0';
	CHECK(!bc3_ztex_heartbeat_bitstream_is_safe(long_bitstream));

#define EXPECT_SCOPE_FAILURE(field, value, result) do { \
	scope = valid_scope(); \
	scope.field = (value); \
	CHECK(bc3_ztex_heartbeat_policy_validate(&scope) == (result)); \
} while (0)

	EXPECT_SCOPE_FAILURE(interval_seconds, 30u,
		BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL);
	EXPECT_SCOPE_FAILURE(algorithm_sha3t, false,
		BC3_ZTEX_HEARTBEAT_POLICY_ALGORITHM);
	EXPECT_SCOPE_FAILURE(use_ztex, false,
		BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE);
	EXPECT_SCOPE_FAILURE(use_cpu, true,
		BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE);
	EXPECT_SCOPE_FAILURE(use_serial, true,
		BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE);
	EXPECT_SCOPE_FAILURE(serial_only, NULL,
		BC3_ZTEX_HEARTBEAT_POLICY_SERIAL);
	EXPECT_SCOPE_FAILURE(serial_only, "",
		BC3_ZTEX_HEARTBEAT_POLICY_SERIAL);
	EXPECT_SCOPE_FAILURE(serial_only, "TEST000002!",
		BC3_ZTEX_HEARTBEAT_POLICY_SERIAL);
	EXPECT_SCOPE_FAILURE(serial_only, "TEST000003",
		BC3_ZTEX_HEARTBEAT_POLICY_SERIAL);
	EXPECT_SCOPE_FAILURE(fpga_only, NULL,
		BC3_ZTEX_HEARTBEAT_POLICY_LANE);
	EXPECT_SCOPE_FAILURE(fpga_only, "",
		BC3_ZTEX_HEARTBEAT_POLICY_LANE);
	EXPECT_SCOPE_FAILURE(fpga_only, "00",
		BC3_ZTEX_HEARTBEAT_POLICY_LANE);
	EXPECT_SCOPE_FAILURE(fpga_only, "1",
		BC3_ZTEX_HEARTBEAT_POLICY_LANE);
	EXPECT_SCOPE_FAILURE(fpga_only, "0,1",
		BC3_ZTEX_HEARTBEAT_POLICY_LANE);
	EXPECT_SCOPE_FAILURE(bitstream, NULL,
		BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM);
	EXPECT_SCOPE_FAILURE(bitstream, "",
		BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM);
	EXPECT_SCOPE_FAILURE(bitstream, "../candidate.bit",
		BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM);
	EXPECT_SCOPE_FAILURE(bitstream, "dir/candidate.bit",
		BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM);
	EXPECT_SCOPE_FAILURE(bitstream, "dir\\candidate.bit",
		BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM);
	EXPECT_SCOPE_FAILURE(api_listen, 4048,
		BC3_ZTEX_HEARTBEAT_POLICY_API);
	EXPECT_SCOPE_FAILURE(force_firmware, true,
		BC3_ZTEX_HEARTBEAT_POLICY_FIRMWARE);
	EXPECT_SCOPE_FAILURE(auto_frequency, true,
		BC3_ZTEX_HEARTBEAT_POLICY_AUTO_FREQUENCY);
	EXPECT_SCOPE_FAILURE(ztex_frequency_explicit, false,
		BC3_ZTEX_HEARTBEAT_POLICY_ZTEX_FREQUENCY);
	EXPECT_SCOPE_FAILURE(ztex_frequency_exact_96, false,
		BC3_ZTEX_HEARTBEAT_POLICY_ZTEX_FREQUENCY);
	EXPECT_SCOPE_FAILURE(hash_clock_explicit, false,
		BC3_ZTEX_HEARTBEAT_POLICY_HASH_CLOCK);
	EXPECT_SCOPE_FAILURE(hash_clock_exact_96, false,
		BC3_ZTEX_HEARTBEAT_POLICY_HASH_CLOCK);

#undef EXPECT_SCOPE_FAILURE
	CHECK(bc3_ztex_heartbeat_policy_validate(NULL) ==
		BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL);
}

int main(void)
{
	test_default_and_parser();
	test_scope();
	if (failures != 0u) {
		fprintf(stderr, "FAIL: %u/%u BC3 ZTEX heartbeat-policy checks failed\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u BC3 ZTEX heartbeat-policy checks "
		"(default=30, canary=20, exact lane0 scope, hostile inputs)\n",
		checks);
	return EXIT_SUCCESS;
}
