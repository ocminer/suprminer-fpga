#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bc3_ztex_liveness.h"

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

int main(void)
{
	const uint64_t start = UINT64_C(1000000);
	const uint64_t timeout = UINT64_C(30000000);

	CHECK(!bc3_ztex_elapsed_reached(start, start + timeout - 1,
		timeout));
	CHECK(bc3_ztex_elapsed_reached(start, start + timeout, timeout));
	CHECK(bc3_ztex_elapsed_reached(0, start, timeout));
	CHECK(bc3_ztex_elapsed_reached(start, start - 1, timeout));

	CHECK(bc3_ztex_first_work_timed_out(false, true, false, false,
		start, start + timeout, timeout));
	CHECK(!bc3_ztex_first_work_timed_out(true, true, false, false,
		start, start + timeout, timeout));
	CHECK(!bc3_ztex_first_work_timed_out(false, false, false, false,
		start, start + timeout, timeout));
	CHECK(!bc3_ztex_first_work_timed_out(false, true, true, false,
		start, start + timeout, timeout));
	CHECK(!bc3_ztex_first_work_timed_out(false, true, false, true,
		start, start + timeout, timeout));

	CHECK(bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(true, true, false, false,
		false, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, false, false, false,
		false, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, true, false,
		false, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, false, true,
		false, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, false, false,
		true, false, start, start + timeout, timeout));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, true, start, start + timeout, timeout));

	printf("BC3_ZTEX_LIVENESS_TEST_PASS checks=%u first_work=bounded "
		"active_stall=bounded drain_pending_ack_publish_fifo=excluded "
		"clock_regression=fail_closed\n", checks);
	return EXIT_SUCCESS;
}
