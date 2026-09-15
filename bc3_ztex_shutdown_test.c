#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bc3_ztex_shutdown.h"

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
	struct bc3_ztex_shutdown_state state;

	bc3_ztex_shutdown_init(&state);
	CHECK(!state.stop_requested && !state.failure);
	CHECK(!bc3_ztex_shutdown_can_enqueue(&state));
	CHECK(!bc3_ztex_shutdown_mark_enqueued(&state, 1));
	CHECK(!bc3_ztex_shutdown_mark_consumed(&state));
	CHECK(!bc3_ztex_shutdown_final_success(&state, 0));

	/* Normal signal: monotone request, one typed token, one consumption. */
	CHECK(bc3_ztex_shutdown_request(&state, false));
	CHECK(state.stop_requested && !state.failure);
	CHECK(bc3_ztex_shutdown_can_enqueue(&state));
	CHECK(!bc3_ztex_shutdown_mark_enqueued(&state, 0));
	CHECK(bc3_ztex_shutdown_mark_enqueued(&state, 100));
	CHECK(!bc3_ztex_shutdown_can_enqueue(&state));
	CHECK(!bc3_ztex_shutdown_mark_enqueued(&state, 101));
	CHECK(bc3_ztex_shutdown_deadline_armed(&state));
	CHECK(bc3_ztex_shutdown_expired(&state, 99, 50));
	CHECK(!bc3_ztex_shutdown_expired(&state, 100, 50));
	CHECK(!bc3_ztex_shutdown_expired(&state, 149, 50));
	CHECK(bc3_ztex_shutdown_expired(&state, 150, 50));
	CHECK(bc3_ztex_shutdown_expired(&state, 101, 0));
	CHECK(bc3_ztex_shutdown_mark_consumed(&state));
	CHECK(!bc3_ztex_shutdown_mark_consumed(&state));
	CHECK(!bc3_ztex_shutdown_deadline_armed(&state));
	CHECK(!bc3_ztex_shutdown_expired(&state, UINT64_MAX, 1));
	CHECK(bc3_ztex_shutdown_final_success(&state, 0));
	CHECK(!bc3_ztex_shutdown_final_success(&state, 1));

	/* Workio dies first: failure is sticky and no unauthenticated wake counts. */
	bc3_ztex_shutdown_init(&state);
	CHECK(bc3_ztex_shutdown_request(&state, true));
	CHECK(state.stop_requested && state.failure);
	CHECK(bc3_ztex_shutdown_request(&state, false));
	CHECK(state.failure);
	CHECK(!bc3_ztex_shutdown_final_success(&state, 0));

	/* Post-worker startup failure stays failed even after a complete token. */
	CHECK(bc3_ztex_shutdown_mark_enqueued(&state, 200));
	CHECK(bc3_ztex_shutdown_mark_consumed(&state));
	CHECK(!bc3_ztex_shutdown_final_success(&state, 0));

	/* Enqueue failure leaves the handshake incomplete. */
	bc3_ztex_shutdown_init(&state);
	CHECK(bc3_ztex_shutdown_request(&state, false));
	CHECK(bc3_ztex_shutdown_can_enqueue(&state));
	CHECK(!bc3_ztex_shutdown_final_success(&state, 0));

	CHECK(!bc3_ztex_shutdown_request(NULL, true));
	CHECK(!bc3_ztex_shutdown_can_enqueue(NULL));
	CHECK(!bc3_ztex_shutdown_mark_enqueued(NULL, 1));
	CHECK(!bc3_ztex_shutdown_mark_consumed(NULL));
	CHECK(!bc3_ztex_shutdown_deadline_armed(NULL));
	CHECK(!bc3_ztex_shutdown_expired(NULL, 1, 1));
	CHECK(!bc3_ztex_shutdown_final_success(NULL, 0));

	printf("BC3_ZTEX_SHUTDOWN_TEST_PASS checks=%u monotone=1 "
		"typed_token=exact deadline=monotonic final=fail_closed\n", checks);
	return EXIT_SUCCESS;
}
