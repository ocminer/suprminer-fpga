#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "stratum_transport_guard.h"

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
	struct stratum_transport_state state;
	uint64_t first, second, wrapped;

	stratum_transport_init(&state);
	CHECK(!stratum_transport_can_control(&state));
	CHECK(!stratum_transport_can_share(&state));
	CHECK(!stratum_transport_job_usable(&state, 1));
	CHECK(stratum_transport_begin_connect(&state, &first));
	CHECK(first == 1 && state.phase == STRATUM_TRANSPORT_CONNECTING);
	CHECK(!stratum_transport_can_control(&state));
	CHECK(!stratum_transport_mark_connected(&state, first + 1));
	CHECK(stratum_transport_mark_connected(&state, first));
	CHECK(stratum_transport_can_control(&state));
	CHECK(!stratum_transport_can_share(&state));
	CHECK(!stratum_transport_mark_authenticated(&state, first + 1));
	CHECK(stratum_transport_mark_authenticated(&state, first));
	CHECK(stratum_transport_can_share(&state));
	CHECK(stratum_transport_job_usable(&state, first));
	CHECK(!stratum_transport_job_usable(&state, first + 1));
	stratum_transport_poison(&state);
	CHECK(!stratum_transport_can_control(&state));
	CHECK(!stratum_transport_job_usable(&state, first));
	CHECK(stratum_transport_begin_connect(&state, &second));
	CHECK(second == first + 1);
	CHECK(stratum_transport_mark_connected(&state, second));
	CHECK(stratum_transport_mark_authenticated(&state, second));
	CHECK(!stratum_transport_job_usable(&state, first));
	CHECK(stratum_transport_job_usable(&state, second));

	state.generation = UINT64_MAX;
	stratum_transport_poison(&state);
	CHECK(stratum_transport_begin_connect(&state, &wrapped));
	CHECK(wrapped == 1);
	CHECK(!stratum_transport_mark_connected(NULL, wrapped));
	CHECK(!stratum_transport_begin_connect(NULL, &wrapped));
	CHECK(!stratum_transport_begin_connect(&state, NULL));

	/* A newly notified R34 job may be generated before legacy g_work catches
	 * up.  Exact Stratum generation/epoch validity must win regardless of the
	 * old cache's prevhash.  The same rule preserves clean=false old jobs. */
	CHECK(!stratum_submission_is_stale(true, true, false, false));
	CHECK(!stratum_submission_is_stale(true, true, true, false));
	CHECK(stratum_submission_is_stale(true, false, false, true));
	CHECK(stratum_submission_is_stale(true, false, true, true));
	CHECK(!stratum_submission_is_stale(false, false, true, false));
	CHECK(!stratum_submission_is_stale(false, false, false, true));
	CHECK(stratum_submission_is_stale(false, true, false, false));

	printf("STRATUM_TRANSPORT_GUARD_TEST_PASS checks=%u "
		"share=authenticated_only job=generation_bound poison=fail_closed "
		"wrap=nonzero submission=epoch_authoritative\n", checks);
	return EXIT_SUCCESS;
}
