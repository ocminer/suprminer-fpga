#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_liveness.h"
#include "bc3_ztex_progress.h"
#include "bc3_ztex_session.h"

#define BUILD_ID UINT32_C(0x00000034)
#define MAX_INTERVAL_US UINT64_C(30000000)
#define DISPLAY_INTERVAL_US UINT64_C(1000000)
#define NO_PROGRESS_TIMEOUT_US UINT64_C(60000000)
#define MAX_HPS UINT64_C(22000000)
#define SNAPSHOT_AGE_US UINT64_C(12000)
#define BURST_SLACK UINT32_C(45)

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

static struct bc3_ztex_status active_status(struct bc3_ztex_tuple tuple,
	uint32_t completed, uint32_t hash7)
{
	struct bc3_ztex_status status;

	memset(&status, 0, sizeof(status));
	status.abi_id = BC3_ZTEX_ABI_ID;
	status.build_id = BUILD_ID;
	status.version = BC3_ZTEX_PROTOCOL_VERSION;
	status.type = BC3_ZTEX_TYPE_STATUS;
	status.flags = BC3_ZTEX_FLAG_ACTIVE_VALID;
	status.active_session = tuple.session;
	status.active_epoch = tuple.epoch;
	status.completed_hashes = completed;
	status.progress_generation = completed;
	status.progress_nonce = completed ? completed - UINT32_C(1) : 0;
	status.progress_hash7 = completed ? hash7 : 0;
	return status;
}

/* Model the caller after the hash word has been independently recomputed on
 * the CPU. A repeated diagnostic is legal only for a nonpublishing baseline;
 * a newly advancing diagnostic is committed exactly once. */
static bool accept_verified_progress(struct bc3_ztex_progress_state *state,
	const struct bc3_ztex_status *status, bool baseline)
{
	struct bc3_ztex_progress_key key;
	enum bc3_ztex_progress_disposition disposition;

	disposition = bc3_ztex_progress_classify(state, status, &key);
	if (!bc3_ztex_progress_allowed_for_rate(disposition, baseline))
		return false;
	if (disposition == BC3_ZTEX_PROGRESS_REPEAT)
		return true;
	return bc3_ztex_progress_mark_verified(state, status, &key);
}

int main(void)
{
	struct bc3_ztex_session_state session;
	struct bc3_ztex_progress_state progress;
	struct bc3_ztex_tuple tuple;
	struct bc3_ztex_status status;
	enum bc3_ztex_work_slot head_slot;
	enum bc3_ztex_rate_disposition rate;
	enum bc3_ztex_display_rate_disposition display;
	bool switched;
	uint32_t delta;
	uint64_t elapsed;
	uint64_t last_progress_us;
	const uint64_t first_us = UINT64_C(1000000);
	const uint64_t stale_us = first_us + MAX_INTERVAL_US + UINT64_C(1);
	const uint64_t advanced_us = stale_us + MAX_INTERVAL_US + UINT64_C(1);

	CHECK(bc3_ztex_session_init(&session, BUILD_ID, 7));
	bc3_ztex_progress_init(&progress);
	CHECK(bc3_ztex_session_begin_offer(&session, &tuple));
	status = active_status(tuple, 1, UINT32_C(0x11111111));
	CHECK(bc3_ztex_session_reconcile(&session, &status, &head_slot,
		&switched));
	CHECK(switched && head_slot == BC3_ZTEX_SLOT_NONE);

	rate = bc3_ztex_session_rate_sample(&session, &status, first_us,
		MAX_INTERVAL_US, MAX_HPS, SNAPSHOT_AGE_US, BURST_SLACK,
		&delta, &elapsed);
	CHECK(rate == BC3_ZTEX_RATE_BASELINE);
	display = bc3_ztex_session_display_rate_sample(&session, &status,
		first_us, DISPLAY_INTERVAL_US, MAX_INTERVAL_US, MAX_HPS,
		SNAPSHOT_AGE_US, BURST_SLACK, &delta, &elapsed);
	CHECK(display == BC3_ZTEX_DISPLAY_RATE_BASELINE);
	CHECK(accept_verified_progress(&progress, &status, true));
	last_progress_us = first_us;

	/* An unchanged snapshot beyond the 30-second accounting window merely
	 * reanchors both baselines. Its exact already-verified diagnostic is not
	 * new progress and does not refresh the 60-second liveness timestamp. */
	rate = bc3_ztex_session_rate_sample(&session, &status, stale_us,
		MAX_INTERVAL_US, MAX_HPS, SNAPSHOT_AGE_US, BURST_SLACK,
		&delta, &elapsed);
	CHECK(rate == BC3_ZTEX_RATE_BASELINE && delta == 0 && elapsed == 0);
	display = bc3_ztex_session_display_rate_sample(&session, &status,
		stale_us, DISPLAY_INTERVAL_US, MAX_INTERVAL_US, MAX_HPS,
		SNAPSHOT_AGE_US, BURST_SLACK, &delta, &elapsed);
	CHECK(display == BC3_ZTEX_DISPLAY_RATE_BASELINE);
	CHECK(accept_verified_progress(&progress, &status, true));
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, false, last_progress_us, stale_us,
		NO_PROGRESS_TIMEOUT_US));

	/* A later long-gap snapshot really advanced. It is rebaselined without a
	 * published rate, but its new diagnostic must verify and refresh liveness. */
	status = active_status(tuple, 2, UINT32_C(0x22222222));
	rate = bc3_ztex_session_rate_sample(&session, &status, advanced_us,
		MAX_INTERVAL_US, MAX_HPS, SNAPSHOT_AGE_US, BURST_SLACK,
		&delta, &elapsed);
	CHECK(rate == BC3_ZTEX_RATE_REBASELINE_PROGRESS &&
		delta == 0 && elapsed == 0);
	display = bc3_ztex_session_display_rate_sample(&session, &status,
		advanced_us, DISPLAY_INTERVAL_US, MAX_INTERVAL_US, MAX_HPS,
		SNAPSHOT_AGE_US, BURST_SLACK, &delta, &elapsed);
	CHECK(display == BC3_ZTEX_DISPLAY_RATE_BASELINE);
	CHECK(bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, false, last_progress_us, advanced_us,
		NO_PROGRESS_TIMEOUT_US));
	CHECK(accept_verified_progress(&progress, &status, true));
	last_progress_us = advanced_us;
	CHECK(!bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, false, last_progress_us,
		advanced_us + NO_PROGRESS_TIMEOUT_US - UINT64_C(1),
		NO_PROGRESS_TIMEOUT_US));
	CHECK(bc3_ztex_hash_progress_timed_out(false, true, false, false,
		false, false, last_progress_us,
		advanced_us + NO_PROGRESS_TIMEOUT_US,
		NO_PROGRESS_TIMEOUT_US));

	printf("BC3_ZTEX_RUNTIME_POLICY_TEST_PASS checks=%u "
		"stale_repeat=baseline_only advancing_rebaseline=verified "
		"liveness_refresh=exact freeze_timeout=60s\n", checks);
	return EXIT_SUCCESS;
}
