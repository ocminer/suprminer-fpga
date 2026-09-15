#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_session.h"

#define BUILD_ID UINT32_C(0x52333201)
#define SHORT_MAX_INTERVAL_US UINT64_C(1000000)
#define RELEASE_MAX_INTERVAL_US UINT64_C(30000000)
#define RELEASE_MAX_HPS UINT64_C(22000000)
#define RELEASE_MAX_SNAPSHOT_AGE_US UINT64_C(12000)
#define RELEASE_BURST_SLACK UINT32_C(45)
#define RELEASE_SAMPLE_BOUND UINT32_C(660264045)

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

static struct bc3_ztex_status base_status(void)
{
	struct bc3_ztex_status status = { 0 };
	status.abi_id = BC3_ZTEX_ABI_ID;
	status.build_id = BUILD_ID;
	status.version = BC3_ZTEX_PROTOCOL_VERSION;
	status.type = BC3_ZTEX_TYPE_STATUS;
	return status;
}

static void set_active(struct bc3_ztex_status *status,
	struct bc3_ztex_tuple tuple)
{
	status->flags |= BC3_ZTEX_FLAG_ACTIVE_VALID;
	status->active_session = tuple.session;
	status->active_epoch = tuple.epoch;
}

static void set_completed(struct bc3_ztex_status *status, uint32_t completed)
{
	status->completed_hashes = completed;
	status->progress_generation = completed;
	status->progress_nonce = completed ? completed - 1u : 0;
	status->progress_hash7 = completed ? UINT32_C(0x13579bdf) : 0;
}

static void set_head(struct bc3_ztex_status *status,
	struct bc3_ztex_tuple tuple, uint32_t sequence, uint32_t nonce)
{
	status->flags |= BC3_ZTEX_FLAG_HEAD_VALID;
	status->type = BC3_ZTEX_TYPE_RESULT;
	status->occupancy = 1;
	status->head_session = tuple.session;
	status->head_epoch = tuple.epoch;
	status->head_sequence = sequence;
	status->head_nonce = nonce;
}

int main(void)
{
	struct bc3_ztex_session_state state;
	struct bc3_ztex_session_state rate_state, rate_before;
	struct bc3_ztex_session_state display_state, display_before;
	struct bc3_ztex_status status;
	struct bc3_ztex_status rate_status;
	struct bc3_ztex_tuple first, second, unknown = { 9, 9 };
	struct bc3_ztex_tuple rate_tuple;
	struct bc3_ztex_tuple display_tuple;
	enum bc3_ztex_display_rate_disposition display_disposition;
	enum bc3_ztex_work_slot head_slot;
	bool switched;
	uint32_t delta;
	uint64_t elapsed;

	CHECK(!bc3_ztex_session_init(NULL, BUILD_ID, 7));
	CHECK(!bc3_ztex_session_init(&state, 0, 7));
	CHECK(!bc3_ztex_session_init(&state, BUILD_ID, 0));
	CHECK(bc3_ztex_session_init(&state, BUILD_ID, 7));
	CHECK(bc3_ztex_session_begin_offer(&state, &first));
	CHECK(first.session == 7 && first.epoch == 1);
	CHECK(!bc3_ztex_session_begin_offer(&state, &second));
	CHECK(bc3_ztex_session_lookup(&state, first) ==
		BC3_ZTEX_SLOT_PENDING);

	status = base_status();
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	CHECK(!switched && head_slot == BC3_ZTEX_SLOT_NONE);
	set_active(&status, first);
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	CHECK(switched && state.active_valid && !state.pending_valid);
	CHECK(bc3_ztex_session_lookup(&state, first) ==
		BC3_ZTEX_SLOT_ACTIVE);

	CHECK(bc3_ztex_session_rate_sample(&state, &status, 1000,
			SHORT_MAX_INTERVAL_US, RELEASE_MAX_HPS,
			RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
			&delta, &elapsed) == BC3_ZTEX_RATE_BASELINE);
	set_completed(&status, 200);
	CHECK(bc3_ztex_session_rate_sample(&state, &status, 11000,
			SHORT_MAX_INTERVAL_US, RELEASE_MAX_HPS,
			RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
			&delta, &elapsed) == BC3_ZTEX_RATE_SAMPLE);
	CHECK(delta == 200 && elapsed == 10000);
	CHECK(bc3_ztex_session_rate_sample(&state, &status, 21000,
			SHORT_MAX_INTERVAL_US, RELEASE_MAX_HPS,
			RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
			&delta, &elapsed) == BC3_ZTEX_RATE_NO_PROGRESS);
	CHECK(delta == 0 && elapsed == 0 && state.rate_time_us == 11000);
	set_completed(&status, 199);
	CHECK(bc3_ztex_session_rate_sample(&state, &status, 31000,
			SHORT_MAX_INTERVAL_US, RELEASE_MAX_HPS,
			RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
			&delta, &elapsed) == BC3_ZTEX_RATE_INVALID);
	set_completed(&status, 300);
	CHECK(bc3_ztex_session_rate_sample(&state, &status, 2000000,
			SHORT_MAX_INTERVAL_US, RELEASE_MAX_HPS,
			RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
			&delta, &elapsed) ==
			BC3_ZTEX_RATE_REBASELINE_PROGRESS);
	CHECK(state.rate_completed == 300 && state.rate_time_us == 2000000 &&
		delta == 0 && elapsed == 0);

	/* A simple 1 hash/us envelope has an exact 115-hash bound over a
	 * 100-us host interval, 10 us of snapshot age, and five hashes of burst. */
	CHECK(bc3_ztex_session_init(&rate_state, BUILD_ID, 8));
	CHECK(bc3_ztex_session_begin_offer(&rate_state, &rate_tuple));
	rate_status = base_status();
	set_active(&rate_status, rate_tuple);
	CHECK(bc3_ztex_session_reconcile(&rate_state, &rate_status, &head_slot,
		&switched));
	CHECK(switched);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1000,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_BASELINE);
	rate_before = rate_state;
	set_completed(&rate_status, 115);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_SAMPLE);
	CHECK(delta == 115 && elapsed == 100);
	rate_state = rate_before;
	set_completed(&rate_status, 116);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_INVALID);
	CHECK(delta == 0 && elapsed == 0 &&
		memcmp(&rate_state, &rate_before, sizeof(rate_state)) == 0);
	set_completed(&rate_status, UINT32_MAX - 1u);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_INVALID);
	CHECK(memcmp(&rate_state, &rate_before, sizeof(rate_state)) == 0);

	/* Exercise another synthetic rate envelope as well. */
	rate_state.rate_valid = false;
	set_completed(&rate_status, 0);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 100,
		RELEASE_MAX_INTERVAL_US, RELEASE_MAX_HPS,
		RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
		&delta, &elapsed) == BC3_ZTEX_RATE_BASELINE);
	rate_before = rate_state;
	set_completed(&rate_status, RELEASE_SAMPLE_BOUND);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status,
		RELEASE_MAX_INTERVAL_US + 100, RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) == BC3_ZTEX_RATE_SAMPLE);
	CHECK(delta == RELEASE_SAMPLE_BOUND &&
		elapsed == RELEASE_MAX_INTERVAL_US);
	rate_state = rate_before;
	set_completed(&rate_status, RELEASE_SAMPLE_BOUND + 1u);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status,
		RELEASE_MAX_INTERVAL_US + 100, RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) == BC3_ZTEX_RATE_INVALID);
	CHECK(memcmp(&rate_state, &rate_before, sizeof(rate_state)) == 0);

	/* Invalid or overflowing caller limits fail before baseline/state update. */
	set_completed(&rate_status, 1);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, 0, 10, 5, &delta, &elapsed) == BC3_ZTEX_RATE_INVALID);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		UINT64_MAX, 1, 1, 0, &delta, &elapsed) ==
		BC3_ZTEX_RATE_INVALID);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, UINT64_MAX, 0, 0, &delta, &elapsed) ==
		BC3_ZTEX_RATE_INVALID);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 1100,
		1000, UINT64_C(1000000), 10, UINT32_MAX, &delta, &elapsed) ==
		BC3_ZTEX_RATE_INVALID);
	CHECK(memcmp(&rate_state, &rate_before, sizeof(rate_state)) == 0);

	/* Saturation is monotone: reach UINT32_MAX once, then report no progress;
	 * a stale/long sampling gap re-establishes a baseline without a delta. */
	rate_state.rate_valid = false;
	set_completed(&rate_status, UINT32_MAX - 5u);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 2000,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_BASELINE);
	set_completed(&rate_status, UINT32_MAX);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 2010,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_SAMPLE);
	CHECK(delta == 5 && elapsed == 10);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 2020,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_NO_PROGRESS);
	CHECK(rate_state.rate_time_us == 2010);
	CHECK(bc3_ztex_session_rate_sample(&rate_state, &rate_status, 3011,
		1000, UINT64_C(1000000), 10, 5, &delta, &elapsed) ==
		BC3_ZTEX_RATE_BASELINE);
	CHECK(rate_state.rate_time_us == 3011 && delta == 0 && elapsed == 0);

	/* A one-second display accumulator must not advance its baseline for the
	 * asynchronous ~10 ms FPGA/host observations that bias instantaneous rates.
	 * The aggregate sample is independently constrained by the physical bound. */
	CHECK(bc3_ztex_session_init(&display_state, BUILD_ID, 9));
	CHECK(bc3_ztex_session_begin_offer(&display_state, &display_tuple));
	rate_status = base_status();
	set_active(&rate_status, display_tuple);
	CHECK(bc3_ztex_session_reconcile(&display_state, &rate_status,
		&head_slot, &switched));
	CHECK(switched);
	display_disposition = bc3_ztex_session_display_rate_sample(
		&display_state, &rate_status, 1000, UINT64_C(1000000),
		RELEASE_MAX_INTERVAL_US, RELEASE_MAX_HPS,
		RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
		&delta, &elapsed);
	CHECK(display_disposition == BC3_ZTEX_DISPLAY_RATE_BASELINE);
	display_before = display_state;
	set_completed(&rate_status, UINT32_C(200000));
	CHECK(bc3_ztex_session_display_rate_sample(&display_state, &rate_status,
		11000, UINT64_C(1000000), RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) ==
		BC3_ZTEX_DISPLAY_RATE_ACCUMULATING);
	CHECK(display_state.display_rate_completed ==
		display_before.display_rate_completed &&
		display_state.display_rate_time_us ==
		display_before.display_rate_time_us && delta == 0 && elapsed == 0);
	set_completed(&rate_status, UINT32_C(19999980));
	CHECK(bc3_ztex_session_display_rate_sample(&display_state, &rate_status,
		1000999, UINT64_C(1000000), RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) ==
		BC3_ZTEX_DISPLAY_RATE_ACCUMULATING);
	set_completed(&rate_status, UINT32_C(20000000));
	CHECK(bc3_ztex_session_display_rate_sample(&display_state, &rate_status,
		1001000, UINT64_C(1000000), RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) ==
		BC3_ZTEX_DISPLAY_RATE_SAMPLE);
	CHECK(delta == UINT32_C(20000000) && elapsed == UINT64_C(1000000));
	display_before = display_state;
	set_completed(&rate_status, UINT32_C(43000000));
	CHECK(bc3_ztex_session_display_rate_sample(&display_state, &rate_status,
		2001000, UINT64_C(1000000), RELEASE_MAX_INTERVAL_US,
		RELEASE_MAX_HPS, RELEASE_MAX_SNAPSHOT_AGE_US,
		RELEASE_BURST_SLACK, &delta, &elapsed) ==
		BC3_ZTEX_DISPLAY_RATE_INVALID);
	CHECK(memcmp(&display_state, &display_before,
		sizeof(display_state)) == 0 && delta == 0 && elapsed == 0);
	CHECK(bc3_ztex_session_display_rate_sample(&display_state, &rate_status,
		2001000, 0, RELEASE_MAX_INTERVAL_US, RELEASE_MAX_HPS,
		RELEASE_MAX_SNAPSHOT_AGE_US, RELEASE_BURST_SLACK,
		&delta, &elapsed) == BC3_ZTEX_DISPLAY_RATE_INVALID);

	CHECK(bc3_ztex_session_begin_offer(&state, &second));
	CHECK(second.epoch == 2);
	status = base_status();
	set_active(&status, first);
	set_head(&status, first, 1, 0);
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	CHECK(!switched && head_slot == BC3_ZTEX_SLOT_ACTIVE);

	/* Hardware may not claim new active while exposing an old-tagged head. */
	set_active(&status, second);
	CHECK(!bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	CHECK(state.pending_valid && bc3_ztex_tuple_equal(state.active, first));

	status = base_status();
	set_active(&status, second);
	set_head(&status, second, 2, 0);
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	CHECK(switched && head_slot == BC3_ZTEX_SLOT_PENDING);
	CHECK(bc3_ztex_tuple_equal(state.active, second));
	CHECK(!state.pending_valid && !state.rate_valid);

	status = base_status();
	set_active(&status, second);
	set_head(&status, unknown, 3, 1);
	CHECK(!bc3_ztex_session_reconcile(&state, &status, &head_slot,
		&switched));
	status = base_status();
	status.build_id ^= 1;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status = base_status();
	status.occupancy = BC3_ZTEX_FIFO_DEPTH;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status.flags = BC3_ZTEX_FLAG_FIFO_FULL | BC3_ZTEX_FLAG_HEAD_VALID;
	status.type = BC3_ZTEX_TYPE_RESULT;
	status.flags |= BC3_ZTEX_FLAG_ACTIVE_VALID;
	status.active_session = 1;
	status.active_epoch = 1;
	status.head_session = 1;
	status.head_epoch = 1;
	CHECK(bc3_ztex_status_compatible(&status, BUILD_ID));
	status = base_status();
	set_active(&status, second);
	set_completed(&status, 9);
	status.completed_hashes = 10;
	CHECK(bc3_ztex_status_compatible(&status, BUILD_ID));
	status.completed_hashes = 11;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status.completed_hashes = 8;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status.completed_hashes = 9;
	status.progress_nonce++;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status = base_status();
	status.flags = BC3_ZTEX_FLAG_FIFO_FULL | BC3_ZTEX_FLAG_HEAD_VALID |
		BC3_ZTEX_FLAG_ACTIVE_VALID;
	status.type = BC3_ZTEX_TYPE_RESULT;
	status.occupancy = BC3_ZTEX_FIFO_DEPTH;
	status.active_session = 1;
	status.active_epoch = 1;
	status.head_session = 1;
	status.head_epoch = 1;
	status.flags |= BC3_ZTEX_FLAG_PROTOCOL_ERROR;
	CHECK(bc3_ztex_status_compatible(&status, BUILD_ID));
	CHECK(!bc3_ztex_status_healthy(&status, BUILD_ID));
	status = base_status();
	status.flags = BC3_ZTEX_FLAG_QUIESCED;
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED |
		BC3_ZTEX_FLAG_PAUSED | BC3_ZTEX_FLAG_QUIESCED;
	CHECK(bc3_ztex_status_compatible(&status, BUILD_ID));
	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED;
	CHECK(bc3_ztex_status_compatible(&status, BUILD_ID));
	status = base_status();
	set_active(&status, second);
	status.flags |= BC3_ZTEX_FLAG_PROTOCOL_ERROR;
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
			&switched));
	CHECK(head_slot == BC3_ZTEX_SLOT_NONE && !switched);
	set_head(&status, second, 3, 0);
	CHECK(bc3_ztex_session_reconcile(&state, &status, &head_slot,
			&switched));
	CHECK(head_slot == BC3_ZTEX_SLOT_ACTIVE && !switched);

	status = base_status();
	set_head(&status, second, 3, 0);
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));
	status = base_status();
	set_active(&status, second);
	set_head(&status, first, 3, 0);
	CHECK(!bc3_ztex_status_compatible(&status, BUILD_ID));

	state.pending_valid = false;
	state.next_epoch = UINT32_MAX;
	CHECK(bc3_ztex_session_begin_offer(&state, &first));
	CHECK(first.epoch == UINT32_MAX && state.next_epoch == 0);
	state.pending_valid = false;
	CHECK(!bc3_ztex_session_begin_offer(&state, &first));

	printf("BC3_ZTEX_SESSION_TEST_PASS checks=%u tuple_lifetime=2 "
			"old_head_blocks_retire=1 unknown=fail_closed "
			"counter_decrease=fail_closed rate_bound=physical "
			"saturation=monotone display_window=alias_safe protocol_error=drain_safe pause_flags=strict "
		"head_active=invariant epoch_wrap=fail_closed\n", checks);
	return EXIT_SUCCESS;
}
