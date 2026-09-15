#ifndef BC3_ZTEX_SESSION_H
#define BC3_ZTEX_SESSION_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bc3_ztex_protocol.h"

struct bc3_ztex_tuple {
	uint32_t session;
	uint32_t epoch;
};

enum bc3_ztex_work_slot {
	BC3_ZTEX_SLOT_NONE = 0,
	BC3_ZTEX_SLOT_ACTIVE,
	BC3_ZTEX_SLOT_PENDING
};

enum bc3_ztex_rate_disposition {
	BC3_ZTEX_RATE_INVALID = 0,
	BC3_ZTEX_RATE_BASELINE,
	BC3_ZTEX_RATE_REBASELINE_PROGRESS,
	BC3_ZTEX_RATE_NO_PROGRESS,
	BC3_ZTEX_RATE_SAMPLE
};

enum bc3_ztex_display_rate_disposition {
	BC3_ZTEX_DISPLAY_RATE_INVALID = 0,
	BC3_ZTEX_DISPLAY_RATE_BASELINE,
	BC3_ZTEX_DISPLAY_RATE_ACCUMULATING,
	BC3_ZTEX_DISPLAY_RATE_SAMPLE
};

struct bc3_ztex_session_state {
	uint32_t expected_build_id;
	uint32_t session;
	uint32_t next_epoch;
	bool active_valid;
	bool pending_valid;
	struct bc3_ztex_tuple active;
	struct bc3_ztex_tuple pending;
	bool rate_valid;
	struct bc3_ztex_tuple rate_tuple;
	uint32_t rate_completed;
	uint64_t rate_time_us;
	bool display_rate_valid;
	struct bc3_ztex_tuple display_rate_tuple;
	uint32_t display_rate_completed;
	uint64_t display_rate_time_us;
};

static inline bool bc3_ztex_tuple_equal(struct bc3_ztex_tuple a,
	struct bc3_ztex_tuple b)
{
	return a.session == b.session && a.epoch == b.epoch;
}

static inline bool bc3_ztex_session_init(
	struct bc3_ztex_session_state *state, uint32_t expected_build_id,
	uint32_t session)
{
	if (!state || expected_build_id == 0 || session == 0)
		return false;
	memset(state, 0, sizeof(*state));
	state->expected_build_id = expected_build_id;
	state->session = session;
	state->next_epoch = 1;
	return true;
}

/* Reserve the only pending tuple.  Epoch zero is never issued, so wrapping
 * the 32-bit allocator fails closed rather than reusing a decoder identity. */
static inline bool bc3_ztex_session_begin_offer(
	struct bc3_ztex_session_state *state, struct bc3_ztex_tuple *tuple)
{
	if (!state || !tuple || state->pending_valid || state->next_epoch == 0)
		return false;
	state->pending.session = state->session;
	state->pending.epoch = state->next_epoch++;
	state->pending_valid = true;
	*tuple = state->pending;
	return true;
}

static inline enum bc3_ztex_work_slot bc3_ztex_session_lookup(
	const struct bc3_ztex_session_state *state, struct bc3_ztex_tuple tuple)
{
	if (!state)
		return BC3_ZTEX_SLOT_NONE;
	if (state->active_valid && bc3_ztex_tuple_equal(state->active, tuple))
		return BC3_ZTEX_SLOT_ACTIVE;
	if (state->pending_valid && bc3_ztex_tuple_equal(state->pending, tuple))
		return BC3_ZTEX_SLOT_PENDING;
	return BC3_ZTEX_SLOT_NONE;
}

static inline bool bc3_ztex_status_compatible(
	const struct bc3_ztex_status *status, uint32_t expected_build_id)
{
	bool head_valid;
	bool full;
	bool active_valid;
	bool paused;
	bool quiesced;
	bool pause_latched;

	if (!status || expected_build_id == 0 ||
	    status->abi_id != BC3_ZTEX_ABI_ID ||
	    status->version != BC3_ZTEX_PROTOCOL_VERSION ||
	    status->build_id != expected_build_id ||
	    (status->type != BC3_ZTEX_TYPE_RESULT &&
	     status->type != BC3_ZTEX_TYPE_STATUS) ||
	    (status->flags & (uint8_t)~BC3_ZTEX_FLAG_MASK) != 0 ||
	    status->occupancy > BC3_ZTEX_FIFO_DEPTH)
		return false;
	head_valid = (status->flags & BC3_ZTEX_FLAG_HEAD_VALID) != 0;
	full = (status->flags & BC3_ZTEX_FLAG_FIFO_FULL) != 0;
	active_valid = (status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID) != 0;
	paused = (status->flags & BC3_ZTEX_FLAG_PAUSED) != 0;
	quiesced = (status->flags & BC3_ZTEX_FLAG_QUIESCED) != 0;
	pause_latched =
		(status->flags & BC3_ZTEX_FLAG_PAUSE_LATCHED) != 0;
	if (head_valid != (status->type == BC3_ZTEX_TYPE_RESULT) ||
	    head_valid != (status->occupancy != 0) ||
	    full != (status->occupancy == BC3_ZTEX_FIFO_DEPTH) ||
	    (active_valid &&
	     (status->active_session == 0 || status->active_epoch == 0)) ||
	    (!active_valid &&
	     (status->progress_generation != 0 || status->progress_nonce != 0 ||
	      status->progress_hash7 != 0 || status->completed_hashes != 0)) ||
	    (active_valid &&
	     (status->progress_generation > status->completed_hashes ||
	      status->completed_hashes - status->progress_generation > 1u ||
	      (status->progress_generation != 0 &&
	       status->progress_nonce != status->progress_generation - 1u))) ||
	    (status->progress_generation == 0 &&
	     (status->progress_nonce != 0 || status->progress_hash7 != 0)) ||
	    (quiesced && (!paused || !pause_latched)) ||
	    (!active_valid &&
	     (status->active_session != 0 || status->active_epoch != 0)) ||
	    (head_valid &&
	     (!active_valid || status->head_session != status->active_session ||
	      status->head_epoch != status->active_epoch)) ||
	    (!head_valid &&
	     (status->head_session != 0 || status->head_epoch != 0 ||
	      status->head_sequence != 0 ||
	      status->head_nonce != 0 || status->head_hash7 != 0)))
		return false;
	return true;
}

static inline bool bc3_ztex_status_healthy(
	const struct bc3_ztex_status *status, uint32_t expected_build_id)
{
	return bc3_ztex_status_compatible(status, expected_build_id) &&
		!(status->flags & BC3_ZTEX_FLAG_PROTOCOL_ERROR);
}

/* Reconcile one coherent status snapshot.  A sticky protocol-error flag is
 * deliberately diagnostic here: malformed frames are semantically inert in
 * the decoder, and known queued heads must remain drainable after a short OUT
 * transfer.  Qualification policy can still reject !status_healthy().
 * head_slot names the work object
 * required to verify the visible FIFO head before any caller-side swap.
 * switched permits retiring the old active object only because an old-tagged
 * head in the same new-active snapshot is rejected as an invariant failure. */
static inline bool bc3_ztex_session_reconcile(
	struct bc3_ztex_session_state *state,
	const struct bc3_ztex_status *status,
	enum bc3_ztex_work_slot *head_slot, bool *switched)
{
	bool hw_active;
	struct bc3_ztex_tuple hw_tuple;
	enum bc3_ztex_work_slot visible_head = BC3_ZTEX_SLOT_NONE;

	if (head_slot)
		*head_slot = BC3_ZTEX_SLOT_NONE;
	if (switched)
		*switched = false;
	if (!state || !status || !head_slot || !switched ||
	    !bc3_ztex_status_compatible(status, state->expected_build_id))
		return false;
	if (status->flags & BC3_ZTEX_FLAG_HEAD_VALID) {
		struct bc3_ztex_tuple head = {
			status->head_session, status->head_epoch
		};
		visible_head = bc3_ztex_session_lookup(state, head);
		if (visible_head == BC3_ZTEX_SLOT_NONE)
			return false;
	}

	hw_active = (status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID) != 0;
	hw_tuple.session = status->active_session;
	hw_tuple.epoch = status->active_epoch;
	if (!hw_active) {
		if (state->active_valid)
			return false;
		*head_slot = visible_head;
		return true;
	}

	if (state->pending_valid &&
	    bc3_ztex_tuple_equal(hw_tuple, state->pending)) {
		if (visible_head == BC3_ZTEX_SLOT_ACTIVE)
			return false;
		state->active = state->pending;
		state->active_valid = true;
		state->pending_valid = false;
		state->rate_valid = false;
		state->display_rate_valid = false;
		*switched = true;
	} else if (!state->active_valid ||
	           !bc3_ztex_tuple_equal(hw_tuple, state->active)) {
		return false;
	}

	*head_slot = visible_head;
	return true;
}

/* Produce a completion delta only within one active tuple.  The RTL counter
 * saturates at ffffffff, so any decrease is an invariant failure.  Bound each
 * advancing sample by the qualified physical rate, worst-case age difference
 * between coherent status snapshots, and short architectural completion burst.
 * Caller limits whose worst case approaches the complete uint32 range are
 * rejected before any state is changed. */
static inline enum bc3_ztex_rate_disposition bc3_ztex_session_rate_sample(
	struct bc3_ztex_session_state *state,
	const struct bc3_ztex_status *status, uint64_t now_us,
	uint64_t max_interval_us, uint64_t max_hps,
	uint64_t max_snapshot_age_us, uint32_t burst_slack,
	uint32_t *completed_delta, uint64_t *elapsed_us)
{
	struct bc3_ztex_tuple hw_tuple;
	uint64_t elapsed;
	uint64_t limit_window_us;
	uint64_t hash_budget;
	uint64_t product_budget;
	uint64_t effective_us;
	uint64_t product;
	uint64_t allowed_hashes;

	if (completed_delta)
		*completed_delta = 0;
	if (elapsed_us)
		*elapsed_us = 0;
	if (!state || !status || !completed_delta || !elapsed_us ||
	    max_interval_us == 0 || max_hps == 0 ||
	    max_interval_us > UINT64_MAX - max_snapshot_age_us ||
	    burst_slack == UINT32_MAX ||
	    !bc3_ztex_status_compatible(status, state->expected_build_id) ||
	    !(status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID))
		return BC3_ZTEX_RATE_INVALID;
	/* Keep the largest caller-authorized sample strictly below the complete
	 * uint32 range.  This makes an arbitrary near-2^32 jump unrepresentable as
	 * a plausible sample and also proves the multiplication below cannot
	 * overflow uint64. */
	limit_window_us = max_interval_us + max_snapshot_age_us;
	hash_budget = (uint64_t)UINT32_MAX - 1u - burst_slack;
	product_budget = hash_budget * UINT64_C(1000000);
	if (limit_window_us > product_budget / max_hps)
		return BC3_ZTEX_RATE_INVALID;
	hw_tuple.session = status->active_session;
	hw_tuple.epoch = status->active_epoch;
	if (!state->active_valid ||
	    !bc3_ztex_tuple_equal(hw_tuple, state->active))
		return BC3_ZTEX_RATE_INVALID;
	if (!state->rate_valid ||
	    !bc3_ztex_tuple_equal(state->rate_tuple, hw_tuple)) {
		state->rate_valid = true;
		state->rate_tuple = hw_tuple;
		state->rate_completed = status->completed_hashes;
		state->rate_time_us = now_us;
		state->display_rate_valid = false;
		return BC3_ZTEX_RATE_BASELINE;
	}
	if (now_us <= state->rate_time_us ||
	    status->completed_hashes < state->rate_completed)
		return BC3_ZTEX_RATE_INVALID;
	elapsed = now_us - state->rate_time_us;
	if (elapsed > max_interval_us) {
		bool advanced =
			status->completed_hashes != state->rate_completed;

		state->rate_completed = status->completed_hashes;
		state->rate_time_us = now_us;
		state->display_rate_valid = false;
		return advanced ? BC3_ZTEX_RATE_REBASELINE_PROGRESS :
			BC3_ZTEX_RATE_BASELINE;
	}
	if (status->completed_hashes == state->rate_completed)
		return BC3_ZTEX_RATE_NO_PROGRESS;
	effective_us = elapsed + max_snapshot_age_us;
	product = max_hps * effective_us;
	allowed_hashes = product / UINT64_C(1000000);
	if (product % UINT64_C(1000000) != 0)
		allowed_hashes++;
	allowed_hashes += burst_slack;
	if ((uint64_t)(status->completed_hashes - state->rate_completed) >
	    allowed_hashes)
		return BC3_ZTEX_RATE_INVALID;
	*completed_delta = status->completed_hashes - state->rate_completed;
	*elapsed_us = elapsed;
	state->rate_completed = status->completed_hashes;
	state->rate_time_us = now_us;
	return BC3_ZTEX_RATE_SAMPLE;
}

/* Independently accumulate completion telemetry over a long host-time window
 * before publishing MH/s.  The FPGA publishes snapshots periodically, while
 * USB polling is asynchronous; dividing each changed snapshot by the latest
 * host poll interval produces a deterministic alias bias.  This baseline is
 * therefore never advanced for sub-window samples.  The aggregate delta is
 * bounded again with a single snapshot-age allowance so repeated short-frame
 * allowances cannot inflate the displayed rate. */
static inline enum bc3_ztex_display_rate_disposition
bc3_ztex_session_display_rate_sample(
	struct bc3_ztex_session_state *state,
	const struct bc3_ztex_status *status, uint64_t now_us,
	uint64_t min_interval_us, uint64_t max_interval_us, uint64_t max_hps,
	uint64_t max_snapshot_age_us, uint32_t burst_slack,
	uint32_t *completed_delta, uint64_t *elapsed_us)
{
	struct bc3_ztex_tuple hw_tuple;
	uint64_t elapsed;
	uint64_t limit_window_us;
	uint64_t hash_budget;
	uint64_t product_budget;
	uint64_t effective_us;
	uint64_t product;
	uint64_t allowed_hashes;
	uint32_t delta;

	if (completed_delta)
		*completed_delta = 0;
	if (elapsed_us)
		*elapsed_us = 0;
	if (!state || !status || !completed_delta || !elapsed_us ||
	    min_interval_us == 0 || min_interval_us > max_interval_us ||
	    max_hps == 0 ||
	    max_interval_us > UINT64_MAX - max_snapshot_age_us ||
	    burst_slack == UINT32_MAX ||
	    !bc3_ztex_status_compatible(status, state->expected_build_id) ||
	    !(status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID))
		return BC3_ZTEX_DISPLAY_RATE_INVALID;
	limit_window_us = max_interval_us + max_snapshot_age_us;
	hash_budget = (uint64_t)UINT32_MAX - 1u - burst_slack;
	product_budget = hash_budget * UINT64_C(1000000);
	if (limit_window_us > product_budget / max_hps)
		return BC3_ZTEX_DISPLAY_RATE_INVALID;
	hw_tuple.session = status->active_session;
	hw_tuple.epoch = status->active_epoch;
	if (!state->active_valid ||
	    !bc3_ztex_tuple_equal(hw_tuple, state->active))
		return BC3_ZTEX_DISPLAY_RATE_INVALID;
	if (!state->display_rate_valid ||
	    !bc3_ztex_tuple_equal(state->display_rate_tuple, hw_tuple)) {
		state->display_rate_valid = true;
		state->display_rate_tuple = hw_tuple;
		state->display_rate_completed = status->completed_hashes;
		state->display_rate_time_us = now_us;
		return BC3_ZTEX_DISPLAY_RATE_BASELINE;
	}
	if (now_us <= state->display_rate_time_us ||
	    status->completed_hashes < state->display_rate_completed)
		return BC3_ZTEX_DISPLAY_RATE_INVALID;
	elapsed = now_us - state->display_rate_time_us;
	if (elapsed > max_interval_us) {
		state->display_rate_completed = status->completed_hashes;
		state->display_rate_time_us = now_us;
		return BC3_ZTEX_DISPLAY_RATE_BASELINE;
	}
	if (status->completed_hashes == state->display_rate_completed ||
	    elapsed < min_interval_us)
		return BC3_ZTEX_DISPLAY_RATE_ACCUMULATING;
	effective_us = elapsed + max_snapshot_age_us;
	product = max_hps * effective_us;
	allowed_hashes = product / UINT64_C(1000000);
	if (product % UINT64_C(1000000) != 0)
		allowed_hashes++;
	allowed_hashes += burst_slack;
	delta = status->completed_hashes - state->display_rate_completed;
	if ((uint64_t)delta > allowed_hashes)
		return BC3_ZTEX_DISPLAY_RATE_INVALID;
	*completed_delta = delta;
	*elapsed_us = elapsed;
	state->display_rate_completed = status->completed_hashes;
	state->display_rate_time_us = now_us;
	return BC3_ZTEX_DISPLAY_RATE_SAMPLE;
}

#endif
