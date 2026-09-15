#ifndef BC3_ZTEX_RESULT_H
#define BC3_ZTEX_RESULT_H

#include <stdbool.h>
#include <stdint.h>

#include "bc3_ztex_protocol.h"

struct bc3_ztex_result_key {
	uint32_t session;
	uint32_t epoch;
	uint32_t sequence;
	uint32_t nonce;
	uint32_t hash7;
};

enum bc3_ztex_result_disposition {
	BC3_ZTEX_RESULT_INVALID = 0,
	BC3_ZTEX_RESULT_EMPTY,
	BC3_ZTEX_RESULT_NEW,
	BC3_ZTEX_RESULT_ACK_RETRY
};

struct bc3_ztex_result_state {
	uint32_t next_sequence;
	bool processed_valid;
	bool exhausted;
	struct bc3_ztex_result_key processed;
};

static inline void bc3_ztex_result_init(
	struct bc3_ztex_result_state *state)
{
	if (!state)
		return;
	state->next_sequence = 1;
	state->processed_valid = false;
	state->exhausted = false;
}

static inline bool bc3_ztex_result_key_equal(
	struct bc3_ztex_result_key a, struct bc3_ztex_result_key b)
{
	return a.session == b.session && a.epoch == b.epoch &&
		a.sequence == b.sequence && a.nonce == b.nonce &&
		a.hash7 == b.hash7;
}

static inline bool bc3_ztex_result_key_from_status(
	const struct bc3_ztex_status *status,
	struct bc3_ztex_result_key *key)
{
	if (!status || !key ||
	    !(status->flags & BC3_ZTEX_FLAG_HEAD_VALID) ||
	    status->type != BC3_ZTEX_TYPE_RESULT)
		return false;
	key->session = status->head_session;
	key->epoch = status->head_epoch;
	key->sequence = status->head_sequence;
	key->nonce = status->head_nonce;
	key->hash7 = status->head_hash7;
	return true;
}

/* The hardware sequence starts at one after configuration and advances once
 * for every FIFO insertion.  A byte-identical repeat is an uncertain-ACK
 * retry; every other discontinuity is unsafe and fails closed. */
static inline enum bc3_ztex_result_disposition
bc3_ztex_result_classify(const struct bc3_ztex_result_state *state,
	const struct bc3_ztex_status *status,
	struct bc3_ztex_result_key *key)
{
	struct bc3_ztex_result_key candidate;

	if (!state || !status)
		return BC3_ZTEX_RESULT_INVALID;
	if (!(status->flags & BC3_ZTEX_FLAG_HEAD_VALID))
		return status->type == BC3_ZTEX_TYPE_STATUS ?
			BC3_ZTEX_RESULT_EMPTY : BC3_ZTEX_RESULT_INVALID;
	if (!bc3_ztex_result_key_from_status(status, &candidate))
		return BC3_ZTEX_RESULT_INVALID;
	if (key)
		*key = candidate;
	if (state->processed_valid &&
	    bc3_ztex_result_key_equal(state->processed, candidate))
		return BC3_ZTEX_RESULT_ACK_RETRY;
	if (state->exhausted || candidate.sequence != state->next_sequence)
		return BC3_ZTEX_RESULT_INVALID;
	return BC3_ZTEX_RESULT_NEW;
}

/* Call only after the result has either been rejected/accounted locally or
 * its queue-owned work copy has been published successfully.  The same status
 * snapshot used for classification binds every key field before the sequence
 * is advanced, so a damaged or accidentally replaced caller-side key cannot
 * authorize an ACK. */
static inline bool bc3_ztex_result_mark_processed(
	struct bc3_ztex_result_state *state,
	const struct bc3_ztex_status *status,
	const struct bc3_ztex_result_key *key)
{
	struct bc3_ztex_result_key candidate;

	if (!state || !status || !key ||
	    state->exhausted ||
	    !bc3_ztex_result_key_from_status(status, &candidate) ||
	    !bc3_ztex_result_key_equal(candidate, *key) ||
	    key->sequence != state->next_sequence)
		return false;
	state->processed = *key;
	state->processed_valid = true;
	if (key->sequence == UINT32_MAX)
		state->exhausted = true;
	else
		state->next_sequence++;
	return true;
}

static inline bool bc3_ztex_result_ack_allowed(
	const struct bc3_ztex_result_state *state,
	const struct bc3_ztex_status *status)
{
	struct bc3_ztex_result_key candidate;

	return state && state->processed_valid &&
		bc3_ztex_result_key_from_status(status, &candidate) &&
		bc3_ztex_result_key_equal(state->processed, candidate);
}

#endif
