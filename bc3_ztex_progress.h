#ifndef BC3_ZTEX_PROGRESS_H
#define BC3_ZTEX_PROGRESS_H

#include <stdbool.h>
#include <stdint.h>

#include "bc3_ztex_protocol.h"

struct bc3_ztex_progress_key {
	uint32_t session;
	uint32_t epoch;
	uint32_t generation;
	uint32_t nonce;
	uint32_t hash7;
};

struct bc3_ztex_progress_state {
	bool verified_valid;
	struct bc3_ztex_progress_key verified;
};

enum bc3_ztex_progress_disposition {
	BC3_ZTEX_PROGRESS_INVALID = 0,
	BC3_ZTEX_PROGRESS_EMPTY,
	BC3_ZTEX_PROGRESS_NEW,
	BC3_ZTEX_PROGRESS_REPEAT
};

/* A displayed SAMPLE must carry a newly CPU-verifiable diagnostic.  A
 * non-publishing BASELINE may also reuse the exact immutable diagnostic that
 * was already verified, which is required after a long no-progress gap
 * re-anchors rate accounting. */
static inline bool bc3_ztex_progress_allowed_for_rate(
	enum bc3_ztex_progress_disposition disposition, bool baseline)
{
	return disposition == BC3_ZTEX_PROGRESS_NEW ||
		(baseline && disposition == BC3_ZTEX_PROGRESS_REPEAT);
}

static inline void bc3_ztex_progress_init(
	struct bc3_ztex_progress_state *state)
{
	if (!state)
		return;
	state->verified_valid = false;
}

static inline bool bc3_ztex_progress_key_equal(
	struct bc3_ztex_progress_key a, struct bc3_ztex_progress_key b)
{
	return a.session == b.session && a.epoch == b.epoch &&
		a.generation == b.generation && a.nonce == b.nonce &&
		a.hash7 == b.hash7;
}

static inline bool bc3_ztex_progress_key_from_status(
	const struct bc3_ztex_status *status,
	struct bc3_ztex_progress_key *key)
{
	if (!status || !key ||
	    !(status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID) ||
	    status->active_session == 0 || status->active_epoch == 0 ||
	    status->progress_generation == 0)
		return false;
	key->session = status->active_session;
	key->epoch = status->active_epoch;
	key->generation = status->progress_generation;
	key->nonce = status->progress_nonce;
	key->hash7 = status->progress_hash7;
	return true;
}

/* Generation zero is an explicit, nonce-zero-safe invalid marker. Once a
 * coherent diagnostic is published, its complete tuple is immutable for that
 * generation and generations are strictly monotone within one work tuple. */
static inline enum bc3_ztex_progress_disposition
bc3_ztex_progress_classify(const struct bc3_ztex_progress_state *state,
	const struct bc3_ztex_status *status,
	struct bc3_ztex_progress_key *key)
{
	struct bc3_ztex_progress_key candidate;
	bool active;

	if (!state || !status)
		return BC3_ZTEX_PROGRESS_INVALID;
	active = (status->flags & BC3_ZTEX_FLAG_ACTIVE_VALID) != 0;
	if (!active || status->progress_generation == 0) {
		if (status->progress_generation != 0 || status->progress_nonce != 0 ||
		    status->progress_hash7 != 0)
			return BC3_ZTEX_PROGRESS_INVALID;
		return BC3_ZTEX_PROGRESS_EMPTY;
	}
	if (!bc3_ztex_progress_key_from_status(status, &candidate))
		return BC3_ZTEX_PROGRESS_INVALID;
	/* This ABI binds the fixed start-at-zero, globally ordered scheduler:
	 * generation one is nonce zero and every later generation is the next
	 * nonce. Rotation occurs before the uint32 guard can create ambiguity. */
	if (candidate.nonce != candidate.generation - UINT32_C(1) ||
	    candidate.generation > status->completed_hashes ||
	    status->completed_hashes - candidate.generation > UINT32_C(1))
		return BC3_ZTEX_PROGRESS_INVALID;
	if (key)
		*key = candidate;
	if (!state->verified_valid)
		return BC3_ZTEX_PROGRESS_NEW;
	if (candidate.session != state->verified.session ||
	    candidate.epoch != state->verified.epoch ||
	    candidate.generation < state->verified.generation)
		return BC3_ZTEX_PROGRESS_INVALID;
	if (candidate.generation == state->verified.generation)
		return bc3_ztex_progress_key_equal(candidate, state->verified) ?
			BC3_ZTEX_PROGRESS_REPEAT : BC3_ZTEX_PROGRESS_INVALID;
	/* One work tuple hashes each nonce at most once.  A later generation that
	 * republishes an already verified nonce cannot be fresh progress, even if
	 * its deterministic hash word is also replayed. */
	if (candidate.nonce == state->verified.nonce)
		return BC3_ZTEX_PROGRESS_INVALID;
	return BC3_ZTEX_PROGRESS_NEW;
}

static inline bool bc3_ztex_progress_mark_verified(
	struct bc3_ztex_progress_state *state,
	const struct bc3_ztex_status *status,
	const struct bc3_ztex_progress_key *key)
{
	struct bc3_ztex_progress_key candidate;

	if (!state || !status || !key ||
	    !bc3_ztex_progress_key_from_status(status, &candidate) ||
	    candidate.nonce != candidate.generation - UINT32_C(1) ||
	    candidate.generation > status->completed_hashes ||
	    status->completed_hashes - candidate.generation > UINT32_C(1) ||
	    !bc3_ztex_progress_key_equal(candidate, *key) ||
	    (state->verified_valid &&
	     (candidate.session != state->verified.session ||
	      candidate.epoch != state->verified.epoch ||
	      candidate.generation <= state->verified.generation ||
	      candidate.nonce == state->verified.nonce)))
		return false;
	state->verified = candidate;
	state->verified_valid = true;
	return true;
}

#endif
