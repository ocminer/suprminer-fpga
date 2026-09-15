#ifndef STRATUM_TRANSPORT_GUARD_H
#define STRATUM_TRANSPORT_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STRATUM_URL_MAX ((size_t)4096)

enum stratum_transport_phase {
	STRATUM_TRANSPORT_DISCONNECTED = 0,
	STRATUM_TRANSPORT_CONNECTING,
	STRATUM_TRANSPORT_CONNECTED_UNAUTH,
	STRATUM_TRANSPORT_AUTHENTICATED
};

struct stratum_transport_state {
	enum stratum_transport_phase phase;
	uint64_t generation;
};

static inline void stratum_transport_init(
	struct stratum_transport_state *state)
{
	if (!state)
		return;
	state->phase = STRATUM_TRANSPORT_DISCONNECTED;
	state->generation = 0;
}

static inline bool stratum_transport_begin_connect(
	struct stratum_transport_state *state, uint64_t *generation)
{
	if (!state || !generation)
		return false;
	state->generation++;
	if (state->generation == 0)
		state->generation = 1;
	state->phase = STRATUM_TRANSPORT_CONNECTING;
	*generation = state->generation;
	return true;
}

static inline bool stratum_transport_mark_connected(
	struct stratum_transport_state *state, uint64_t generation)
{
	if (!state || generation == 0 ||
	    state->phase != STRATUM_TRANSPORT_CONNECTING ||
	    state->generation != generation)
		return false;
	state->phase = STRATUM_TRANSPORT_CONNECTED_UNAUTH;
	return true;
}

static inline bool stratum_transport_mark_authenticated(
	struct stratum_transport_state *state, uint64_t generation)
{
	if (!state || generation == 0 ||
	    state->phase != STRATUM_TRANSPORT_CONNECTED_UNAUTH ||
	    state->generation != generation)
		return false;
	state->phase = STRATUM_TRANSPORT_AUTHENTICATED;
	return true;
}

static inline void stratum_transport_poison(
	struct stratum_transport_state *state)
{
	if (state)
		state->phase = STRATUM_TRANSPORT_DISCONNECTED;
}

static inline bool stratum_transport_can_control(
	const struct stratum_transport_state *state)
{
	return state &&
		(state->phase == STRATUM_TRANSPORT_CONNECTED_UNAUTH ||
		 state->phase == STRATUM_TRANSPORT_AUTHENTICATED) &&
		state->generation != 0;
}

static inline bool stratum_transport_can_share(
	const struct stratum_transport_state *state)
{
	return state && state->phase == STRATUM_TRANSPORT_AUTHENTICATED &&
		state->generation != 0;
}

static inline bool stratum_transport_job_usable(
	const struct stratum_transport_state *state, uint64_t job_generation)
{
	return stratum_transport_can_share(state) && job_generation != 0 &&
		job_generation == state->generation;
}

/* Stratum job epochs are authoritative for Stratum submissions.  Comparing a
 * candidate's prevhash with the asynchronously refreshed legacy g_work cache
 * can discard a valid result in the notify-to-publication interval, and would
 * also defeat clean=false old-job validity. */
static inline bool stratum_submission_is_stale(bool stratum_mode,
	bool share_current, bool submit_old, bool prevhash_matches)
{
	if (stratum_mode)
		return !share_current;
	return !submit_old && !prevhash_matches;
}

#endif
