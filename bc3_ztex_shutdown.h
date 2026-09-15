#ifndef BC3_ZTEX_SHUTDOWN_H
#define BC3_ZTEX_SHUTDOWN_H

#include <stdbool.h>
#include <stdint.h>

struct bc3_ztex_shutdown_state {
	bool stop_requested;
	bool failure;
	bool token_enqueued;
	bool token_consumed;
	uint64_t token_enqueued_us;
};

static inline void bc3_ztex_shutdown_init(
	struct bc3_ztex_shutdown_state *state)
{
	if (!state)
		return;
	state->stop_requested = false;
	state->failure = false;
	state->token_enqueued = false;
	state->token_consumed = false;
	state->token_enqueued_us = 0;
}

static inline bool bc3_ztex_shutdown_request(
	struct bc3_ztex_shutdown_state *state, bool failure)
{
	if (!state)
		return false;
	state->stop_requested = true;
	if (failure)
		state->failure = true;
	return true;
}

static inline bool bc3_ztex_shutdown_can_enqueue(
	const struct bc3_ztex_shutdown_state *state)
{
	return state && state->stop_requested && !state->token_enqueued &&
		!state->token_consumed;
}

static inline bool bc3_ztex_shutdown_mark_enqueued(
	struct bc3_ztex_shutdown_state *state, uint64_t now_us)
{
	if (!bc3_ztex_shutdown_can_enqueue(state) || now_us == 0)
		return false;
	state->token_enqueued = true;
	state->token_enqueued_us = now_us;
	return true;
}

static inline bool bc3_ztex_shutdown_mark_consumed(
	struct bc3_ztex_shutdown_state *state)
{
	if (!state || !state->token_enqueued || state->token_consumed ||
	    state->token_enqueued_us == 0)
		return false;
	state->token_consumed = true;
	return true;
}

static inline bool bc3_ztex_shutdown_handshake_complete(
	const struct bc3_ztex_shutdown_state *state)
{
	return state && state->token_enqueued && state->token_consumed &&
		state->token_enqueued_us != 0;
}

static inline bool bc3_ztex_shutdown_deadline_armed(
	const struct bc3_ztex_shutdown_state *state)
{
	return state && state->token_enqueued && !state->token_consumed &&
		state->token_enqueued_us != 0;
}

static inline bool bc3_ztex_shutdown_expired(
	const struct bc3_ztex_shutdown_state *state, uint64_t now_us,
	uint64_t timeout_us)
{
	if (!bc3_ztex_shutdown_deadline_armed(state))
		return false;
	if (timeout_us == 0 || now_us < state->token_enqueued_us)
		return true;
	return now_us - state->token_enqueued_us >= timeout_us;
}

static inline bool bc3_ztex_shutdown_final_success(
	const struct bc3_ztex_shutdown_state *state, int worker_result)
{
	return worker_result == 0 && state && state->stop_requested &&
		!state->failure &&
		bc3_ztex_shutdown_handshake_complete(state);
}

#endif
