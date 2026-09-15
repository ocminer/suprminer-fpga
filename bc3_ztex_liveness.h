#ifndef BC3_ZTEX_LIVENESS_H
#define BC3_ZTEX_LIVENESS_H

#include <stdbool.h>
#include <stdint.h>

static inline bool bc3_ztex_elapsed_reached(uint64_t started_us,
	uint64_t now_us, uint64_t timeout_us)
{
	return timeout_us == 0 || started_us == 0 || now_us < started_us ||
		now_us - started_us >= timeout_us;
}

static inline bool bc3_ztex_first_work_timed_out(bool drain_requested,
	bool want_new_work, bool active_work_valid, bool pending_work_valid,
	uint64_t wait_started_us, uint64_t now_us, uint64_t timeout_us)
{
	return !drain_requested && want_new_work && !active_work_valid &&
		!pending_work_valid && bc3_ztex_elapsed_reached(wait_started_us,
			now_us, timeout_us);
}

static inline bool bc3_ztex_hash_progress_timed_out(bool drain_requested,
	bool active_work_valid, bool pending_work_valid, bool ack_pending,
	bool publish_blocked, bool fifo_full, uint64_t last_progress_us,
	uint64_t now_us, uint64_t timeout_us)
{
	return !drain_requested && active_work_valid && !pending_work_valid &&
		!ack_pending && !publish_blocked && !fifo_full &&
		bc3_ztex_elapsed_reached(last_progress_us, now_us, timeout_us);
}

#endif
