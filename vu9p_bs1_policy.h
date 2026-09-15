/* BS1-only nonce epoch policy for the public VU9P proof of concept.
 *
 * One lane with stride one covers the 32-bit nonce space. The host rolls
 * work before wrap, allowing for the configured polling/transaction bound.
 * This header admits only the BS1 build identity and single-lane geometry.
 */
#ifndef VU9P_BS1_POLICY_H
#define VU9P_BS1_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#define VU9P_NONCE_SPACE_HASHES       (UINT64_C(1) << 32)
#define VU9P_FIXED_LANE_STRIDE        UINT32_C(1)
#define VU9P_POLL_PERIOD_MS           UINT32_C(50)
#define VU9P_ACTIVE_MASK_BS1          UINT32_C(0x000001)
#define VU9P_BUILD_ID_BC3_BS1         UINT32_C(0x5a3d0001)

enum vu9p_roll_decision {
	VU9P_ROLL_CONTINUE = 0,
	VU9P_ROLL_THRESHOLD,
	VU9P_ROLL_COUNTER_REGRESSION,
	VU9P_ROLL_COUNTER_OVERRUN,
	VU9P_ROLL_INVALID_CONFIG
};

static inline bool vu9p_active_lanes_valid(uint32_t active_lanes)
{
	return active_lanes == UINT32_C(1);
}

static inline uint32_t vu9p_active_lane_mask(uint32_t active_lanes)
{
	return active_lanes == UINT32_C(1) ? VU9P_ACTIVE_MASK_BS1 : 0;
}

static inline uint32_t vu9p_production_build_id(uint32_t active_lanes)
{
	return active_lanes == UINT32_C(1) ? VU9P_BUILD_ID_BC3_BS1 : 0;
}

static inline bool vu9p_production_identity_matches(uint32_t build_id,
		uint32_t active_lanes)
{
	return active_lanes == UINT32_C(1) &&
	       build_id == VU9P_BUILD_ID_BC3_BS1;
}

static inline uint32_t vu9p_transaction_timeout_ms(
		uint32_t max_poll_work_ms)
{
	if (max_poll_work_ms <= VU9P_POLL_PERIOD_MS)
		return 0;
	return (max_poll_work_ms - VU9P_POLL_PERIOD_MS) / UINT32_C(2);
}

/* One stride-one lane visits every uint32 nonce exactly once. */
static inline uint64_t vu9p_unique_epoch_capacity(uint32_t active_lanes)
{
	return active_lanes == UINT32_C(1) ? VU9P_NONCE_SPACE_HASHES : 0;
}

/* Return ceil(rate_hps * interval_ms / 1000), saturated at cap. */
static inline uint64_t vu9p_hashes_for_ms_capped(uint64_t rate_hps,
		uint32_t interval_ms, uint64_t cap)
{
	uint64_t whole;
	uint64_t remainder;
	uint64_t tail;

	if (rate_hps == 0 || interval_ms == 0 || cap == 0)
		return 0;
	whole = rate_hps / UINT64_C(1000);
	remainder = rate_hps % UINT64_C(1000);
	if (whole > cap / interval_ms)
		return cap;
	whole *= interval_ms;
	tail = (remainder * interval_ms + UINT64_C(999)) /
	       UINT64_C(1000);
	if (whole >= cap || tail >= cap - whole)
		return cap;
	return whole + tail;
}

static inline uint64_t vu9p_roll_limit(uint32_t active_lanes,
		uint64_t configured_rate_hps, uint64_t measured_rate_hps,
		uint32_t max_poll_work_ms)
{
	uint64_t capacity = vu9p_unique_epoch_capacity(active_lanes);
	uint64_t effective_rate = configured_rate_hps;
	uint64_t guard_hashes;

	if (capacity == 0 || configured_rate_hps == 0 ||
	    vu9p_transaction_timeout_ms(max_poll_work_ms) == 0)
		return 0;
	if (measured_rate_hps > effective_rate)
		effective_rate = measured_rate_hps;
	guard_hashes = vu9p_hashes_for_ms_capped(effective_rate,
		max_poll_work_ms, capacity);
	if (guard_hashes >= capacity)
		return 0;
	return capacity - guard_hashes;
}

static inline enum vu9p_roll_decision vu9p_classify_hash_counter(
		uint64_t previous_raw, uint64_t current_raw,
		uint32_t active_lanes, uint64_t configured_rate_hps,
		uint64_t measured_rate_hps, uint32_t max_poll_work_ms)
{
	uint64_t capacity = vu9p_unique_epoch_capacity(active_lanes);
	uint64_t limit = vu9p_roll_limit(active_lanes, configured_rate_hps,
		measured_rate_hps, max_poll_work_ms);

	if (capacity == 0 || limit == 0)
		return VU9P_ROLL_INVALID_CONFIG;
	if (current_raw > capacity)
		return VU9P_ROLL_COUNTER_OVERRUN;
	if (current_raw < previous_raw)
		return VU9P_ROLL_COUNTER_REGRESSION;
	if (current_raw >= limit)
		return VU9P_ROLL_THRESHOLD;
	return VU9P_ROLL_CONTINUE;
}

static inline uint64_t vu9p_unique_hashes_in_epoch(uint64_t raw_hashes,
		uint32_t active_lanes)
{
	uint64_t capacity = vu9p_unique_epoch_capacity(active_lanes);

	return raw_hashes > capacity ? capacity : raw_hashes;
}

static inline uint64_t vu9p_add_unique_hashes(uint64_t cumulative,
		uint64_t raw_epoch_hashes, uint32_t active_lanes)
{
	uint64_t epoch = vu9p_unique_hashes_in_epoch(raw_epoch_hashes,
		active_lanes);

	if (cumulative > UINT64_MAX - epoch)
		return UINT64_MAX;
	return cumulative + epoch;
}

#endif
