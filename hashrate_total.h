#ifndef SUPRMINER_HASHRATE_TOTAL_H
#define SUPRMINER_HASHRATE_TOTAL_H

#include <stddef.h>

/* The runtime layout is:
 *   miner-count slots, four service slots, device-count board workers,
 *   and one final spare slot.
 *
 * g_miner_count already includes the FPGA boards, so a mixed C-CPU/F-board
 * process allocates C + 2*F + 5 slots.  Accepted-share reporting must sum the
 * complete allocation because the board-worker rates live after the service
 * slots rather than in [0, g_miner_count). */
static inline size_t hashrate_slot_count(size_t miner_count,
		size_t device_count)
{
	return miner_count + device_count + 5;
}

static inline size_t hashrate_device_start(size_t miner_count)
{
	return miner_count + 4;
}

static inline size_t hashrate_monitor_index(size_t miner_count,
		size_t device_count)
{
	return hashrate_device_start(miner_count) + device_count;
}

static inline double sum_hashrate_slots(const double *rates, size_t count)
{
	double total = 0.0;
	size_t i;

	if (!rates)
		return 0.0;
	for (i = 0; i < count; i++)
		total += rates[i];
	return total;
}

static inline void clear_hashrate_slot(double *rates, size_t count,
		size_t index)
{
	if (rates && index < count)
		rates[index] = 0.0;
}

static inline void clear_lane_hashrate(double *raw, double *smoothed)
{
	if (raw)
		*raw = 0.0;
	if (smoothed)
		*smoothed = 0.0;
}

/* Disabled lanes contribute zero immediately, even if they held a smoothed
 * rate before a USB/send/read failure disabled them. */
static inline double active_lane_hashrate(int enabled, double *raw,
		double *smoothed)
{
	if (!enabled) {
		clear_lane_hashrate(raw, smoothed);
		return 0.0;
	}
	return smoothed ? *smoothed : 0.0;
}

#endif
