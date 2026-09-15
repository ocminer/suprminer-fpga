#ifndef SUPRMINER_SHA3_VARIANT_LADDER_H
#define SUPRMINER_SHA3_VARIANT_LADDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A SHA3T frequency rung is a separately implemented fixed-clock bitstream.
 * These helpers contain no USB or filesystem operations so the governor's
 * fail-safe selection policy can be exhaustively tested on the host. */
#define SHA3_VARIANT_MIN_WINDOW_CHECKS 20U
#define SHA3_VARIANT_CLEAN_WINDOWS_FOR_PROBE 5U

enum sha3_variant_window_action {
	SHA3_VARIANT_HOLD = 0,
	SHA3_VARIANT_STEP_DOWN,
	SHA3_VARIANT_PROBE_UP
};

enum sha3_variant_activation {
	SHA3_VARIANT_DISABLED = 0,
	SHA3_VARIANT_READY,
	SHA3_VARIANT_REJECT_OVERRIDE,
	SHA3_VARIANT_REJECT_INSUFFICIENT_IMAGES
};

/* SHA3T fixed-image tuning is explicit. An exact candidate override and a
 * governor are mutually exclusive, and auto mode may never fall through to
 * the legacy programmable-clock controls when its image set is incomplete. */
static inline enum sha3_variant_activation sha3_variant_activation_decide(
		bool auto_frequency, bool explicit_override,
		size_t available_images)
{
	if (!auto_frequency)
		return SHA3_VARIANT_DISABLED;
	if (explicit_override)
		return SHA3_VARIANT_REJECT_OVERRIDE;
	if (available_images < 2)
		return SHA3_VARIANT_REJECT_INSUFFICIENT_IMAGES;
	return SHA3_VARIANT_READY;
}

/* Variant mode stores the actual fixed clock in ztex_stats.freq. Legacy
 * programmable-clock mode stores the historical M index (MHz=4*(M+1)). */
static inline unsigned sha3_variant_display_mhz(bool variant_mode,
		int stored_frequency)
{
	if (stored_frequency < 0)
		return 0;
	return variant_mode ? (unsigned)stored_frequency :
		(unsigned)(stored_frequency + 1) * 4U;
}

static inline bool sha3_variant_rung_is_tainted(uint32_t mask,
		size_t count, int rung)
{
	return count <= 32 && rung >= 0 && (size_t)rung < count &&
		(mask & (UINT32_C(1) << (unsigned)rung)) != 0;
}

static inline bool sha3_variant_taint_rung(uint32_t *mask,
		size_t count, int rung)
{
	if (!mask || count > 32 || rung < 0 || (size_t)rung >= count)
		return false;
	*mask |= UINT32_C(1) << (unsigned)rung;
	return true;
}

/* Prefer the requested rung, otherwise the nearest available slower rung.
 * A faster rung is used only when no slower/equal image exists. */
static inline int sha3_variant_initial_rung(const bool *available,
		size_t count, int preferred)
{
	int rung;

	if (!available || count == 0 || preferred < 0 ||
	    (size_t)preferred >= count)
		return -1;
	for (rung = preferred; rung >= 0; --rung)
		if (available[rung])
			return rung;
	for (rung = preferred + 1; (size_t)rung < count; ++rung)
		if (available[rung])
			return rung;
	return -1;
}

static inline int sha3_variant_next_slower(const bool *available,
		size_t count, int current)
{
	int rung;

	if (!available || count == 0 || current <= 0 ||
	    (size_t)current >= count)
		return -1;
	for (rung = current - 1; rung >= 0; --rung)
		if (available[rung])
			return rung;
	return -1;
}

static inline int sha3_variant_next_faster(const bool *available,
		size_t count, int current)
{
	int rung;

	if (!available || count == 0 || current < 0 ||
	    (size_t)current >= count)
		return -1;
	for (rung = current + 1; (size_t)rung < count; ++rung)
		if (available[rung])
			return rung;
	return -1;
}

/* CPU-verified SHA3T mismatches are never an acceptable operating point: one
 * observed mismatch requests an immediate slower image, even in a short
 * window.  A faster image is probed only after five consecutive
 * sufficiently sampled zero-error windows and is not retried after it has
 * already produced a mismatch during this process lifetime. */
static inline enum sha3_variant_window_action sha3_variant_window_decide(
		unsigned checks, unsigned errors, bool faster_available,
		bool faster_tainted, unsigned *clean_windows)
{
	if (!clean_windows)
		return SHA3_VARIANT_HOLD;
	if (errors > 0) {
		*clean_windows = 0;
		return SHA3_VARIANT_STEP_DOWN;
	}
	if (checks < SHA3_VARIANT_MIN_WINDOW_CHECKS) {
		*clean_windows = 0;
		return SHA3_VARIANT_HOLD;
	}
	if (!faster_available || faster_tainted) {
		*clean_windows = 0;
		return SHA3_VARIANT_HOLD;
	}
	if (*clean_windows < SHA3_VARIANT_CLEAN_WINDOWS_FOR_PROBE)
		(*clean_windows)++;
	if (*clean_windows >= SHA3_VARIANT_CLEAN_WINDOWS_FOR_PROBE) {
		*clean_windows = 0;
		return SHA3_VARIANT_PROBE_UP;
	}
	return SHA3_VARIANT_HOLD;
}

#endif
