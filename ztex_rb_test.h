#ifndef SUPRMINER_ZTEX_RB_TEST_H
#define SUPRMINER_ZTEX_RB_TEST_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define ZTEX_RB_PERIOD_US 250000ULL

enum ztex_rb_test_mode {
	ZTEX_RB_TEST_OFF = 0,
	ZTEX_RB_TEST_OBSERVE,
	ZTEX_RB_TEST_STAGGER,
	ZTEX_RB_TEST_RETRY,
	ZTEX_RB_TEST_STAGGER_RETRY
};

enum ztex_rb_cause {
	ZTEX_RB_CLEAN = 0,
	ZTEX_RB_SELECT,
	ZTEX_RB_SHORT,
	ZTEX_RB_USB_ERROR,
	ZTEX_RB_ZERO,
	ZTEX_RB_JUMP,
	ZTEX_RB_NOISE
};

enum ztex_rb_work_match {
	ZTEX_RB_MATCH_NA = 0,
	ZTEX_RB_MATCH_CURRENT,
	ZTEX_RB_MATCH_PREVIOUS,
	ZTEX_RB_MATCH_BOTH,
	ZTEX_RB_MATCH_NEITHER
};

static inline bool ztex_rb_parse_mode(const char *value,
				      enum ztex_rb_test_mode *mode)
{
	if (!mode)
		return false;
	if (!value) {
		*mode = ZTEX_RB_TEST_OFF;
		return true;
	}
	if (strcmp(value, "observe") == 0)
		*mode = ZTEX_RB_TEST_OBSERVE;
	else if (strcmp(value, "stagger") == 0)
		*mode = ZTEX_RB_TEST_STAGGER;
	else if (strcmp(value, "retry") == 0)
		*mode = ZTEX_RB_TEST_RETRY;
	else if (strcmp(value, "stagger-retry") == 0)
		*mode = ZTEX_RB_TEST_STAGGER_RETRY;
	else
		return false;
	return true;
}

static inline const char *ztex_rb_mode_name(enum ztex_rb_test_mode mode)
{
	switch (mode) {
	case ZTEX_RB_TEST_OBSERVE: return "observe";
	case ZTEX_RB_TEST_STAGGER: return "stagger";
	case ZTEX_RB_TEST_RETRY: return "retry";
	case ZTEX_RB_TEST_STAGGER_RETRY: return "stagger-retry";
	default: return "off";
	}
}

static inline bool ztex_rb_enabled(enum ztex_rb_test_mode mode)
{
	return mode != ZTEX_RB_TEST_OFF;
}

static inline bool ztex_rb_stagger_enabled(enum ztex_rb_test_mode mode)
{
	return mode == ZTEX_RB_TEST_STAGGER ||
	       mode == ZTEX_RB_TEST_STAGGER_RETRY;
}

static inline bool ztex_rb_retry_enabled(enum ztex_rb_test_mode mode)
{
	return mode == ZTEX_RB_TEST_RETRY ||
	       mode == ZTEX_RB_TEST_STAGGER_RETRY;
}

static inline uint64_t ztex_rb_board_phase_us(unsigned board_idx,
					      unsigned board_count)
{
	return board_count ? ((uint64_t)board_idx * ZTEX_RB_PERIOD_US) /
			     board_count : 0;
}

static inline uint64_t ztex_rb_lane_gap_us(unsigned board_count)
{
	uint64_t slot = board_count ? ZTEX_RB_PERIOD_US / board_count :
					 ZTEX_RB_PERIOD_US;
	uint64_t gap = slot / 5;
	return gap < 2000 ? gap : 2000;
}

static inline uint64_t ztex_rb_next_slot_us(uint64_t now_us,
					    uint64_t phase_us)
{
	uint64_t base = now_us - (now_us % ZTEX_RB_PERIOD_US);
	uint64_t target = base + (phase_us % ZTEX_RB_PERIOD_US);
	if (target < now_us)
		target += ZTEX_RB_PERIOD_US;
	return target;
}

static inline enum ztex_rb_cause ztex_rb_classify_frame(int rc,
		uint32_t nonce, uint32_t hash7, uint32_t golden1,
		uint32_t last_nonce, bool sha3t)
{
	if (rc == -99)
		return ZTEX_RB_SHORT;
	if (rc < 0)
		return ZTEX_RB_USB_ERROR;
	if (nonce == 0 && golden1 == 0 && last_nonce > 2000000U)
		return ZTEX_RB_ZERO;
	if (sha3t && nonce > last_nonce &&
	    (nonce - last_nonce) > 60000000U)
		return ZTEX_RB_JUMP;
	if (nonce == 0 || nonce == hash7)
		return ZTEX_RB_NOISE;
	return ZTEX_RB_CLEAN;
}

static inline enum ztex_rb_work_match ztex_rb_match_hash7(
		uint32_t observed, uint32_t current, bool previous_valid,
		uint32_t previous)
{
	bool cur = observed == current;
	bool prev = previous_valid && observed == previous;
	if (cur && prev)
		return ZTEX_RB_MATCH_BOTH;
	if (cur)
		return ZTEX_RB_MATCH_CURRENT;
	if (prev)
		return ZTEX_RB_MATCH_PREVIOUS;
	return ZTEX_RB_MATCH_NEITHER;
}

static inline unsigned ztex_rb_retry_delay_ms(enum ztex_rb_cause cause,
					       unsigned attempt)
{
	static const unsigned short_ms[4] = { 1, 2, 4, 8 };
	static const unsigned semantic_ms[3] = { 1, 4, 16 };
	if (cause == ZTEX_RB_SHORT)
		return short_ms[attempt < 4 ? attempt : 3];
	return semantic_ms[attempt < 3 ? attempt : 2];
}

#endif
