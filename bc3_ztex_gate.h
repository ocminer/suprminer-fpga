#ifndef BC3_ZTEX_GATE_H
#define BC3_ZTEX_GATE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bc3_ztex_session.h"

#define BC3_ZTEX_SUPPORTED_BUILD_ID UINT32_C(0x00000034)

static inline bool bc3_ztex_build_id_supported(uint32_t build_id)
{
	return build_id == BC3_ZTEX_SUPPORTED_BUILD_ID;
}

static inline int bc3_ztex_hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return 10 + value - 'a';
	if (value >= 'A' && value <= 'F')
		return 10 + value - 'A';
	return -1;
}

/* Build IDs are an exact protocol allowlist, not a user-friendly number.
 * Accept precisely eight hexadecimal digits, optionally prefixed by 0x, and
 * reject zero, signs, whitespace, truncation, and trailing characters. */
static inline bool bc3_ztex_parse_build_id(const char *text,
	uint32_t *build_id)
{
	uint32_t value = 0;
	size_t offset = 0;
	size_t i;

	if (!text || !build_id)
		return false;
	if (strlen(text) == 10 && text[0] == '0' &&
	    (text[1] == 'x' || text[1] == 'X'))
		offset = 2;
	else if (strlen(text) != 8)
		return false;
	for (i = 0; i < 8; ++i) {
		int digit = bc3_ztex_hex_value(text[offset + i]);
		if (digit < 0)
			return false;
		value = (value << 4) | (uint32_t)digit;
	}
	if (value == 0)
		return false;
	*build_id = value;
	return true;
}

/* A freshly configured R34 lane has no active tuple or queued result, and
 * advertises PAUSED until its first complete work pair is committed.  Keep
 * this qualification pure so startup cannot drift from its regression test. */
static inline bool bc3_ztex_startup_status_ok(
	const struct bc3_ztex_status *status, uint32_t expected_build_id)
{
	return status &&
		bc3_ztex_status_healthy(status, expected_build_id) &&
		status->type == BC3_ZTEX_TYPE_STATUS &&
		status->flags == BC3_ZTEX_FLAG_PAUSED &&
		status->occupancy == 0 &&
		status->completed_hashes == 0 &&
		status->progress_generation == 0 &&
		status->progress_nonce == 0 &&
		status->progress_hash7 == 0;
}

/* A rollback boundary is proven only after a valid PAUSE has propagated
 * through the mining pipeline and every queued result has been ACKed.  A
 * previously latched protocol-error bit is allowed here because it is one of
 * the reasons the host enters this restricted drain path. */
static inline bool bc3_ztex_quiesced_empty_status_ok(
	const struct bc3_ztex_status *status, uint32_t expected_build_id)
{
	return status &&
		bc3_ztex_status_compatible(status, expected_build_id) &&
		(status->flags & (BC3_ZTEX_FLAG_PAUSE_LATCHED |
			BC3_ZTEX_FLAG_PAUSED |
			BC3_ZTEX_FLAG_QUIESCED)) ==
			(BC3_ZTEX_FLAG_PAUSE_LATCHED |
			 BC3_ZTEX_FLAG_PAUSED | BC3_ZTEX_FLAG_QUIESCED) &&
		!(status->flags & BC3_ZTEX_FLAG_HEAD_VALID) &&
		status->type == BC3_ZTEX_TYPE_STATUS &&
		status->occupancy == 0;
}

#endif
