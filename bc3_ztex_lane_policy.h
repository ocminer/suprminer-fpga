#ifndef BC3_ZTEX_LANE_POLICY_H
#define BC3_ZTEX_LANE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BC3_ZTEX_MAX_LANES 8u

struct bc3_ztex_lane_policy {
	uint8_t selection_mask;
	uint8_t order[BC3_ZTEX_MAX_LANES];
	uint8_t lane_count;
	uint8_t selected_count;
};

static inline bool bc3_ztex_lane_digit(char value, unsigned lane_count,
	unsigned *lane)
{
	unsigned parsed;

	if (!lane || value < '0' || value > '7')
		return false;
	parsed = (unsigned)(value - '0');
	if (parsed >= lane_count)
		return false;
	*lane = parsed;
	return true;
}

static inline bool bc3_ztex_parse_only(const char *text,
	unsigned lane_count, uint8_t *mask, uint8_t *selected_count)
{
	uint8_t parsed_mask = UINT8_C(0);
	unsigned parsed_count = 0u;
	size_t length;
	size_t index;
	bool comma_form;

	if (!mask || !selected_count || lane_count == 0u ||
	    lane_count > BC3_ZTEX_MAX_LANES)
		return false;
	if (!text) {
		unsigned all_bits = (UINT32_C(1) << lane_count) - UINT32_C(1);
		*mask = (uint8_t)all_bits;
		*selected_count = (uint8_t)lane_count;
		return true;
	}

	length = strlen(text);
	if (length == 0u)
		return false;
	comma_form = strchr(text, ',') != NULL;
	if (comma_form && (length % 2u) == 0u)
		return false;

	for (index = 0u; index < length; ++index) {
		unsigned lane;
		unsigned bit;

		if (comma_form && (index % 2u) != 0u) {
			if (text[index] != ',')
				return false;
			continue;
		}
		if (!bc3_ztex_lane_digit(text[index], lane_count, &lane))
			return false;
		bit = UINT32_C(1) << lane;
		if (((unsigned)parsed_mask & bit) != 0u)
			return false;
		parsed_mask = (uint8_t)((unsigned)parsed_mask | bit);
		parsed_count++;
	}

	if (parsed_count == 0u || parsed_count > lane_count)
		return false;
	*mask = parsed_mask;
	*selected_count = (uint8_t)parsed_count;
	return true;
}

static inline bool bc3_ztex_parse_order(const char *text,
	unsigned lane_count, uint8_t order[BC3_ZTEX_MAX_LANES])
{
	uint8_t parsed_order[BC3_ZTEX_MAX_LANES] = { UINT8_C(0) };
	uint8_t seen = UINT8_C(0);
	size_t index;

	if (!order || lane_count == 0u || lane_count > BC3_ZTEX_MAX_LANES)
		return false;
	if (!text) {
		for (index = 0u; index < (size_t)lane_count; ++index)
			parsed_order[index] = (uint8_t)index;
		memcpy(order, parsed_order, sizeof(parsed_order));
		return true;
	}
	if (strlen(text) != (size_t)lane_count)
		return false;

	for (index = 0u; index < (size_t)lane_count; ++index) {
		unsigned lane;
		unsigned bit;

		if (!bc3_ztex_lane_digit(text[index], lane_count, &lane))
			return false;
		bit = UINT32_C(1) << lane;
		if (((unsigned)seen & bit) != 0u)
			return false;
		seen = (uint8_t)((unsigned)seen | bit);
		parsed_order[index] = (uint8_t)lane;
	}

	memcpy(order, parsed_order, sizeof(parsed_order));
	return true;
}

/* Parse both environment selectors transactionally.  NULL means the safe
 * default (all lanes, natural order); a present empty or malformed value is
 * rejected.  On failure, policy is left byte-for-byte unchanged. */
static inline bool bc3_ztex_lane_policy_parse(unsigned number_of_fpgas,
	const char *fpga_only, const char *fpga_order,
	struct bc3_ztex_lane_policy *policy)
{
	struct bc3_ztex_lane_policy parsed;

	if (!policy || number_of_fpgas == 0u ||
	    number_of_fpgas > BC3_ZTEX_MAX_LANES)
		return false;
	memset(&parsed, 0, sizeof(parsed));
	parsed.lane_count = (uint8_t)number_of_fpgas;
	if (!bc3_ztex_parse_only(fpga_only, number_of_fpgas,
		&parsed.selection_mask, &parsed.selected_count) ||
	    !bc3_ztex_parse_order(fpga_order, number_of_fpgas, parsed.order))
		return false;
	*policy = parsed;
	return true;
}

#endif
