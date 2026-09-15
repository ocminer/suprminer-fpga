#ifndef BC3_ZTEX_HEARTBEAT_POLICY_H
#define BC3_ZTEX_HEARTBEAT_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS 30u
#define BC3_ZTEX_HEARTBEAT_CANARY_SECONDS 20u
#define BC3_ZTEX_CANARY_SERIAL_MAX 10u
/* Synthetic test identity: no real device is selected by this override. */
#define BC3_ZTEX_HEARTBEAT_CANARY_SERIAL "TEST000002"
#define BC3_ZTEX_CANARY_BITSTREAM_MAX 255u

enum bc3_ztex_heartbeat_policy_result {
	BC3_ZTEX_HEARTBEAT_POLICY_OK = 0,
	BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL,
	BC3_ZTEX_HEARTBEAT_POLICY_DUPLICATE,
	BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL,
	BC3_ZTEX_HEARTBEAT_POLICY_ALGORITHM,
	BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE,
	BC3_ZTEX_HEARTBEAT_POLICY_SERIAL,
	BC3_ZTEX_HEARTBEAT_POLICY_LANE,
	BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM,
	BC3_ZTEX_HEARTBEAT_POLICY_API,
	BC3_ZTEX_HEARTBEAT_POLICY_FIRMWARE,
	BC3_ZTEX_HEARTBEAT_POLICY_AUTO_FREQUENCY,
	BC3_ZTEX_HEARTBEAT_POLICY_ZTEX_FREQUENCY,
	BC3_ZTEX_HEARTBEAT_POLICY_HASH_CLOCK
};

struct bc3_ztex_heartbeat_scope {
	bool option_seen;
	unsigned interval_seconds;
	bool algorithm_sha3t;
	bool use_ztex;
	bool use_cpu;
	bool use_serial;
	const char *serial_only;
	const char *fpga_only;
	const char *bitstream;
	int api_listen;
	bool force_firmware;
	bool auto_frequency;
	bool ztex_frequency_explicit;
	bool ztex_frequency_exact_96;
	bool hash_clock_explicit;
	bool hash_clock_exact_96;
};

/* The canary override deliberately has one canonical spelling.  Parsing every
 * byte, rather than accepting atoi()/strtoul() prefixes, rejects whitespace,
 * signs, leading zeroes, suffixes, and overflow before any hardware access. */
static inline bool bc3_ztex_heartbeat_parse_canary_seconds(
	const char *text, unsigned *seconds)
{
	unsigned parsed = 0u;
	size_t index;

	if (!text || !seconds || text[0] == '\0')
		return false;
	for (index = 0u; text[index] != '\0'; ++index) {
		unsigned digit;

		if (text[index] < '0' || text[index] > '9')
			return false;
		digit = (unsigned)(text[index] - '0');
		if (parsed > (BC3_ZTEX_HEARTBEAT_CANARY_SECONDS - digit) / 10u)
			return false;
		parsed = parsed * 10u + digit;
	}
	if (index != 2u || text[0] != '2' || text[1] != '0' ||
	    parsed != BC3_ZTEX_HEARTBEAT_CANARY_SECONDS)
		return false;
	*seconds = parsed;
	return true;
}

/* Apply the command-line option transactionally.  A second occurrence is an
 * error even if both values are 20, avoiding config/argv precedence ambiguity. */
static inline enum bc3_ztex_heartbeat_policy_result
bc3_ztex_heartbeat_option_apply(const char *text, bool *seen,
	unsigned *seconds)
{
	unsigned parsed;

	if (!seen || !seconds)
		return BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL;
	if (*seen)
		return BC3_ZTEX_HEARTBEAT_POLICY_DUPLICATE;
	if (!bc3_ztex_heartbeat_parse_canary_seconds(text, &parsed))
		return BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL;
	*seconds = parsed;
	*seen = true;
	return BC3_ZTEX_HEARTBEAT_POLICY_OK;
}

static inline bool bc3_ztex_heartbeat_serial_is_safe(const char *serial)
{
	size_t index;
	size_t length;

	if (!serial)
		return false;
	length = strlen(serial);
	if (length == 0u || length > BC3_ZTEX_CANARY_SERIAL_MAX)
		return false;
	for (index = 0u; index < length; ++index) {
		char value = serial[index];

		if (!((value >= '0' && value <= '9') ||
		      (value >= 'A' && value <= 'Z') ||
		      (value >= 'a' && value <= 'z') ||
		      value == '-' || value == '_'))
			return false;
	}
	return true;
}

static inline bool bc3_ztex_heartbeat_bitstream_is_safe(const char *name)
{
	size_t length;

	if (!name)
		return false;
	length = strlen(name);
	return length > 0u && length <= BC3_ZTEX_CANARY_BITSTREAM_MAX &&
		strchr(name, '/') == NULL && strchr(name, '\\') == NULL &&
		strstr(name, "..") == NULL;
}

/* Validate only when the 20-second canary cadence was explicitly requested.
 * With no override, the production 30-second behavior is an invariant and no
 * canary-specific runtime restriction is imposed. */
static inline enum bc3_ztex_heartbeat_policy_result
bc3_ztex_heartbeat_policy_validate(
	const struct bc3_ztex_heartbeat_scope *scope)
{
	if (!scope)
		return BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL;
	if (!scope->option_seen)
		return scope->interval_seconds ==
			BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS ?
			BC3_ZTEX_HEARTBEAT_POLICY_OK :
			BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL;
	if (scope->interval_seconds != BC3_ZTEX_HEARTBEAT_CANARY_SECONDS)
		return BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL;
	if (!scope->algorithm_sha3t)
		return BC3_ZTEX_HEARTBEAT_POLICY_ALGORITHM;
	if (!scope->use_ztex || scope->use_cpu || scope->use_serial)
		return BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE;
	if (!bc3_ztex_heartbeat_serial_is_safe(scope->serial_only) ||
	    strcmp(scope->serial_only,
		BC3_ZTEX_HEARTBEAT_CANARY_SERIAL) != 0)
		return BC3_ZTEX_HEARTBEAT_POLICY_SERIAL;
	if (!scope->fpga_only || strcmp(scope->fpga_only, "0") != 0)
		return BC3_ZTEX_HEARTBEAT_POLICY_LANE;
	if (!bc3_ztex_heartbeat_bitstream_is_safe(scope->bitstream))
		return BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM;
	if (scope->api_listen != 0)
		return BC3_ZTEX_HEARTBEAT_POLICY_API;
	if (scope->force_firmware)
		return BC3_ZTEX_HEARTBEAT_POLICY_FIRMWARE;
	if (scope->auto_frequency)
		return BC3_ZTEX_HEARTBEAT_POLICY_AUTO_FREQUENCY;
	if (!scope->ztex_frequency_explicit ||
	    !scope->ztex_frequency_exact_96)
		return BC3_ZTEX_HEARTBEAT_POLICY_ZTEX_FREQUENCY;
	if (!scope->hash_clock_explicit || !scope->hash_clock_exact_96)
		return BC3_ZTEX_HEARTBEAT_POLICY_HASH_CLOCK;
	return BC3_ZTEX_HEARTBEAT_POLICY_OK;
}

static inline const char *bc3_ztex_heartbeat_policy_result_text(
	enum bc3_ztex_heartbeat_policy_result result)
{
	switch (result) {
	case BC3_ZTEX_HEARTBEAT_POLICY_OK:
		return "valid";
	case BC3_ZTEX_HEARTBEAT_POLICY_INTERNAL:
		return "internal policy state";
	case BC3_ZTEX_HEARTBEAT_POLICY_DUPLICATE:
		return "option may appear exactly once";
	case BC3_ZTEX_HEARTBEAT_POLICY_INTERVAL:
		return "the only supported override is the exact value 20";
	case BC3_ZTEX_HEARTBEAT_POLICY_ALGORITHM:
		return "algorithm must be sha3t";
	case BC3_ZTEX_HEARTBEAT_POLICY_DEVICE_MODE:
		return "requires ZTEX-only mining";
	case BC3_ZTEX_HEARTBEAT_POLICY_SERIAL:
		return "requires ZTEX_SERIAL_ONLY=TEST000002";
	case BC3_ZTEX_HEARTBEAT_POLICY_LANE:
		return "requires FPGA_ONLY=0";
	case BC3_ZTEX_HEARTBEAT_POLICY_BITSTREAM:
		return "requires a safe bare SHA3_BITSTREAM override";
	case BC3_ZTEX_HEARTBEAT_POLICY_API:
		return "requires --api-bind 0";
	case BC3_ZTEX_HEARTBEAT_POLICY_FIRMWARE:
		return "cannot be combined with --firmware";
	case BC3_ZTEX_HEARTBEAT_POLICY_AUTO_FREQUENCY:
		return "cannot be combined with --auto-freq";
	case BC3_ZTEX_HEARTBEAT_POLICY_ZTEX_FREQUENCY:
		return "requires an explicit --ztex 96";
	case BC3_ZTEX_HEARTBEAT_POLICY_HASH_CLOCK:
		return "requires an explicit --hash-clock 96";
	default:
		return "unknown policy result";
	}
}

#endif
