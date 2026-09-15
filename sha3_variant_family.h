#ifndef SUPRMINER_SHA3_VARIANT_FAMILY_H
#define SUPRMINER_SHA3_VARIANT_FAMILY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHA3_VARIANT_DIGEST_HEX_CHARS 64U
#define SHA3_VARIANT_FAMILY_MAX_RUNGS 32U

/* A final governor rung is identified by an immutable implementation, not by
 * a rounded MHz label. This matters for the 99.6923077-MHz exact-18 image and
 * for different engine counts that may share the same clock. */
struct sha3_variant_spec {
	const char *state_id;
	const char *bitfile;
	const char *sha256_hex;
	uint32_t engines;
	uint64_t clock_hz_numerator;
	uint64_t clock_hz_denominator;
	uint64_t expected_rate_hps_floor;
};

static inline bool sha3_variant_safe_token(const char *text, size_t maximum)
{
	size_t length;

	if (!text)
		return false;
	length = strlen(text);
	if (length == 0 || length > maximum)
		return false;
	for (size_t i = 0; i < length; ++i) {
		const unsigned char c = (unsigned char)text[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
			return false;
	}
	return true;
}

static inline bool sha3_variant_digest_valid(const char *digest)
{
	if (!digest || strlen(digest) != SHA3_VARIANT_DIGEST_HEX_CHARS)
		return false;
	for (size_t i = 0; i < SHA3_VARIANT_DIGEST_HEX_CHARS; ++i)
		if (!((digest[i] >= '0' && digest[i] <= '9') ||
		      (digest[i] >= 'a' && digest[i] <= 'f')))
			return false;
	return true;
}

static inline bool sha3_variant_rate_floor(const struct sha3_variant_spec *spec,
		uint64_t *rate)
{
	uint64_t numerator;
	uint64_t denominator;

	if (!spec || !rate || spec->engines == 0 ||
	    spec->clock_hz_numerator == 0 || spec->clock_hz_denominator == 0 ||
	    spec->clock_hz_numerator > UINT64_MAX / spec->engines ||
	    spec->clock_hz_denominator > UINT64_MAX / UINT64_C(72))
		return false;
	numerator = spec->clock_hz_numerator * spec->engines;
	denominator = spec->clock_hz_denominator * UINT64_C(72);
	*rate = numerator / denominator;
	return true;
}

static inline bool sha3_variant_spec_valid(const struct sha3_variant_spec *spec)
{
	uint64_t rate;
	size_t filename_length;

	if (!spec || !sha3_variant_safe_token(spec->state_id, 63) ||
	    !sha3_variant_safe_token(spec->bitfile, 255) ||
	    !sha3_variant_digest_valid(spec->sha256_hex) ||
	    spec->engines > 64 ||
	    !sha3_variant_rate_floor(spec, &rate) ||
	    rate != spec->expected_rate_hps_floor)
		return false;
	filename_length = strlen(spec->bitfile);
	return filename_length > 4 &&
		strcmp(spec->bitfile + filename_length - 4, ".bit") == 0 &&
		strstr(spec->bitfile, "..") == NULL;
}

static inline bool sha3_variant_family_valid(const char *family_id,
		const struct sha3_variant_spec *specs, size_t count,
		int default_rung)
{
	if (!sha3_variant_safe_token(family_id, 63) || !specs || count < 2 ||
	    count > SHA3_VARIANT_FAMILY_MAX_RUNGS || default_rung < 0 ||
	    (size_t)default_rung >= count)
		return false;
	for (size_t i = 0; i < count; ++i) {
		if (!sha3_variant_spec_valid(&specs[i]))
			return false;
		if (i > 0 && specs[i - 1].expected_rate_hps_floor >=
				specs[i].expected_rate_hps_floor)
			return false;
		for (size_t j = 0; j < i; ++j)
			if (strcmp(specs[i].state_id, specs[j].state_id) == 0 ||
			    strcmp(specs[i].bitfile, specs[j].bitfile) == 0)
				return false;
	}
	return true;
}

static inline double sha3_variant_clock_mhz(
		const struct sha3_variant_spec *spec)
{
	if (!spec || spec->clock_hz_denominator == 0)
		return 0.0;
	return (double)spec->clock_hz_numerator /
		(double)spec->clock_hz_denominator / 1000000.0;
}

#endif
