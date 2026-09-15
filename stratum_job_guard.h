#ifndef STRATUM_JOB_GUARD_H
#define STRATUM_JOB_GUARD_H

#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STRATUM_JOB_ID_MAX ((size_t)256)
#define STRATUM_SESSION_ID_MAX ((size_t)256)
#define STRATUM_XNONCE1_MAX ((size_t)64)
#define STRATUM_XNONCE2_MAX ((size_t)16)
#define STRATUM_COINBASE_MAX ((size_t)1048576)
#define STRATUM_MERKLE_MAX ((size_t)64)

static inline bool stratum_hex_nibble(unsigned char c)
{
	return (c >= (unsigned char)'0' && c <= (unsigned char)'9') ||
		(c >= (unsigned char)'a' && c <= (unsigned char)'f') ||
		(c >= (unsigned char)'A' && c <= (unsigned char)'F');
}

static inline bool stratum_string_bounded(const char *text, size_t maximum,
	size_t *length)
{
	size_t i;

	if (length)
		*length = 0;
	if (!text || !length)
		return false;
	for (i = 0; i <= maximum; ++i) {
		if (text[i] == '\0') {
			*length = i;
			return true;
		}
	}
	return false;
}

static inline bool stratum_hex_exact(const char *text, size_t bytes)
{
	size_t i;

	if (!text || bytes > SIZE_MAX / 2)
		return false;
	for (i = 0; i < bytes * 2; ++i)
		if (text[i] == '\0' ||
		    !stratum_hex_nibble((unsigned char)text[i]))
			return false;
	return text[bytes * 2] == '\0';
}

static inline bool stratum_hex_bounded(const char *text, size_t maximum_bytes,
	size_t *bytes)
{
	size_t chars;
	size_t maximum_chars;

	if (bytes)
		*bytes = 0;
	if (!text || !bytes || maximum_bytes > SIZE_MAX / 2)
		return false;
	maximum_chars = maximum_bytes * 2;
	for (chars = 0; chars <= maximum_chars; ++chars) {
		if (text[chars] == '\0') {
			if ((chars & 1u) != 0)
				return false;
			*bytes = chars / 2;
			return true;
		}
		if (!stratum_hex_nibble((unsigned char)text[chars]))
			return false;
	}
	return false;
}

static inline bool stratum_coinbase_layout(size_t coinb1_size,
	size_t xnonce1_size, size_t xnonce2_size, size_t coinb2_size,
	size_t *xnonce2_offset, size_t *coinbase_size)
{
	size_t offset;
	size_t total;

	if (xnonce2_offset)
		*xnonce2_offset = 0;
	if (coinbase_size)
		*coinbase_size = 0;
	if (!xnonce2_offset || !coinbase_size ||
	    coinb1_size > STRATUM_COINBASE_MAX ||
	    xnonce1_size > STRATUM_XNONCE1_MAX ||
	    xnonce2_size > STRATUM_XNONCE2_MAX ||
	    coinb2_size > STRATUM_COINBASE_MAX ||
	    coinb1_size > STRATUM_COINBASE_MAX - xnonce1_size)
		return false;
	offset = coinb1_size + xnonce1_size;
	if (offset > STRATUM_COINBASE_MAX - xnonce2_size)
		return false;
	total = offset + xnonce2_size;
	if (total > STRATUM_COINBASE_MAX - coinb2_size)
		return false;
	total += coinb2_size;
	if (total == 0 || total > (size_t)INT_MAX)
		return false;
	*xnonce2_offset = offset;
	*coinbase_size = total;
	return true;
}

static inline bool stratum_xnonce_layout_valid(size_t coinbase_size,
	size_t xnonce2_offset, size_t xnonce2_size)
{
	return coinbase_size != 0 && coinbase_size <= STRATUM_COINBASE_MAX &&
		coinbase_size <= (size_t)INT_MAX &&
		xnonce2_offset <= coinbase_size &&
		xnonce2_size <= coinbase_size - xnonce2_offset;
}

static inline uint32_t stratum_coinbase_height(const uint8_t *coinbase,
	size_t coinbase_size)
{
	size_t i;
	size_t run_start;
	size_t search_end;
	uint8_t height_length;
	uint32_t height = 0;
	unsigned byte;

	if (!coinbase)
		return 0;
	/* Preserve the deployed Decred-first heuristic. */
	if (coinbase_size >= 144) {
		height = (uint32_t)coinbase[92] |
			((uint32_t)coinbase[93] << 8) |
			((uint32_t)coinbase[94] << 16) |
			((uint32_t)coinbase[95] << 24);
		if (height > 0 && height < UINT32_C(100000000))
			return height;
	}
	if (coinbase_size <= 32)
		return 0;
	search_end = coinbase_size < 160 ? coinbase_size : 160;
	for (i = 32; i < search_end && coinbase[i] != UINT8_C(0xff); ++i)
		;
	run_start = i;
	while (i < search_end && coinbase[i] == UINT8_C(0xff))
		++i;
	if (i - run_start < 2 || i >= coinbase_size)
		return 0;
	/* The legacy layout skips one byte between the ff tag and BIP34 length. */
	++i;
	if (i >= coinbase_size)
		return 0;
	height_length = coinbase[i++];
	if (height_length == 0 || height_length > 4 ||
	    (size_t)height_length > coinbase_size - i)
		return 0;
	for (byte = 0; byte < height_length; ++byte)
		height |= (uint32_t)coinbase[i + byte] << (8u * byte);
	return height;
}

static inline bool stratum_diff_to_target(uint32_t *target, double difficulty)
{
	long double quotient;
	uint64_t mantissa;
	int word;

	if (!target)
		return false;
	for (word = 0; word < 8; ++word)
		target[word] = 0;
	if (!isfinite(difficulty) || difficulty <= 0.0)
		return false;
	for (word = 6; word > 0 && difficulty > 1.0; --word)
		difficulty /= 4294967296.0;
	if (!isfinite(difficulty) || difficulty <= 0.0)
		return false;
	quotient = 4294901760.0L / (long double)difficulty;
	if (quotient >= (long double)UINT64_MAX) {
		for (word = 0; word < 8; ++word)
			target[word] = UINT32_MAX;
		return true;
	}
	if (quotient < 1.0L)
		return true;
	mantissa = (uint64_t)quotient;
	target[word] = (uint32_t)mantissa;
	target[word + 1] = (uint32_t)(mantissa >> 32);
	return true;
}

#endif
