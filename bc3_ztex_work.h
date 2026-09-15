#ifndef BC3_ZTEX_WORK_H
#define BC3_ZTEX_WORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bc3_ztex_protocol.h"

#define BC3_ZTEX_HEADER_PREFIX_WORDS 19u
#define BC3_ZTEX_TARGET_HIGH_WORD 7u

static inline void bc3_ztex_put_be32(uint8_t *bytes, uint32_t value)
{
	bytes[0] = (uint8_t)(value >> 24);
	bytes[1] = (uint8_t)(value >> 16);
	bytes[2] = (uint8_t)(value >> 8);
	bytes[3] = (uint8_t)value;
}

/* Produce the exact 80-byte payload consumed by the R34 RTL: the serialized
 * 76-byte header prefix followed by the numerical high target word, all in
 * big-endian byte order per 32-bit host word.  The header's nonce word is
 * deliberately absent because the FPGA enumerates it. */
static inline bool bc3_ztex_pack_work(
	uint8_t physical_work[BC3_ZTEX_WORK_SIZE],
	const uint32_t *header_words, size_t header_word_count,
	const uint32_t *target_words, size_t target_word_count)
{
	size_t word;

	if (!physical_work || !header_words || !target_words ||
	    header_word_count <= BC3_ZTEX_HEADER_PREFIX_WORDS ||
	    target_word_count <= BC3_ZTEX_TARGET_HIGH_WORD)
		return false;
	for (word = 0; word < BC3_ZTEX_HEADER_PREFIX_WORDS; ++word)
		bc3_ztex_put_be32(physical_work + 4u * word,
			header_words[word]);
	bc3_ztex_put_be32(physical_work + 76,
		target_words[BC3_ZTEX_TARGET_HIGH_WORD]);
	return true;
}

#endif
