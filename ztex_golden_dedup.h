#ifndef ZTEX_GOLDEN_DEDUP_H
#define ZTEX_GOLDEN_DEDUP_H

#include <stdbool.h>
#include <stdint.h>

struct ztex_golden_checkpoint {
	uint32_t last1;
	uint32_t last2;
};

static inline struct ztex_golden_checkpoint ztex_golden_checkpoint_capture(
	uint32_t last1, uint32_t last2)
{
	struct ztex_golden_checkpoint checkpoint = { last1, last2 };

	return checkpoint;
}

static inline void ztex_golden_checkpoint_restore(
	const struct ztex_golden_checkpoint *checkpoint,
	uint32_t *last1, uint32_t *last2)
{
	*last1 = checkpoint->last1;
	*last2 = checkpoint->last2;
}

/* Consume one of the two ZTEX golden readback slots.  SHA3T exposes the
 * newest hit in slot 0 and its predecessor in slot 1, so visit it in
 * chronological order.  Other algorithms retain their historical slot order.
 * A zero return means that this pass has no new nonzero candidate. */
static inline uint32_t ztex_golden_consume(bool sha3t, unsigned pass,
	const uint32_t golden[2], uint32_t *last1, uint32_t *last2)
{
	unsigned slot;
	uint32_t candidate;

	if (pass >= 2)
		return 0;

	slot = sha3t ? (1U - pass) : pass;
	candidate = golden[slot];
	if (candidate == 0 || candidate == *last1 || candidate == *last2)
		return 0;

	*last2 = *last1;
	*last1 = candidate;
	return candidate;
}

#endif
