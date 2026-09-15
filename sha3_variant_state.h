#ifndef SUPRMINER_SHA3_VARIANT_STATE_H
#define SUPRMINER_SHA3_VARIANT_STATE_H

#include <stdbool.h>
#include <stddef.h>

/* State is bound to both an implementation family and an exact rung ID; a
 * rounded MHz integer is not an identity (notably for the 99.692307-MHz
 * exact-18 image). The on-disk value is FAMILY/STATE_ID. */
bool sha3_variant_state_lookup(const char *path, const char *serial,
		unsigned fpga, const char *family_id, char *state_id,
		size_t state_id_size, bool *found);

/* Atomically replace the small per-lane fixed-bitstream assignment file.
 * The implementation writes and fsyncs a same-directory temporary file
 * before rename(2), so interruption cannot expose a partially rewritten
 * fleet state. */
bool sha3_variant_state_save_atomic(const char *path, const char *serial,
		unsigned fpga, const char *family_id, const char *state_id);

#endif
