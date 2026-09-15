#ifndef SUPRMINER_WORK_PUBLISH_GUARD_H
#define SUPRMINER_WORK_PUBLISH_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef void (*work_publish_release_fn)(void *work);
typedef bool (*work_publish_submit_fn)(void *context,
		const void *candidate);
typedef void (*work_publish_pause_fn)(void *context,
		unsigned failed_attempt);

/* Move the dynamically owned active record aside without freeing it.  The
 * zeroed active slot can then receive a candidate from code that normally
 * frees/reallocates its input fields. */
static inline void work_publish_move(void *active, void *prior, size_t size)
{
	memcpy(prior, active, size);
	memset(active, 0, size);
}

/* Abandon an unpublished candidate and move the prior hardware-visible record
 * back into the active slot.  Zeroing prior prevents accidental double free. */
static inline void work_publish_restore(void *active, void *prior, size_t size,
		work_publish_release_fn release)
{
	release(active);
	memcpy(active, prior, size);
	memset(prior, 0, size);
}

/* Hardware publication succeeded (or the lane was disabled after a terminal
 * send failure), so only the old record remains to be released. */
static inline void work_publish_commit_prior(void *prior, size_t size,
		work_publish_release_fn release)
{
	release(prior);
	memset(prior, 0, size);
}

static inline bool work_publish_retry(void *context, const void *candidate,
		unsigned attempts, work_publish_submit_fn submit,
		work_publish_pause_fn pause)
{
	unsigned attempt;

	if (!candidate || attempts == 0 || !submit)
		return false;
	for (attempt = 1; attempt <= attempts; ++attempt) {
		if (submit(context, candidate))
			return true;
		if (attempt != attempts && pause)
			pause(context, attempt);
	}
	return false;
}

#endif
