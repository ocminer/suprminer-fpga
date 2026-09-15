#ifndef SUPRMINER_WORK_CLONE_CHECKED_H
#define SUPRMINER_WORK_CLONE_CHECKED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * This header expects struct work to have been defined by miner.h.
 * Destination storage must be fresh or have had all owned fields released.
 * On failure it is left fully zeroed and owns nothing.
 */
typedef void *(*work_clone_alloc_fn)(void *context, size_t size);
typedef void (*work_clone_free_fn)(void *context, void *pointer);

struct work_clone_allocator {
	void *context;
	work_clone_alloc_fn allocate;
	work_clone_free_fn release;
};

static inline void work_clone_release_owned(struct work *work,
		const struct work_clone_allocator *allocator)
{
	if (work->txs)
		allocator->release(allocator->context, work->txs);
	if (work->workid)
		allocator->release(allocator->context, work->workid);
	if (work->job_id)
		allocator->release(allocator->context, work->job_id);
	if (work->xnonce2)
		allocator->release(allocator->context, work->xnonce2);
	memset(work, 0, sizeof(*work));
}

static inline bool work_clone_string(char **destination, const char *source,
		const struct work_clone_allocator *allocator)
{
	size_t size;
	char *copy;

	if (!source)
		return true;
	size = strlen(source);
	if (size == SIZE_MAX)
		return false;
	size++;
	copy = allocator->allocate(allocator->context, size);
	if (!copy)
		return false;
	memcpy(copy, source, size);
	*destination = copy;
	return true;
}

static inline bool work_clone_checked_with(struct work *destination,
		const struct work *source,
		const struct work_clone_allocator *allocator)
{
	struct work temporary;

	if (!destination || !source || destination == source || !allocator ||
	    !allocator->allocate || !allocator->release)
		return false;

	temporary = *source;
	temporary.txs = NULL;
	temporary.workid = NULL;
	temporary.job_id = NULL;
	temporary.xnonce2 = NULL;

	if (!work_clone_string(&temporary.txs, source->txs, allocator) ||
	    !work_clone_string(&temporary.workid, source->workid, allocator) ||
	    !work_clone_string(&temporary.job_id, source->job_id, allocator))
		goto fail;

    /* A nonzero length requires storage.  Several upstream parsers legally
     * retain an allocation for a zero-length extranonce; canonicalize that
     * representation to NULL/zero in the private clone. */
    if (source->xnonce2_len != 0 && !source->xnonce2)
        goto fail;
    if (source->xnonce2_len != 0) {
        temporary.xnonce2 = allocator->allocate(allocator->context,
            source->xnonce2_len);
		if (!temporary.xnonce2)
			goto fail;
		memcpy(temporary.xnonce2, source->xnonce2, source->xnonce2_len);
	}

	*destination = temporary;
	return true;

fail:
	work_clone_release_owned(&temporary, allocator);
	memset(destination, 0, sizeof(*destination));
	return false;
}

/* Clone first, then release/replace the destination.  Allocation failure
 * leaves the previously owned destination byte-for-byte untouched. */
static inline bool work_replace_checked_with(struct work *destination,
        const struct work *source,
        const struct work_clone_allocator *allocator)
{
    struct work replacement;

    if (!destination || !source || !allocator || !allocator->allocate ||
        !allocator->release)
        return false;
    if (destination == source)
        return true;
    memset(&replacement, 0, sizeof(replacement));
    if (!work_clone_checked_with(&replacement, source, allocator))
        return false;
    work_clone_release_owned(destination, allocator);
    *destination = replacement;
    return true;
}

static inline void *work_clone_system_allocate(void *context, size_t size)
{
	(void)context;
	return malloc(size);
}

static inline void work_clone_system_release(void *context, void *pointer)
{
	(void)context;
	free(pointer);
}

static inline bool work_clone_checked(struct work *destination,
		const struct work *source)
{
	const struct work_clone_allocator allocator = {
		NULL, work_clone_system_allocate, work_clone_system_release
	};

	return work_clone_checked_with(destination, source, &allocator);
}

static inline bool work_replace_checked(struct work *destination,
        const struct work *source)
{
    const struct work_clone_allocator allocator = {
        NULL, work_clone_system_allocate, work_clone_system_release
    };

    return work_replace_checked_with(destination, source, &allocator);
}

#endif
