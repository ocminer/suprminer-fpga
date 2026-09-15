#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct work {
	uint32_t data[48];
	uint32_t target[8];
	uint32_t block_target[8];
	int height;
	char *txs;
	char *workid;
	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
	int dev_board;
	int dev_fpga;
};

#include "work_clone_checked.h"

struct allocation_probe {
	unsigned calls;
	unsigned fail_at;
	unsigned live;
	unsigned releases;
};

static void *probe_allocate(void *opaque, size_t size)
{
	struct allocation_probe *probe = opaque;
	void *pointer;

	probe->calls++;
	if (probe->calls == probe->fail_at)
		return NULL;
	pointer = malloc(size);
	if (pointer)
		probe->live++;
	return pointer;
}

static void probe_release(void *opaque, void *pointer)
{
	struct allocation_probe *probe = opaque;

	if (pointer) {
		probe->releases++;
		probe->live--;
		free(pointer);
	}
}

static int expect_true(const char *name, bool condition)
{
	if (!condition) {
		fprintf(stderr, "%s: failed\n", name);
		return 1;
	}
	return 0;
}

static bool all_zero(const void *memory, size_t size)
{
	const unsigned char *bytes = memory;
	size_t index;

	for (index = 0; index < size; index++)
		if (bytes[index] != 0)
			return false;
	return true;
}

static void initialize_source(struct work *source)
{
	static char txs[] = "01020304";
	static char workid[] = "work-17";
	static char job_id[] = "job-23";
	static unsigned char xnonce2[] = { 0x11, 0x22, 0x33, 0x44 };

	memset(source, 0, sizeof(*source));
	source->data[0] = 0x01234567U;
	source->data[19] = 0x89abcdefU;
	source->target[7] = 0x10203040U;
	source->block_target[3] = 0x55667788U;
	source->height = 12345;
	source->txs = txs;
	source->workid = workid;
	source->job_id = job_id;
	source->xnonce2_len = sizeof(xnonce2);
	source->xnonce2 = xnonce2;
	source->dev_board = 7;
	source->dev_fpga = 3;
}

int main(void)
{
	struct work source;
	struct work destination;
	struct work snapshot;
	struct work replacement_source;
	struct work replacement_snapshot;
	struct work destination_snapshot;
	struct allocation_probe probe;
	struct work_clone_allocator allocator;
	unsigned fail_at;
	int failures = 0;

	initialize_source(&source);
	snapshot = source;
	memset(&destination, 0xa5, sizeof(destination));
	memset(&probe, 0, sizeof(probe));
	allocator.context = &probe;
	allocator.allocate = probe_allocate;
	allocator.release = probe_release;

	failures += expect_true("successful-clone",
		work_clone_checked_with(&destination, &source, &allocator));
	failures += expect_true("four-allocations", probe.calls == 4);
	failures += expect_true("four-live", probe.live == 4);
	failures += expect_true("fixed-fields",
		destination.data[0] == source.data[0] &&
		destination.data[19] == source.data[19] &&
		destination.target[7] == source.target[7] &&
		destination.block_target[3] == source.block_target[3] &&
		destination.height == source.height &&
		destination.dev_board == source.dev_board &&
		destination.dev_fpga == source.dev_fpga);
	failures += expect_true("distinct-pointers",
		destination.txs != source.txs &&
		destination.workid != source.workid &&
		destination.job_id != source.job_id &&
		destination.xnonce2 != source.xnonce2);
	failures += expect_true("equal-owned-values",
		strcmp(destination.txs, source.txs) == 0 &&
		strcmp(destination.workid, source.workid) == 0 &&
		strcmp(destination.job_id, source.job_id) == 0 &&
		destination.xnonce2_len == source.xnonce2_len &&
		memcmp(destination.xnonce2, source.xnonce2,
			source.xnonce2_len) == 0);
	destination.txs[0] ^= 1;
	destination.xnonce2[0] ^= 1;
	failures += expect_true("source-independent",
		memcmp(&source, &snapshot, sizeof(source)) == 0 &&
		source.txs[0] == '0' && source.xnonce2[0] == 0x11);
	work_clone_release_owned(&destination, &allocator);
	failures += expect_true("success-release-balanced",
		probe.live == 0 && probe.releases == 4 &&
		all_zero(&destination, sizeof(destination)));

	for (fail_at = 1; fail_at <= 4; fail_at++) {
		memset(&destination, 0xa5, sizeof(destination));
		memset(&probe, 0, sizeof(probe));
		probe.fail_at = fail_at;
		failures += expect_true("injected-failure-rejected",
			!work_clone_checked_with(&destination, &source, &allocator));
		failures += expect_true("failure-call-index",
			probe.calls == fail_at);
		failures += expect_true("failure-no-leak",
			probe.live == 0 && probe.releases == fail_at - 1);
		failures += expect_true("failure-destination-zero",
			all_zero(&destination, sizeof(destination)));
		failures += expect_true("failure-source-immutable",
			memcmp(&source, &snapshot, sizeof(source)) == 0);
	}

	memset(&destination, 0xa5, sizeof(destination));
	memset(&probe, 0, sizeof(probe));
	source.xnonce2_len = 0;
	failures += expect_true("zero-length-xnonce-canonicalized",
		work_clone_checked_with(&destination, &source, &allocator));
	failures += expect_true("zero-length-xnonce-null",
		destination.xnonce2 == NULL && destination.xnonce2_len == 0);
	failures += expect_true("zero-length-three-allocations",
		probe.live == 3 && probe.calls == 3);
	work_clone_release_owned(&destination, &allocator);
	failures += expect_true("zero-length-release-balanced",
		probe.live == 0 && probe.releases == 3);
	initialize_source(&source);

	/* Replacement is transactional: a failed clone preserves every old field
	 * and allocation; success releases the old four and installs four new
	 * private allocations. */
	memset(&destination, 0, sizeof(destination));
	memset(&probe, 0, sizeof(probe));
	failures += expect_true("replace-seed",
		work_clone_checked_with(&destination, &source, &allocator));
	destination_snapshot = destination;
	initialize_source(&replacement_source);
	replacement_source.data[0] = 0xfedcba98U;
	replacement_source.job_id = "replacement-job";
	replacement_snapshot = replacement_source;
	probe.fail_at = probe.calls + 2;
	failures += expect_true("replace-failure-rejected",
		!work_replace_checked_with(&destination, &replacement_source,
			&allocator));
	failures += expect_true("replace-failure-preserves-destination",
		memcmp(&destination, &destination_snapshot, sizeof(destination)) == 0 &&
		probe.live == 4);
	probe.fail_at = 0;
	failures += expect_true("replace-success",
		work_replace_checked_with(&destination, &replacement_source,
			&allocator));
	failures += expect_true("replace-new-fixed-fields",
		destination.data[0] == replacement_source.data[0] &&
		strcmp(destination.job_id, replacement_source.job_id) == 0 &&
		memcmp(&replacement_source, &replacement_snapshot,
			sizeof(replacement_source)) == 0);
	failures += expect_true("replace-live-balanced", probe.live == 4);
	work_clone_release_owned(&destination, &allocator);
	failures += expect_true("replace-final-release-balanced", probe.live == 0);

	memset(&probe, 0, sizeof(probe));
	failures += expect_true("alias-rejected",
		!work_clone_checked_with(&source, &source, &allocator));
	failures += expect_true("alias-not-mutated",
		memcmp(&source, &snapshot, sizeof(source)) == 0);
	failures += expect_true("null-destination-rejected",
		!work_clone_checked_with(NULL, &source, &allocator));
	failures += expect_true("null-source-rejected",
		!work_clone_checked_with(&destination, NULL, &allocator));

	if (failures)
		return 1;
	puts("WORK_CLONE_CHECKED_TEST_PASS clone_failpoints=4 zero_xnonce=canonical replace=transactional leaks=0 aliases=0");
	return 0;
}
