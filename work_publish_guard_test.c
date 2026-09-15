#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "work_publish_guard.h"

struct fake_work {
	unsigned identity;
	uintptr_t owned_token;
	unsigned payload[4];
};

struct submit_mock {
	unsigned calls;
	unsigned pauses;
	unsigned succeed_on;
	unsigned last_failed_attempt;
	const void *last_candidate;
};

static unsigned releases;
static unsigned released_identity;

static void fake_release(void *opaque)
{
	struct fake_work *work = opaque;
	releases++;
	released_identity = work->identity;
	work->owned_token = 0;
}

static bool fake_submit(void *opaque, const void *candidate)
{
	struct submit_mock *mock = opaque;
	mock->calls++;
	mock->last_candidate = candidate;
	return mock->succeed_on != 0 && mock->calls == mock->succeed_on;
}

static void fake_pause(void *opaque, unsigned failed_attempt)
{
	struct submit_mock *mock = opaque;
	mock->pauses++;
	mock->last_failed_attempt = failed_attempt;
}

static int expect_true(const char *name, bool condition)
{
	if (!condition) {
		fprintf(stderr, "%s: failed\n", name);
		return 1;
	}
	return 0;
}

static bool all_zero(const void *data, size_t size)
{
	const unsigned char *bytes = data;
	size_t i;
	for (i = 0; i < size; ++i)
		if (bytes[i] != 0)
			return false;
	return true;
}

int main(void)
{
	struct fake_work active = { 1, 0x1111U, { 1, 2, 3, 4 } };
	struct fake_work prior = { 0 };
	struct fake_work candidate = { 9, 0x9999U, { 9, 9, 9, 9 } };
	struct submit_mock mock;
	int failures = 0;

	work_publish_move(&active, &prior, sizeof(active));
	failures += expect_true("move-prior-identity", prior.identity == 1);
	failures += expect_true("move-prior-ownership", prior.owned_token == 0x1111U);
	failures += expect_true("move-active-zero", all_zero(&active, sizeof(active)));
	active.identity = 2;
	active.owned_token = 0x2222U;
	releases = 0;
	work_publish_restore(&active, &prior, sizeof(active), fake_release);
	failures += expect_true("restore-released-candidate",
		releases == 1 && released_identity == 2);
	failures += expect_true("restore-prior-active",
		active.identity == 1 && active.owned_token == 0x1111U);
	failures += expect_true("restore-prior-zero", all_zero(&prior, sizeof(prior)));

	work_publish_move(&active, &prior, sizeof(active));
	active.identity = 3;
	active.owned_token = 0x3333U;
	releases = 0;
	work_publish_commit_prior(&prior, sizeof(prior), fake_release);
	failures += expect_true("commit-released-prior",
		releases == 1 && released_identity == 1);
	failures += expect_true("commit-kept-candidate",
		active.identity == 3 && active.owned_token == 0x3333U);
	failures += expect_true("commit-prior-zero", all_zero(&prior, sizeof(prior)));

	memset(&mock, 0, sizeof(mock));
	mock.succeed_on = 1;
	failures += expect_true("retry-first-success",
		work_publish_retry(&mock, &candidate, 3, fake_submit, fake_pause));
	failures += expect_true("retry-first-counts",
		mock.calls == 1 && mock.pauses == 0 && mock.last_candidate == &candidate);

	memset(&mock, 0, sizeof(mock));
	mock.succeed_on = 3;
	failures += expect_true("retry-third-success",
		work_publish_retry(&mock, &candidate, 3, fake_submit, fake_pause));
	failures += expect_true("retry-third-counts",
		mock.calls == 3 && mock.pauses == 2 && mock.last_failed_attempt == 2);

	memset(&mock, 0, sizeof(mock));
	failures += expect_true("retry-terminal-failure",
		!work_publish_retry(&mock, &candidate, 3, fake_submit, fake_pause));
	failures += expect_true("retry-terminal-counts",
		mock.calls == 3 && mock.pauses == 2 && mock.last_failed_attempt == 2);
	failures += expect_true("retry-zero-rejected",
		!work_publish_retry(&mock, &candidate, 0, fake_submit, fake_pause));
	failures += expect_true("retry-null-candidate-rejected",
		!work_publish_retry(&mock, NULL, 3, fake_submit, fake_pause));
	failures += expect_true("retry-null-submit-rejected",
		!work_publish_retry(&mock, &candidate, 3, NULL, fake_pause));

	if (failures)
		return 1;
	puts("WORK_PUBLISH_GUARD_TEST_PASS cases=18 retry=3 restore=1 commit=1 ownership=1");
	return 0;
}
