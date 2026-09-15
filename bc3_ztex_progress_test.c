#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_progress.h"

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

static struct bc3_ztex_status active_status(uint32_t generation,
	uint32_t nonce, uint32_t hash7)
{
	struct bc3_ztex_status status;

	memset(&status, 0, sizeof(status));
	status.flags = BC3_ZTEX_FLAG_ACTIVE_VALID;
	status.active_session = 7;
	status.active_epoch = 11;
	status.progress_generation = generation;
	status.progress_nonce = nonce;
	status.progress_hash7 = hash7;
	status.completed_hashes = generation;
	return status;
}

int main(void)
{
	struct bc3_ztex_progress_state state;
	struct bc3_ztex_progress_key key, altered;
	struct bc3_ztex_status status = { 0 };

	bc3_ztex_progress_init(&state);
	CHECK(!state.verified_valid);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_EMPTY);
	CHECK(!bc3_ztex_progress_allowed_for_rate(BC3_ZTEX_PROGRESS_INVALID,
		true));
	CHECK(!bc3_ztex_progress_allowed_for_rate(BC3_ZTEX_PROGRESS_EMPTY,
		true));
	CHECK(bc3_ztex_progress_allowed_for_rate(BC3_ZTEX_PROGRESS_NEW,
		false));
	CHECK(!bc3_ztex_progress_allowed_for_rate(BC3_ZTEX_PROGRESS_REPEAT,
		false));
	CHECK(bc3_ztex_progress_allowed_for_rate(BC3_ZTEX_PROGRESS_REPEAT,
		true));
	status = active_status(0, 0, 0);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_EMPTY);
	status.progress_nonce = 1;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);

	/* A nonzero first-window baseline is verified and anchored immediately;
	 * replaying that same key at an advancing display sample is not NEW. */
	status = active_status(1, 0, 0);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_NEW);
	CHECK(bc3_ztex_progress_mark_verified(&state, &status, &key));
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_REPEAT);

	/* A deliberate bad-progress mutation under the same generation fails. */
	status.progress_hash7 = 1;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	status.progress_hash7 = 0;
	status.progress_nonce = 1;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	status = active_status(2, 1, 456);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_NEW);
	altered = key;
	altered.hash7++;
	CHECK(!bc3_ztex_progress_mark_verified(&state, &status, &altered));
	CHECK(bc3_ztex_progress_mark_verified(&state, &status, &key));
	status.progress_generation = 1;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	/* A forged later generation may not replay a nonce already completed in
	 * this work tuple, even with the same correct hash word. */
	status = active_status(3, 1, 456);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	CHECK(!bc3_ztex_progress_mark_verified(&state, &status, &key));
	status = active_status(2, 1, 457);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	status = active_status(3, 2, 9);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_NEW);
	CHECK(bc3_ztex_progress_mark_verified(&state, &status, &key));
	status = active_status(4, 99, 9);
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	status = active_status(4, 3, 9);
	status.completed_hashes = 6;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);
	status.completed_hashes = 3;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);

	bc3_ztex_progress_init(&state);
	status.active_epoch = 12;
	status.progress_generation = 1;
	status.progress_nonce = 0;
	status.completed_hashes = 1;
	CHECK(bc3_ztex_progress_classify(&state, &status, &key) ==
		BC3_ZTEX_PROGRESS_NEW);
	CHECK(bc3_ztex_progress_mark_verified(&state, &status, &key));

	CHECK(!bc3_ztex_progress_mark_verified(NULL, &status, &key));
	CHECK(!bc3_ztex_progress_mark_verified(&state, NULL, &key));
	CHECK(!bc3_ztex_progress_mark_verified(&state, &status, NULL));
	CHECK(bc3_ztex_progress_classify(NULL, &status, &key) ==
		BC3_ZTEX_PROGRESS_INVALID);

	printf("BC3_ZTEX_PROGRESS_TEST_PASS checks=%u generation=explicit "
		"nonce0=valid baseline_anchor=verified replay=fail_closed "
		"mutation=fail_closed "
		"generation_nonce=exact counter_skew=bounded "
		"regression=fail_closed per_work=reset\n",
		checks);
	return EXIT_SUCCESS;
}
