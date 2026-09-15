#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc3_ztex_result.h"

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

static struct bc3_ztex_status make_head(uint32_t session, uint32_t epoch,
	uint32_t sequence, uint32_t nonce, uint32_t hash7)
{
	struct bc3_ztex_status status;

	memset(&status, 0, sizeof(status));
	status.type = BC3_ZTEX_TYPE_RESULT;
	status.flags = BC3_ZTEX_FLAG_HEAD_VALID;
	status.head_session = session;
	status.head_epoch = epoch;
	status.head_sequence = sequence;
	status.head_nonce = nonce;
	status.head_hash7 = hash7;
	return status;
}

int main(void)
{
	struct bc3_ztex_result_state state;
	struct bc3_ztex_status status = { 0 };
	struct bc3_ztex_status altered_status;
	struct bc3_ztex_result_key key, altered;

	bc3_ztex_result_init(&state);
	CHECK(state.next_sequence == 1 && !state.processed_valid &&
		!state.exhausted);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status.type = BC3_ZTEX_TYPE_STATUS;
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_EMPTY);

	status = make_head(7, 1, 1, 0, 5);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_NEW);
	CHECK(key.nonce == 0 && key.hash7 == 5);
	CHECK(!bc3_ztex_result_ack_allowed(&state, &status));
	CHECK(bc3_ztex_result_mark_processed(&state, &status, &key));
	CHECK(state.next_sequence == 2);
	CHECK(bc3_ztex_result_ack_allowed(&state, &status));
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_ACK_RETRY);

	status.head_hash7 ^= 1;
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = make_head(7, 1, 3, 10, 11);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = make_head(7, 2, 2, 10, 11);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_NEW);
	altered = key;
	altered.sequence++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &altered));
	altered = key;
	altered.session++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &altered));
	altered = key;
	altered.epoch++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &altered));
	altered = key;
	altered.nonce++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &altered));
	altered = key;
	altered.hash7++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &altered));
	altered_status = status;
	altered_status.head_session++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &altered_status, &key));
	altered_status = status;
	altered_status.head_epoch++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &altered_status, &key));
	altered_status = status;
	altered_status.head_nonce++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &altered_status, &key));
	altered_status = status;
	altered_status.head_hash7++;
	CHECK(!bc3_ztex_result_mark_processed(&state, &altered_status, &key));
	CHECK(state.next_sequence == 2);
	CHECK(bc3_ztex_result_mark_processed(&state, &status, &key));
	CHECK(state.next_sequence == 3);
	CHECK(bc3_ztex_result_ack_allowed(&state, &status));
	status = make_head(7, 1, 1, 0, 5);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);

	state.next_sequence = UINT32_MAX;
	state.exhausted = false;
	status = make_head(7, 2, UINT32_MAX, UINT32_MAX, 0);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_NEW);
	CHECK(bc3_ztex_result_mark_processed(&state, &status, &key));
	CHECK(state.next_sequence == UINT32_MAX && state.exhausted);
	CHECK(bc3_ztex_result_ack_allowed(&state, &status));
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_ACK_RETRY);
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &key));

	status = make_head(7, 2, 0, 1, 0);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	CHECK(!bc3_ztex_result_ack_allowed(&state, &status));
	status = make_head(8, 2, UINT32_MAX, UINT32_MAX, 0);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = make_head(7, 3, UINT32_MAX, UINT32_MAX, 0);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = make_head(7, 2, UINT32_MAX, UINT32_MAX - 1, 0);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = make_head(7, 2, UINT32_MAX, UINT32_MAX, 1);
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	status = (struct bc3_ztex_status){ 0 };
	status.type = BC3_ZTEX_TYPE_STATUS;
	CHECK(bc3_ztex_result_classify(&state, &status, &key) ==
		BC3_ZTEX_RESULT_EMPTY);

	CHECK(!bc3_ztex_result_mark_processed(NULL, &status, &key));
	CHECK(!bc3_ztex_result_mark_processed(&state, NULL, &key));
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, NULL));
	status.flags &= (uint8_t)~BC3_ZTEX_FLAG_HEAD_VALID;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &key));
	status.flags |= BC3_ZTEX_FLAG_HEAD_VALID;
	status.type = BC3_ZTEX_TYPE_STATUS;
	CHECK(!bc3_ztex_result_mark_processed(&state, &status, &key));
	CHECK(bc3_ztex_result_classify(NULL, &status, &key) ==
		BC3_ZTEX_RESULT_INVALID);
	CHECK(!bc3_ztex_result_key_from_status(NULL, &key));

	printf("BC3_ZTEX_RESULT_TEST_PASS checks=%u nonce0=valid "
		"uncertain_ack=dedup sequence=exact wrap=fail_closed stale=fail_closed\n",
		checks);
	return EXIT_SUCCESS;
}
