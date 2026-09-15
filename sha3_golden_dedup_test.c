#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "ztex_golden_dedup.h"

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static unsigned consume_snapshot(bool sha3t, const uint32_t golden[2],
	uint32_t *last1, uint32_t *last2, uint32_t emitted[2])
{
	unsigned pass;
	unsigned count = 0;

	for (pass = 0; pass < 2; pass++) {
		uint32_t candidate = ztex_golden_consume(sha3t, pass, golden,
			last1, last2);
		if (candidate != 0)
			emitted[count++] = candidate;
	}
	return count;
}

static bool consume_and_publish(bool sha3t, unsigned pass,
	const uint32_t golden[2], uint32_t *last1, uint32_t *last2,
	bool publish_succeeds, uint32_t *candidate)
{
	struct ztex_golden_checkpoint checkpoint =
		ztex_golden_checkpoint_capture(*last1, *last2);

	*candidate = ztex_golden_consume(sha3t, pass, golden, last1, last2);
	if (*candidate == 0)
		return true;
	if (publish_succeeds)
		return true;
	ztex_golden_checkpoint_restore(&checkpoint, last1, last2);
	return false;
}

int main(void)
{
	const uint32_t a = UINT32_C(0x01CF3E0B);
	const uint32_t b = UINT32_C(0x01CB497D);
	const uint32_t c = UINT32_C(0x10203040);
	const uint32_t d = UINT32_C(0x50607080);
	const uint32_t e = UINT32_C(0x90A0B0C0);
	const uint32_t q = UINT32_C(0x13579BDF);
	uint32_t last1 = 0, last2 = 0;
	uint32_t emitted[8] = {0};
	uint32_t snapshot[2];
	uint32_t candidate;
	uint32_t pair[2];
	unsigned total = 0;
	unsigned count;

	/* Zeroed history plus two latched hits: emit older B, then newer A. */
	pair[0] = a; pair[1] = b;
	count = consume_snapshot(true, pair, &last1, &last2, snapshot);
	CHECK(count == 2 && snapshot[0] == b && snapshot[1] == a);
	CHECK(last1 == a && last2 == b);
	emitted[total++] = snapshot[0]; emitted[total++] = snapshot[1];

	/* Unchanged readback emits nothing. */
	count = consume_snapshot(true, pair, &last1, &last2, snapshot);
	CHECK(count == 0 && last1 == a && last2 == b);

	/* One new hit must not cause the previous newest hit to replay. */
	pair[0] = c; pair[1] = a;
	count = consume_snapshot(true, pair, &last1, &last2, snapshot);
	CHECK(count == 1 && snapshot[0] == c);
	CHECK(last1 == c && last2 == a);
	emitted[total++] = snapshot[0];

	/* Two new hits are emitted chronologically and both remain in history. */
	pair[0] = e; pair[1] = d;
	count = consume_snapshot(true, pair, &last1, &last2, snapshot);
	CHECK(count == 2 && snapshot[0] == d && snapshot[1] == e);
	CHECK(last1 == e && last2 == d);
	emitted[total++] = snapshot[0]; emitted[total++] = snapshot[1];
	count = consume_snapshot(true, pair, &last1, &last2, snapshot);
	CHECK(count == 0 && last1 == e && last2 == d);
	CHECK(total == 5 && emitted[0] == b && emitted[1] == a &&
		emitted[2] == c && emitted[3] == d && emitted[4] == e);

	/* Empty and duplicate slots are suppressed; an invalid pass is inert. */
	last1 = 0; last2 = 0;
	pair[0] = 0; pair[1] = 0;
	CHECK(consume_snapshot(true, pair, &last1, &last2, snapshot) == 0);
	pair[0] = q; pair[1] = q;
	CHECK(consume_snapshot(true, pair, &last1, &last2, snapshot) == 1);
	CHECK(snapshot[0] == q && last1 == q && last2 == 0);
	CHECK(ztex_golden_consume(true, 2, pair, &last1, &last2) == 0);
	CHECK(last1 == q && last2 == 0);

	/* History is work-local: reset permits the same numeric nonce again. */
	last1 = 0; last2 = 0;
	pair[0] = a; pair[1] = 0;
	CHECK(consume_snapshot(true, pair, &last1, &last2, snapshot) == 1);
	CHECK(snapshot[0] == a && last1 == a && last2 == 0);

	/* Non-SHA3T behavior remains the historical slot-0 then slot-1 order. */
	last1 = 0; last2 = 0;
	pair[0] = a; pair[1] = b;
	CHECK(consume_snapshot(false, pair, &last1, &last2, snapshot) == 2);
	CHECK(snapshot[0] == a && snapshot[1] == b);
	CHECK(last1 == b && last2 == a);

	/* A failed queue publication restores history so the exact same valid
	 * nonce is available on the next hardware readback/retry. */
	last1 = a; last2 = b;
	pair[0] = c; pair[1] = a;
	CHECK(!consume_and_publish(true, 1, pair, &last1, &last2,
		false, &candidate));
	CHECK(candidate == c && last1 == a && last2 == b);
	CHECK(consume_and_publish(true, 1, pair, &last1, &last2,
		true, &candidate));
	CHECK(candidate == c && last1 == c && last2 == a);

	puts("PASS: SHA3T two-golden chronological dedup, queue rollback, and legacy ordering");
	return 0;
}
