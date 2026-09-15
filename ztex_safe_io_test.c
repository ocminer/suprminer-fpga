#include "ztex_safe_io.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

enum fake_kind {
	FAKE_SELECT,
	FAKE_WRITE,
	FAKE_READ
};

struct fake_step {
	enum fake_kind kind;
	unsigned lane;
	size_t length;
	int rc;
	uint8_t fill;
	uint64_t advance_us;
	bool expect_deadline;
	uint64_t expected_deadline_us;
};

#define FAKE_MAX_STEPS 128U

struct fake_io {
	struct fake_step step[FAKE_MAX_STEPS];
	unsigned step_count;
	unsigned step_pos;
	const uint8_t *work;
	uint64_t now_us;
	unsigned sleep_count;
	uint64_t slept_us;
	const struct ztex_safe_deadline *observed_deadline;
	unsigned deadline_calls;
};

static void fake_reset(struct fake_io *fake, const uint8_t *work)
{
	memset(fake, 0, sizeof(*fake));
	fake->work = work;
}

static void fake_add(struct fake_io *fake, enum fake_kind kind,
		unsigned lane, size_t length, int rc, uint8_t fill)
{
	CHECK(fake->step_count < FAKE_MAX_STEPS);
	if (fake->step_count < FAKE_MAX_STEPS) {
		struct fake_step *step = &fake->step[fake->step_count++];

		step->kind = kind;
		step->lane = lane;
		step->length = length;
		step->rc = rc;
		step->fill = fill;
	}
}

static void fake_add_delay(struct fake_io *fake, enum fake_kind kind,
		unsigned lane, size_t length, int rc, uint8_t fill,
		uint64_t advance_us)
{
	unsigned previous_count = fake->step_count;

	fake_add(fake, kind, lane, length, rc, fill);
	if (fake->step_count == previous_count + 1)
		fake->step[fake->step_count - 1].advance_us = advance_us;
}

static void fake_expect_last_deadline(struct fake_io *fake,
		uint64_t absolute_us)
{
	CHECK(fake->step_count != 0);
	if (fake->step_count != 0) {
		struct fake_step *step = &fake->step[fake->step_count - 1];

		step->expect_deadline = true;
		step->expected_deadline_us = absolute_us;
	}
}

static void fake_check_deadline(struct fake_io *fake,
		const struct fake_step *step,
		const struct ztex_safe_deadline *deadline)
{
	if (!step->expect_deadline) {
		CHECK(deadline == NULL);
		return;
	}
	CHECK(deadline != NULL);
	if (!deadline)
		return;
	CHECK(deadline->absolute_us == step->expected_deadline_us);
	if (!fake->observed_deadline)
		fake->observed_deadline = deadline;
	else
		CHECK(fake->observed_deadline == deadline);
	fake->deadline_calls++;
}

static struct fake_step *fake_next(struct fake_io *fake,
		enum fake_kind kind)
{
	struct fake_step *step;

	CHECK(fake->step_pos < fake->step_count);
	if (fake->step_pos >= fake->step_count)
		return NULL;
	step = &fake->step[fake->step_pos++];
	CHECK(step->kind == kind);
	return step;
}

static int fake_select(void *ctx, unsigned lane,
		const struct ztex_safe_deadline *deadline)
{
	struct fake_io *fake = ctx;
	struct fake_step *step = fake_next(fake, FAKE_SELECT);

	if (!step)
		return -700;
	CHECK(step->lane == lane);
	fake_check_deadline(fake, step, deadline);
	fake->now_us += step->advance_us;
	return step->rc;
}

static int fake_write(void *ctx, const uint8_t *data, size_t length)
{
	struct fake_io *fake = ctx;
	struct fake_step *step = fake_next(fake, FAKE_WRITE);

	if (!step)
		return -701;
	CHECK(step->length == length);
	if (fake->work && length == 64)
		CHECK(memcmp(data, fake->work, 64) == 0);
	else if (fake->work && length == 16)
		CHECK(memcmp(data, fake->work + 64, 16) == 0);
	fake->now_us += step->advance_us;
	return step->rc;
}

static int fake_read(void *ctx, uint8_t *data, size_t length,
		const struct ztex_safe_deadline *deadline)
{
	struct fake_io *fake = ctx;
	struct fake_step *step = fake_next(fake, FAKE_READ);
	size_t copied;

	if (!step)
		return -702;
	CHECK(step->length == length);
	fake_check_deadline(fake, step, deadline);
	copied = step->rc > 0 ? (size_t)step->rc : 0;
	if (copied > length)
		copied = length;
	memset(data, step->fill, copied);
	fake->now_us += step->advance_us;
	return step->rc;
}

static uint64_t fake_monotonic(void *ctx)
{
	struct fake_io *fake = ctx;

	return fake->now_us;
}

static void fake_sleep(void *ctx, uint64_t delay_us)
{
	struct fake_io *fake = ctx;

	fake->sleep_count++;
	fake->slept_us += delay_us;
	fake->now_us += delay_us;
}

static struct ztex_safe_io_ops fake_ops(struct fake_io *fake)
{
	struct ztex_safe_io_ops ops;

	memset(&ops, 0, sizeof(ops));
	ops.ctx = fake;
	ops.select_lane = fake_select;
	ops.write_bytes = fake_write;
	ops.read_bytes = fake_read;
	ops.monotonic_us = fake_monotonic;
	ops.sleep_us = fake_sleep;
	return ops;
}

static void fake_done(const struct fake_io *fake)
{
	CHECK(fake->step_pos == fake->step_count);
}

static void check_result_consistency(const struct ztex_safe_io_result *result)
{
	unsigned i;

	CHECK(result->attempts <= ZTEX_SAFE_MAX_ATTEMPTS);
	CHECK(result->retries == (result->attempts ? result->attempts - 1 : 0));
	for (i = 0; i < result->attempts; i++)
		CHECK(result->attempt[i].ordinal == i + 1);
	if (result->code == ZTEX_SAFE_RESULT_OK) {
		CHECK(result->attempts != 0);
		CHECK(result->attempt[result->attempts - 1].outcome ==
		      ZTEX_SAFE_ATTEMPT_OK);
	}
	if (result->code == ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED) {
		CHECK(result->attempts == result->max_attempts);
		CHECK(result->attempt[result->attempts - 1].outcome !=
		      ZTEX_SAFE_ATTEMPT_OK);
	}
}

static void fill_work(uint8_t work[ZTEX_SAFE_WORK80_SIZE])
{
	unsigned i;

	for (i = 0; i < ZTEX_SAFE_WORK80_SIZE; i++)
		work[i] = (uint8_t)(i ^ 0x5aU);
}

static void test_invalid_arguments(void)
{
	uint8_t work[ZTEX_SAFE_WORK80_SIZE];
	uint8_t frame[ZTEX_SAFE_FRAME16_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_attempt attempt;
	struct ztex_safe_io_result result;
	struct ztex_safe_frame16_policy policy = { 1, 0, false, 0 };

	fill_work(work);
	fake_reset(&fake, work);
	ops = fake_ops(&fake);

	CHECK(ztex_safe_work80_attempt(&ops, 4, 1, work, NULL) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_work80_attempt(NULL, 4, 1, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_work80_attempt(&ops, 1, 0, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_work80_attempt(&ops, 4, 4, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_work80_attempt(&ops, 4, 1, NULL, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	ops.select_lane = NULL;
	CHECK(ztex_safe_work80_attempt(&ops, 4, 1, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	ops = fake_ops(&fake);
	ops.write_bytes = NULL;
	CHECK(ztex_safe_work80_attempt(&ops, 4, 1, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	ops = fake_ops(&fake);

	CHECK(ztex_safe_work80_retry(&ops, 4, 1, work, 1, NULL) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	CHECK(ztex_safe_work80_retry(NULL, 4, 1, work, 1, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_work80_retry(&ops, 1, 0, work, 1, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_work80_retry(&ops, 4, 4, work, 1, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_work80_retry(&ops, 4, 1, NULL, 1, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_work80_retry(&ops, 4, 1, work, 0, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_work80_retry(&ops, 4, 1, work, 3, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);

	CHECK(ztex_safe_frame16_attempt(&ops, 4, 1, frame, NULL) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_frame16_attempt(NULL, 4, 1, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_frame16_attempt(&ops, 0, 0, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_frame16_attempt(&ops, 4, 4, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	CHECK(ztex_safe_frame16_attempt(&ops, 4, 1, NULL, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	ops.read_bytes = NULL;
	CHECK(ztex_safe_frame16_attempt(&ops, 4, 1, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT);
	ops = fake_ops(&fake);

	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, &policy, NULL) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	CHECK(ztex_safe_frame16_retry(NULL, 4, 1, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_frame16_retry(&ops, 0, 0, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_frame16_retry(&ops, 4, 4, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, NULL, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, NULL, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	policy.max_attempts = 0;
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	policy.max_attempts = 6;
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	policy.max_attempts = 1;
	policy.has_deadline = true;
	ops.monotonic_us = NULL;
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	ops = fake_ops(&fake);
	policy.has_deadline = false;
	policy.retry_delay_us = 1;
	ops.sleep_us = NULL;
	CHECK(ztex_safe_frame16_retry(&ops, 4, 1, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_INVALID_ARGUMENT);
	check_result_consistency(&result);
	fake_done(&fake);
}

static void test_work_selects_and_success(void)
{
	uint8_t work[ZTEX_SAFE_WORK80_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_attempt attempt;

	fill_work(work);
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, 16, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_OK);
	CHECK(attempt.ordinal == 1);
	CHECK(attempt.alternate_lane == 3);
	CHECK(attempt.target_lane == 2);
	CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_COMPLETE);
	CHECK(attempt.io_rc == 16);
	CHECK(attempt.requested == 16);
	CHECK(attempt.select_calls == 2);
	CHECK(attempt.transfer_calls == 2);
	CHECK(attempt.exact_bytes_completed == 80);
	fake_done(&fake);

	/* The last lane wraps to lane zero for the mandatory away select. */
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 0, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 4, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, 16, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 4, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_OK);
	fake_done(&fake);

	/* An away-select failure forbids the target select and both writes. */
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, -9, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_SELECT_FAILED);
	CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_SELECT_AWAY);
	CHECK(attempt.io_rc == -9);
	CHECK(attempt.select_calls == 1);
	CHECK(attempt.transfer_calls == 0);
	CHECK(attempt.exact_bytes_completed == 0);
	fake_done(&fake);

	/* Any nonzero target-select return forbids both writes. */
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 1, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_SELECT_FAILED);
	CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_SELECT_TARGET);
	CHECK(attempt.io_rc == 1);
	CHECK(attempt.select_calls == 2);
	CHECK(attempt.transfer_calls == 0);
	fake_done(&fake);
}

static void test_work_transfer_boundaries(void)
{
	uint8_t work[ZTEX_SAFE_WORK80_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_attempt attempt;
	int rc;

	fill_work(work);
	for (rc = 0; rc < 64; rc++) {
		fake_reset(&fake, work);
		ops = fake_ops(&fake);
		fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
		fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
		fake_add(&fake, FAKE_WRITE, 0, 64, rc, 0);
		CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
		      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
		CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_WRITE_64);
		CHECK(attempt.io_rc == rc);
		CHECK(attempt.requested == 64);
		fake_done(&fake);
	}

	for (rc = 0; rc < 16; rc++) {
		fake_reset(&fake, work);
		ops = fake_ops(&fake);
		fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
		fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
		fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
		fake_add(&fake, FAKE_WRITE, 0, 16, rc, 0);
		CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
		      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
		CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_WRITE_16);
		CHECK(attempt.io_rc == rc);
		CHECK(attempt.requested == 16);
		fake_done(&fake);
	}

	/* Negative errors and impossible positive overcounts are non-success. */
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, -7, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_IO_ERROR);
	CHECK(attempt.io_rc == -7);
	fake_done(&fake);

	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 65, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
	fake_done(&fake);

	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, -11, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_IO_ERROR);
	CHECK(attempt.io_rc == -11);
	fake_done(&fake);

	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, 17, 0);
	CHECK(ztex_safe_work80_attempt(&ops, 5, 2, work, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
	fake_done(&fake);
}

static void test_work_retry_is_full_frame(void)
{
	uint8_t work[ZTEX_SAFE_WORK80_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_io_result result;
	unsigned i;

	fill_work(work);
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	/* Exact order: A,T,W64,W16,A,T,W64,W16. */
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, 8, 0);
	fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_WRITE, 0, 64, 64, 0);
	fake_add(&fake, FAKE_WRITE, 0, 16, 16, 0);
	CHECK(ztex_safe_work80_retry(&ops, 5, 2, work, 2, &result) ==
	      ZTEX_SAFE_RESULT_OK);
	CHECK(result.attempts == 2);
	CHECK(result.retries == 1);
	CHECK(result.attempt[0].terminal_stage == ZTEX_SAFE_STAGE_WRITE_16);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
	CHECK(result.attempt[0].select_calls == 2);
	CHECK(result.attempt[0].transfer_calls == 2);
	CHECK(result.attempt[0].exact_bytes_completed == 64);
	CHECK(result.attempt[1].terminal_stage == ZTEX_SAFE_STAGE_COMPLETE);
	CHECK(result.attempt[1].exact_bytes_completed == 80);
	check_result_consistency(&result);
	fake_done(&fake);

	/* A persistent zero-length first packet is finite: two full attempts. */
	fake_reset(&fake, work);
	ops = fake_ops(&fake);
	for (i = 0; i < 2; i++) {
		fake_add(&fake, FAKE_SELECT, 3, 0, 0, 0);
		fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
		fake_add(&fake, FAKE_WRITE, 0, 64, 0, 0);
	}
	CHECK(ztex_safe_work80_retry(&ops, 5, 2, work, 2, &result) ==
	      ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED);
	CHECK(result.attempts == 2);
	CHECK(result.retries == 1);
	for (i = 0; i < result.attempts; i++) {
		CHECK(result.attempt[i].terminal_stage ==
		      ZTEX_SAFE_STAGE_WRITE_64);
		CHECK(result.attempt[i].io_rc == 0);
	}
	check_result_consistency(&result);
	fake_done(&fake);
}

static void test_frame_attempt_boundaries(void)
{
	uint8_t frame[ZTEX_SAFE_FRAME16_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_attempt attempt;
	unsigned i;
	int rc;

	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 16, 0x3c);
	memset(frame, 0xa5, sizeof(frame));
	CHECK(ztex_safe_frame16_attempt(&ops, 5, 2, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_OK);
	for (i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0x3c);
	CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_COMPLETE);
	CHECK(attempt.select_calls == 1);
	CHECK(attempt.transfer_calls == 1);
	CHECK(attempt.exact_bytes_completed == 16);
	fake_done(&fake);

	/* A target-select failure performs no read and preserves the frame. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, -5, 0);
	memset(frame, 0xa5, sizeof(frame));
	CHECK(ztex_safe_frame16_attempt(&ops, 5, 2, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_SELECT_FAILED);
	CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_SELECT_TARGET);
	CHECK(attempt.select_calls == 1);
	CHECK(attempt.transfer_calls == 0);
	for (i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	fake_done(&fake);

	for (rc = 0; rc < 16; rc++) {
		fake_reset(&fake, NULL);
		ops = fake_ops(&fake);
		fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
		fake_add(&fake, FAKE_READ, 0, 16, rc, 0x11);
		memset(frame, 0xa5, sizeof(frame));
		CHECK(ztex_safe_frame16_attempt(&ops, 5, 2, frame, &attempt) ==
		      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
		CHECK(attempt.terminal_stage == ZTEX_SAFE_STAGE_READ_16);
		CHECK(attempt.io_rc == rc);
		CHECK(attempt.requested == 16);
		for (i = 0; i < sizeof(frame); i++)
			CHECK(frame[i] == 0xa5);
		fake_done(&fake);
	}

	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, -12, 0);
	CHECK(ztex_safe_frame16_attempt(&ops, 5, 2, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_IO_ERROR);
	fake_done(&fake);

	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 17, 0x22);
	CHECK(ztex_safe_frame16_attempt(&ops, 5, 2, frame, &attempt) ==
	      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
	fake_done(&fake);
}

static void test_frame_retry_and_cap(void)
{
	uint8_t frame[ZTEX_SAFE_FRAME16_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_io_result result;
	struct ztex_safe_frame16_policy policy = { 5, 0, false, 0 };
	unsigned i;

	/* A partial first read is discarded; retry reads one fresh full frame. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 8, 0x11);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 16, 0x22);
	memset(frame, 0xa5, sizeof(frame));
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_OK);
	CHECK(result.attempts == 2);
	CHECK(result.retries == 1);
	for (i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0x22);
	check_result_consistency(&result);
	fake_done(&fake);

	/* max_attempts=5 means exactly five attempts for persistent zero reads. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	for (i = 0; i < 5; i++) {
		fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
		fake_add(&fake, FAKE_READ, 0, 16, 0, 0);
	}
	memset(frame, 0xa5, sizeof(frame));
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED);
	CHECK(result.attempts == 5);
	CHECK(result.retries == 4);
	for (i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	check_result_consistency(&result);
	fake_done(&fake);

	/* Select errors are retried as frames and never trigger a read. */
	policy.max_attempts = 2;
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, -3, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 16, 0x44);
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_OK);
	CHECK(result.attempts == 2);
	CHECK(result.attempt[0].terminal_stage ==
	      ZTEX_SAFE_STAGE_SELECT_TARGET);
	check_result_consistency(&result);
	fake_done(&fake);
}

static void test_frame_deadline_and_sleep(void)
{
	uint8_t frame[ZTEX_SAFE_FRAME16_SIZE];
	struct fake_io fake;
	struct ztex_safe_io_ops ops;
	struct ztex_safe_io_result result;
	struct ztex_safe_frame16_policy policy;

	/* An already-expired absolute deadline starts no select or read. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 100;
	policy.max_attempts = 5;
	policy.retry_delay_us = 10;
	policy.has_deadline = true;
	policy.deadline_us = 100;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 0);
	CHECK(result.retries == 0);
	CHECK(fake.sleep_count == 0);
	check_result_consistency(&result);
	fake_done(&fake);

	/* The same typed absolute deadline reaches every select/read retry call. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 100;
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_expect_last_deadline(&fake, 200);
	fake_add(&fake, FAKE_READ, 0, 16, 0, 0);
	fake_expect_last_deadline(&fake, 200);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_expect_last_deadline(&fake, 200);
	fake_add(&fake, FAKE_READ, 0, 16, 16, 0x5a);
	fake_expect_last_deadline(&fake, 200);
	memset(frame, 0xa5, sizeof(frame));
	policy.max_attempts = 2;
	policy.retry_delay_us = 0;
	policy.has_deadline = true;
	policy.deadline_us = 200;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_OK);
	CHECK(fake.deadline_calls == 4);
	CHECK(fake.observed_deadline != NULL);
	CHECK(result.attempts == 2);
	CHECK(result.retries == 1);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER);
	CHECK(result.attempt[1].outcome == ZTEX_SAFE_ATTEMPT_OK);
	check_result_consistency(&result);
	fake_done(&fake);

	/* A successful target select returning at the deadline permits no read. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 100;
	fake_add_delay(&fake, FAKE_SELECT, 2, 0, 0, 0, 5);
	fake_expect_last_deadline(&fake, 105);
	memset(frame, 0xa5, sizeof(frame));
	policy.max_attempts = 5;
	policy.deadline_us = 105;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 1);
	CHECK(result.retries == 0);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED);
	CHECK(result.attempt[0].terminal_stage ==
	      ZTEX_SAFE_STAGE_SELECT_TARGET);
	CHECK(result.attempt[0].io_rc == 0);
	CHECK(result.attempt[0].select_calls == 1);
	CHECK(result.attempt[0].transfer_calls == 0);
	for (unsigned i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	check_result_consistency(&result);
	fake_done(&fake);

	/* A failing target select returning late is still a deadline failure. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 200;
	fake_add_delay(&fake, FAKE_SELECT, 2, 0, -7, 0, 5);
	fake_expect_last_deadline(&fake, 205);
	memset(frame, 0xa5, sizeof(frame));
	policy.deadline_us = 205;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 1);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED);
	CHECK(result.attempt[0].terminal_stage ==
	      ZTEX_SAFE_STAGE_SELECT_TARGET);
	CHECK(result.attempt[0].io_rc == -7);
	CHECK(result.attempt[0].transfer_calls == 0);
	for (unsigned i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	check_result_consistency(&result);
	fake_done(&fake);

	/* An exact in-flight read reaching the deadline is dropped, not committed. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 100;
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_expect_last_deadline(&fake, 105);
	fake_add_delay(&fake, FAKE_READ, 0, 16, 16, 0x6c, 5);
	fake_expect_last_deadline(&fake, 105);
	memset(frame, 0xa5, sizeof(frame));
	policy.max_attempts = 5;
	policy.retry_delay_us = 0;
	policy.has_deadline = true;
	policy.deadline_us = 105;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 1);
	CHECK(result.retries == 0);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED);
	CHECK(result.attempt[0].terminal_stage == ZTEX_SAFE_STAGE_READ_16);
	CHECK(result.attempt[0].io_rc == 16);
	CHECK(result.attempt[0].exact_bytes_completed == 16);
	CHECK(fake.now_us == 105);
	for (unsigned i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	check_result_consistency(&result);
	fake_done(&fake);

	/* A failed read returning at the deadline is also deadline-terminal. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 300;
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_expect_last_deadline(&fake, 305);
	fake_add_delay(&fake, FAKE_READ, 0, 16, -9, 0, 5);
	fake_expect_last_deadline(&fake, 305);
	memset(frame, 0xa5, sizeof(frame));
	policy.deadline_us = 305;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 1);
	CHECK(result.attempt[0].outcome ==
	      ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED);
	CHECK(result.attempt[0].terminal_stage == ZTEX_SAFE_STAGE_READ_16);
	CHECK(result.attempt[0].io_rc == -9);
	CHECK(result.attempt[0].exact_bytes_completed == 0);
	for (unsigned i = 0; i < sizeof(frame); i++)
		CHECK(frame[i] == 0xa5);
	check_result_consistency(&result);
	fake_done(&fake);

	/* Sleep is clipped to the deadline; no second attempt starts there. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake.now_us = 100;
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_expect_last_deadline(&fake, 105);
	fake_add(&fake, FAKE_READ, 0, 16, 0, 0);
	fake_expect_last_deadline(&fake, 105);
	policy.retry_delay_us = 10;
	policy.deadline_us = 105;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_DEADLINE_EXPIRED);
	CHECK(result.attempts == 1);
	CHECK(result.retries == 0);
	CHECK(fake.sleep_count == 1);
	CHECK(fake.slept_us == 5);
	CHECK(fake.now_us == 105);
	check_result_consistency(&result);
	fake_done(&fake);

	/* Without a deadline, injected sleep occurs only between attempts. */
	fake_reset(&fake, NULL);
	ops = fake_ops(&fake);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, -1, 0);
	fake_add(&fake, FAKE_SELECT, 2, 0, 0, 0);
	fake_add(&fake, FAKE_READ, 0, 16, 16, 0x55);
	policy.max_attempts = 2;
	policy.retry_delay_us = 7;
	policy.has_deadline = false;
	policy.deadline_us = 0;
	CHECK(ztex_safe_frame16_retry(&ops, 5, 2, frame, &policy, &result) ==
	      ZTEX_SAFE_RESULT_OK);
	CHECK(fake.sleep_count == 1);
	CHECK(fake.slept_us == 7);
	CHECK(result.attempts == 2);
	check_result_consistency(&result);
	fake_done(&fake);
}

int main(void)
{
	test_invalid_arguments();
	test_work_selects_and_success();
	test_work_transfer_boundaries();
	test_work_retry_is_full_frame();
	test_frame_attempt_boundaries();
	test_frame_retry_and_cap();
	test_frame_deadline_and_sleep();

	if (failures)
		return 1;
	puts("ZTEX safe transport tests: PASS");
	return 0;
}
