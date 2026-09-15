#include "ztex_safe_io.h"

#include <string.h>

static void ztex_safe_attempt_init(struct ztex_safe_attempt *attempt,
		unsigned ordinal, unsigned target_lane, unsigned alternate_lane)
{
	memset(attempt, 0, sizeof(*attempt));
	attempt->ordinal = ordinal;
	attempt->target_lane = target_lane;
	attempt->alternate_lane = alternate_lane;
	attempt->terminal_stage = ZTEX_SAFE_STAGE_NONE;
	attempt->outcome = ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT;
}

static enum ztex_safe_attempt_outcome ztex_safe_select_failed(
		struct ztex_safe_attempt *attempt, enum ztex_safe_io_stage stage,
		int rc)
{
	attempt->terminal_stage = stage;
	attempt->outcome = ZTEX_SAFE_ATTEMPT_SELECT_FAILED;
	attempt->io_rc = rc;
	attempt->requested = 0;
	return attempt->outcome;
}

static enum ztex_safe_attempt_outcome ztex_safe_transfer_failed(
		struct ztex_safe_attempt *attempt, enum ztex_safe_io_stage stage,
		int rc, size_t requested)
{
	attempt->terminal_stage = stage;
	attempt->outcome = rc < 0 ? ZTEX_SAFE_ATTEMPT_IO_ERROR :
		ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER;
	attempt->io_rc = rc;
	attempt->requested = requested;
	return attempt->outcome;
}

static bool ztex_safe_deadline_expired(const struct ztex_safe_io_ops *ops,
		const struct ztex_safe_deadline *deadline)
{
	return deadline &&
		ops->monotonic_us(ops->ctx) >= deadline->absolute_us;
}

static enum ztex_safe_attempt_outcome ztex_safe_deadline_failed(
		struct ztex_safe_attempt *attempt, enum ztex_safe_io_stage stage,
		int rc, size_t requested)
{
	attempt->terminal_stage = stage;
	attempt->outcome = ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED;
	attempt->io_rc = rc;
	attempt->requested = requested;
	return attempt->outcome;
}

static enum ztex_safe_attempt_outcome ztex_safe_work80_attempt_numbered(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, const uint8_t work[ZTEX_SAFE_WORK80_SIZE],
		unsigned ordinal, struct ztex_safe_attempt *attempt)
{
	unsigned alternate_lane = target_lane;
	int rc;

	if (nlanes >= 2 && target_lane < nlanes)
		alternate_lane = target_lane == nlanes - 1 ? 0 : target_lane + 1;
	ztex_safe_attempt_init(attempt, ordinal, target_lane, alternate_lane);

	if (!ops || !ops->select_lane || !ops->write_bytes || !work ||
	    nlanes < 2 || target_lane >= nlanes)
		return attempt->outcome;

	attempt->select_calls++;
	rc = ops->select_lane(ops->ctx, alternate_lane, NULL);
	if (rc != 0)
		return ztex_safe_select_failed(attempt,
				ZTEX_SAFE_STAGE_SELECT_AWAY, rc);

	attempt->select_calls++;
	rc = ops->select_lane(ops->ctx, target_lane, NULL);
	if (rc != 0)
		return ztex_safe_select_failed(attempt,
				ZTEX_SAFE_STAGE_SELECT_TARGET, rc);

	attempt->transfer_calls++;
	rc = ops->write_bytes(ops->ctx, work, 64);
	if (rc != 64)
		return ztex_safe_transfer_failed(attempt,
				ZTEX_SAFE_STAGE_WRITE_64, rc, 64);
	attempt->exact_bytes_completed += 64;

	attempt->transfer_calls++;
	rc = ops->write_bytes(ops->ctx, work + 64, 16);
	if (rc != 16)
		return ztex_safe_transfer_failed(attempt,
				ZTEX_SAFE_STAGE_WRITE_16, rc, 16);
	attempt->exact_bytes_completed += 16;

	attempt->terminal_stage = ZTEX_SAFE_STAGE_COMPLETE;
	attempt->outcome = ZTEX_SAFE_ATTEMPT_OK;
	attempt->io_rc = rc;
	attempt->requested = 16;
	return attempt->outcome;
}

enum ztex_safe_attempt_outcome ztex_safe_work80_attempt(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, const uint8_t work[ZTEX_SAFE_WORK80_SIZE],
		struct ztex_safe_attempt *attempt)
{
	if (!attempt)
		return ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT;
	return ztex_safe_work80_attempt_numbered(ops, nlanes, target_lane,
			work, 1, attempt);
}

static enum ztex_safe_attempt_outcome ztex_safe_frame16_attempt_numbered(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, uint8_t frame[ZTEX_SAFE_FRAME16_SIZE],
		unsigned ordinal, const struct ztex_safe_deadline *deadline,
		struct ztex_safe_attempt *attempt)
{
	uint8_t scratch[ZTEX_SAFE_FRAME16_SIZE];
	int rc;

	ztex_safe_attempt_init(attempt, ordinal, target_lane, target_lane);
	if (!ops || !ops->select_lane || !ops->read_bytes || !frame ||
	    nlanes == 0 || target_lane >= nlanes ||
	    (deadline && !ops->monotonic_us))
		return attempt->outcome;

	if (ztex_safe_deadline_expired(ops, deadline))
		return ztex_safe_deadline_failed(attempt,
				ZTEX_SAFE_STAGE_SELECT_TARGET, 0, 0);

	attempt->select_calls++;
	rc = ops->select_lane(ops->ctx, target_lane, deadline);
	if (ztex_safe_deadline_expired(ops, deadline))
		return ztex_safe_deadline_failed(attempt,
				ZTEX_SAFE_STAGE_SELECT_TARGET, rc, 0);
	if (rc != 0)
		return ztex_safe_select_failed(attempt,
				ZTEX_SAFE_STAGE_SELECT_TARGET, rc);

	if (ztex_safe_deadline_expired(ops, deadline))
		return ztex_safe_deadline_failed(attempt,
				ZTEX_SAFE_STAGE_READ_16, 0, sizeof(scratch));

	attempt->transfer_calls++;
	rc = ops->read_bytes(ops->ctx, scratch, sizeof(scratch), deadline);
	if (rc == (int)sizeof(scratch))
		attempt->exact_bytes_completed += sizeof(scratch);
	if (ztex_safe_deadline_expired(ops, deadline))
		return ztex_safe_deadline_failed(attempt,
				ZTEX_SAFE_STAGE_READ_16, rc, sizeof(scratch));
	if (rc != (int)sizeof(scratch))
		return ztex_safe_transfer_failed(attempt,
				ZTEX_SAFE_STAGE_READ_16, rc, sizeof(scratch));

	memcpy(frame, scratch, sizeof(scratch));
	attempt->terminal_stage = ZTEX_SAFE_STAGE_COMPLETE;
	attempt->outcome = ZTEX_SAFE_ATTEMPT_OK;
	attempt->io_rc = rc;
	attempt->requested = sizeof(scratch);
	return attempt->outcome;
}

enum ztex_safe_attempt_outcome ztex_safe_frame16_attempt(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, uint8_t frame[ZTEX_SAFE_FRAME16_SIZE],
		struct ztex_safe_attempt *attempt)
{
	if (!attempt)
		return ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT;
	return ztex_safe_frame16_attempt_numbered(ops, nlanes, target_lane,
			frame, 1, NULL, attempt);
}

static void ztex_safe_result_init(struct ztex_safe_io_result *result,
		unsigned max_attempts)
{
	memset(result, 0, sizeof(*result));
	result->code = ZTEX_SAFE_RESULT_INVALID_ARGUMENT;
	result->max_attempts = max_attempts;
}

static void ztex_safe_result_record(struct ztex_safe_io_result *result,
		const struct ztex_safe_attempt *attempt)
{
	result->attempt[result->attempts] = *attempt;
	result->attempts++;
	result->retries = result->attempts - 1;
}

enum ztex_safe_result_code ztex_safe_work80_retry(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, const uint8_t work[ZTEX_SAFE_WORK80_SIZE],
		unsigned max_attempts, struct ztex_safe_io_result *result)
{
	struct ztex_safe_attempt attempt;
	unsigned ordinal;

	if (!result)
		return ZTEX_SAFE_RESULT_INVALID_ARGUMENT;
	ztex_safe_result_init(result, max_attempts);
	if (!ops || !ops->select_lane || !ops->write_bytes || !work ||
	    nlanes < 2 || target_lane >= nlanes ||
	    max_attempts == 0 ||
	    max_attempts > ZTEX_SAFE_WORK80_MAX_ATTEMPTS)
		return result->code;

	for (ordinal = 1; ordinal <= max_attempts; ordinal++) {
		enum ztex_safe_attempt_outcome outcome;

		outcome = ztex_safe_work80_attempt_numbered(ops, nlanes,
				target_lane, work, ordinal, &attempt);
		ztex_safe_result_record(result, &attempt);
		if (outcome == ZTEX_SAFE_ATTEMPT_OK) {
			result->code = ZTEX_SAFE_RESULT_OK;
			return result->code;
		}
	}

	result->code = ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED;
	return result->code;
}

enum ztex_safe_result_code ztex_safe_frame16_retry(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, uint8_t frame[ZTEX_SAFE_FRAME16_SIZE],
		const struct ztex_safe_frame16_policy *policy,
		struct ztex_safe_io_result *result)
{
	struct ztex_safe_attempt attempt;
	struct ztex_safe_deadline deadline_value;
	const struct ztex_safe_deadline *deadline = NULL;
	uint8_t scratch[ZTEX_SAFE_FRAME16_SIZE];
	unsigned ordinal;

	if (!result)
		return ZTEX_SAFE_RESULT_INVALID_ARGUMENT;
	ztex_safe_result_init(result, policy ? policy->max_attempts : 0);
	if (!ops || !ops->select_lane || !ops->read_bytes || !frame ||
	    !policy || nlanes == 0 || target_lane >= nlanes ||
	    policy->max_attempts == 0 ||
	    policy->max_attempts > ZTEX_SAFE_FRAME16_MAX_ATTEMPTS ||
	    (policy->has_deadline && !ops->monotonic_us) ||
	    (policy->retry_delay_us != 0 && !ops->sleep_us))
		return result->code;
	if (policy->has_deadline) {
		deadline_value.absolute_us = policy->deadline_us;
		deadline = &deadline_value;
	}

	for (ordinal = 1; ordinal <= policy->max_attempts; ordinal++) {
		enum ztex_safe_attempt_outcome outcome;

		if (policy->has_deadline &&
		    ops->monotonic_us(ops->ctx) >= policy->deadline_us) {
			result->code = ZTEX_SAFE_RESULT_DEADLINE_EXPIRED;
			return result->code;
		}

		outcome = ztex_safe_frame16_attempt_numbered(ops, nlanes,
				target_lane, scratch, ordinal, deadline, &attempt);
		ztex_safe_result_record(result, &attempt);
		if (outcome == ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED) {
			result->code = ZTEX_SAFE_RESULT_DEADLINE_EXPIRED;
			return result->code;
		}
		if (policy->has_deadline &&
		    ops->monotonic_us(ops->ctx) >= policy->deadline_us) {
			result->code = ZTEX_SAFE_RESULT_DEADLINE_EXPIRED;
			return result->code;
		}
		if (outcome == ZTEX_SAFE_ATTEMPT_OK) {
			memcpy(frame, scratch, sizeof(scratch));
			result->code = ZTEX_SAFE_RESULT_OK;
			return result->code;
		}

		if (ordinal < policy->max_attempts &&
		    policy->retry_delay_us != 0) {
			uint64_t delay = policy->retry_delay_us;

			if (policy->has_deadline) {
				uint64_t now = ops->monotonic_us(ops->ctx);
				uint64_t remaining;

				if (now >= policy->deadline_us) {
					result->code =
						ZTEX_SAFE_RESULT_DEADLINE_EXPIRED;
					return result->code;
				}
				remaining = policy->deadline_us - now;
				if (delay > remaining)
					delay = remaining;
			}
			ops->sleep_us(ops->ctx, delay);
		}
	}

	result->code = ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED;
	return result->code;
}
