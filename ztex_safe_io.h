#ifndef SUPRMINER_ZTEX_SAFE_IO_H
#define SUPRMINER_ZTEX_SAFE_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZTEX_SAFE_WORK80_SIZE 80U
#define ZTEX_SAFE_FRAME16_SIZE 16U
#define ZTEX_SAFE_WORK80_MAX_ATTEMPTS 2U
#define ZTEX_SAFE_FRAME16_MAX_ATTEMPTS 5U
#define ZTEX_SAFE_MAX_ATTEMPTS ZTEX_SAFE_FRAME16_MAX_ATTEMPTS

struct ztex_safe_deadline {
	uint64_t absolute_us; /* same monotonic microsecond clock as monotonic_us */
};

/*
 * The transport is deliberately independent of libusb and miner state.  A
 * select callback succeeds only when it returns zero.  Read/write callbacks
 * succeed only when they return the exact requested byte count.
 *
 * A non-NULL deadline is an absolute monotonic budget shared by the complete
 * frame attempt.  select_lane and read_bytes must derive bounded underlying
 * I/O timeouts from the remaining budget if the caller needs a hard operation
 * duration bound.  This pure layer rejects late results but cannot cancel a
 * callback which ignores its deadline.  Synchronous libusb can request a
 * timeout from the remaining budget; strict real-time cancellation is outside
 * this interface.
 */
struct ztex_safe_io_ops {
	void *ctx;
	int (*select_lane)(void *ctx, unsigned lane,
			const struct ztex_safe_deadline *deadline);
	int (*write_bytes)(void *ctx, const uint8_t *data, size_t length);
	int (*read_bytes)(void *ctx, uint8_t *data, size_t length,
			const struct ztex_safe_deadline *deadline);
	uint64_t (*monotonic_us)(void *ctx);
	void (*sleep_us)(void *ctx, uint64_t delay_us);
};

enum ztex_safe_io_stage {
	ZTEX_SAFE_STAGE_NONE = 0,
	ZTEX_SAFE_STAGE_SELECT_AWAY,
	ZTEX_SAFE_STAGE_SELECT_TARGET,
	ZTEX_SAFE_STAGE_WRITE_64,
	ZTEX_SAFE_STAGE_WRITE_16,
	ZTEX_SAFE_STAGE_READ_16,
	ZTEX_SAFE_STAGE_COMPLETE
};

enum ztex_safe_attempt_outcome {
	ZTEX_SAFE_ATTEMPT_OK = 0,
	ZTEX_SAFE_ATTEMPT_INVALID_ARGUMENT,
	ZTEX_SAFE_ATTEMPT_SELECT_FAILED,
	ZTEX_SAFE_ATTEMPT_NONEXACT_TRANSFER,
	ZTEX_SAFE_ATTEMPT_IO_ERROR,
	ZTEX_SAFE_ATTEMPT_DEADLINE_EXPIRED
};

/* One record describes exactly one started frame attempt. */
struct ztex_safe_attempt {
	unsigned ordinal;            /* one based */
	unsigned target_lane;
	unsigned alternate_lane;     /* target_lane for frame16 reads */
	enum ztex_safe_io_stage terminal_stage;
	enum ztex_safe_attempt_outcome outcome;
	int io_rc;                   /* exact callback return value */
	size_t requested;            /* zero for selects, bytes otherwise */
	unsigned select_calls;
	unsigned transfer_calls;
	size_t exact_bytes_completed; /* sum of exact transfers before terminal */
};

enum ztex_safe_result_code {
	ZTEX_SAFE_RESULT_OK = 0,
	ZTEX_SAFE_RESULT_INVALID_ARGUMENT,
	ZTEX_SAFE_RESULT_ATTEMPTS_EXHAUSTED,
	ZTEX_SAFE_RESULT_DEADLINE_EXPIRED
};

/*
 * attempts is the number of entries populated in attempt[].  retries is
 * always attempts - 1 when attempts is nonzero, otherwise zero.  For an
 * exhausted operation, attempts equals max_attempts.
 */
struct ztex_safe_io_result {
	enum ztex_safe_result_code code;
	unsigned attempts;
	unsigned retries;
	unsigned max_attempts;
	struct ztex_safe_attempt attempt[ZTEX_SAFE_MAX_ATTEMPTS];
};

struct ztex_safe_frame16_policy {
	unsigned max_attempts;       /* accepted range: 1..5 */
	uint64_t retry_delay_us;
	bool has_deadline;
	uint64_t deadline_us;        /* absolute monotonic time */
};

/*
 * One work attempt always selects an alternate lane and then the target lane,
 * followed by one 64-byte write and one 16-byte write.  It never continues
 * after a failed select or a non-exact transfer.
 */
enum ztex_safe_attempt_outcome ztex_safe_work80_attempt(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, const uint8_t work[ZTEX_SAFE_WORK80_SIZE],
		struct ztex_safe_attempt *attempt);

/* max_attempts is accepted only in the range 1..2. */
enum ztex_safe_result_code ztex_safe_work80_retry(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, const uint8_t work[ZTEX_SAFE_WORK80_SIZE],
		unsigned max_attempts, struct ztex_safe_io_result *result);

/* One frame attempt performs one target select and exactly one 16-byte read. */
enum ztex_safe_attempt_outcome ztex_safe_frame16_attempt(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, uint8_t frame[ZTEX_SAFE_FRAME16_SIZE],
		struct ztex_safe_attempt *attempt);

/*
 * A deadline is passed unchanged to target-select/read callbacks and checked
 * before/after each callback.  An exact read which finishes at or after the
 * deadline is dropped.  retry_delay_us is applied only between failed
 * attempts.  Partial and late reads stay in private scratch storage; frame is
 * updated only after a timely exact 16-byte read.
 */
enum ztex_safe_result_code ztex_safe_frame16_retry(
		const struct ztex_safe_io_ops *ops, unsigned nlanes,
		unsigned target_lane, uint8_t frame[ZTEX_SAFE_FRAME16_SIZE],
		const struct ztex_safe_frame16_policy *policy,
		struct ztex_safe_io_result *result);

#endif
