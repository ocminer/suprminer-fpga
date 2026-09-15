#ifndef BC3_ZTEX_IO_H
#define BC3_ZTEX_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bc3_ztex_protocol.h"

/* Kept distinct from libusb's small negative error range.  Positive short
 * transfers are normalized to the same -99 contract as libztex's exact-frame
 * helpers. */
#define BC3_ZTEX_IO_SELECT_ERROR (-10001)
#define BC3_ZTEX_IO_INVALID_ERROR (-10002)
#define BC3_ZTEX_IO_SHORT_ERROR (-99)

struct bc3_ztex_io_ops {
	void *opaque;
	bool (*select_lane)(void *opaque, int lane);
	int (*send_exact)(void *opaque, const uint8_t *frame, int length,
		unsigned timeout_ms);
	int (*read_exact)(void *opaque, uint8_t *frame, int length,
		unsigned timeout_ms);
};

static inline bool bc3_ztex_io_valid_length(int length)
{
	return length > 0 && length <= (int)BC3_ZTEX_STATUS_FRAME_SIZE;
}

/* The ZTEX board-wide FX2 mux is shared by all four FPGAs.  Never trust a
 * cached selectedFpga value: explicitly select immediately before every
 * physical OUT or IN request so another lane cannot inherit the transfer. */
static inline int bc3_ztex_io_send_selected(
	const struct bc3_ztex_io_ops *ops, int lane, const uint8_t *frame,
	int length, unsigned timeout_ms)
{
	int rc;

	if (!ops || !ops->select_lane || !ops->send_exact || lane < 0 ||
	    !frame || !bc3_ztex_io_valid_length(length))
		return BC3_ZTEX_IO_INVALID_ERROR;
	if (!ops->select_lane(ops->opaque, lane))
		return BC3_ZTEX_IO_SELECT_ERROR;
	rc = ops->send_exact(ops->opaque, frame, length, timeout_ms);
	if (rc < 0)
		return rc;
	return rc == length ? rc : BC3_ZTEX_IO_SHORT_ERROR;
}

static inline int bc3_ztex_io_read_selected(
	const struct bc3_ztex_io_ops *ops, int lane, uint8_t *frame,
	int length, unsigned timeout_ms)
{
	int rc;

	if (!ops || !ops->select_lane || !ops->read_exact || lane < 0 ||
	    !frame || !bc3_ztex_io_valid_length(length))
		return BC3_ZTEX_IO_INVALID_ERROR;
	if (!ops->select_lane(ops->opaque, lane))
		return BC3_ZTEX_IO_SELECT_ERROR;
	rc = ops->read_exact(ops->opaque, frame, length, timeout_ms);
	if (rc < 0)
		return rc;
	return rc == length ? rc : BC3_ZTEX_IO_SHORT_ERROR;
}

/* A failed/short fragment is ambiguous: it may already have reached the
 * decoder.  The caller retains both immutable frames and retries this whole
 * function, beginning with fragment zero.  Decoder CRC/key replay makes that
 * retry idempotent. */
static inline bool bc3_ztex_io_send_work_pair(
	const struct bc3_ztex_io_ops *ops, int lane,
	const uint8_t *frames,
	unsigned timeout_ms, unsigned *failed_fragment, int *error_code)
{
	unsigned fragment;

	if (failed_fragment)
		*failed_fragment = 0;
	if (error_code)
		*error_code = BC3_ZTEX_IO_INVALID_ERROR;
	if (!frames)
		return false;
	for (fragment = 0; fragment < 2; ++fragment) {
		int rc = bc3_ztex_io_send_selected(ops, lane,
			frames + fragment * BC3_ZTEX_WORK_FRAME_SIZE,
			(int)BC3_ZTEX_WORK_FRAME_SIZE, timeout_ms);
		if (rc != (int)BC3_ZTEX_WORK_FRAME_SIZE) {
			if (failed_fragment)
				*failed_fragment = fragment;
			if (error_code)
				*error_code = rc;
			return false;
		}
	}
	if (failed_fragment)
		*failed_fragment = 2;
	if (error_code)
		*error_code = 0;
	return true;
}

#endif
