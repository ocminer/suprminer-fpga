#ifndef BC3_ZTEX_PROTOCOL_H
#define BC3_ZTEX_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BC3_ZTEX_ABI_ID UINT32_C(0x42334332)
#define BC3_ZTEX_PROTOCOL_VERSION UINT8_C(2)
#define BC3_ZTEX_WORK_FRAME_SIZE 64u
#define BC3_ZTEX_ACK_FRAME_SIZE 36u
#define BC3_ZTEX_PAUSE_FRAME_SIZE 32u
#define BC3_ZTEX_STATUS_FRAME_SIZE 64u
#define BC3_ZTEX_WORK_SIZE 80u
#define BC3_ZTEX_FIFO_DEPTH 8u

#define BC3_ZTEX_FLAG_HEAD_VALID UINT8_C(0x01)
#define BC3_ZTEX_FLAG_FIFO_FULL UINT8_C(0x02)
#define BC3_ZTEX_FLAG_ACTIVE_VALID UINT8_C(0x04)
#define BC3_ZTEX_FLAG_PROTOCOL_ERROR UINT8_C(0x08)
#define BC3_ZTEX_FLAG_PAUSED UINT8_C(0x10)
#define BC3_ZTEX_FLAG_QUIESCED UINT8_C(0x20)
#define BC3_ZTEX_FLAG_PAUSE_LATCHED UINT8_C(0x40)
#define BC3_ZTEX_FLAG_ROTATION_REQUIRED UINT8_C(0x80)
#define BC3_ZTEX_FLAG_MASK UINT8_C(0xff)

enum bc3_ztex_frame_type {
	BC3_ZTEX_TYPE_WORK = 1,
	BC3_ZTEX_TYPE_ACK = 2,
	BC3_ZTEX_TYPE_RESULT = 3,
	BC3_ZTEX_TYPE_STATUS = 4,
	BC3_ZTEX_TYPE_PAUSE = 5
};

struct bc3_ztex_status {
	uint32_t progress_generation;
	uint32_t progress_nonce;
	uint32_t progress_hash7;
	uint32_t completed_hashes;
	uint32_t abi_id;
	uint32_t build_id;
	uint8_t version;
	uint8_t type;
	uint8_t occupancy;
	uint8_t flags;
	uint32_t head_session;
	uint32_t head_epoch;
	uint32_t head_sequence;
	uint32_t head_nonce;
	uint32_t head_hash7;
	uint32_t active_session;
	uint32_t active_epoch;
};

static inline uint32_t bc3_ztex_get_le32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] |
		((uint32_t)bytes[1] << 8) |
		((uint32_t)bytes[2] << 16) |
		((uint32_t)bytes[3] << 24);
}

static inline void bc3_ztex_put_le32(uint8_t *bytes, uint32_t value)
{
	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
	bytes[2] = (uint8_t)(value >> 16);
	bytes[3] = (uint8_t)(value >> 24);
}

static inline uint32_t bc3_ztex_crc32c(const uint8_t *bytes, size_t length)
{
	uint32_t crc = UINT32_C(0xffffffff);
	size_t i;
	unsigned bit;

	for (i = 0; i < length; ++i) {
		crc ^= bytes[i];
		for (bit = 0; bit < 8; ++bit)
			crc = (crc >> 1) ^
				((UINT32_C(0) - (crc & 1u)) & UINT32_C(0x82f63b78));
	}
	return ~crc;
}

static inline bool bc3_ztex_encode_work_fragment(
	uint8_t frame[BC3_ZTEX_WORK_FRAME_SIZE], uint32_t session,
	uint32_t epoch, unsigned fragment,
	const uint8_t work[BC3_ZTEX_WORK_SIZE])
{
	uint32_t crc;

	if (!frame || !work || fragment > 1u)
		return false;
	memset(frame, 0, BC3_ZTEX_WORK_FRAME_SIZE);
	memcpy(frame, "B3WF", 4);
	bc3_ztex_put_le32(frame + 4, BC3_ZTEX_ABI_ID);
	bc3_ztex_put_le32(frame + 8, session);
	bc3_ztex_put_le32(frame + 12, epoch);
	frame[16] = BC3_ZTEX_PROTOCOL_VERSION;
	frame[17] = BC3_ZTEX_TYPE_WORK;
	frame[18] = (uint8_t)fragment;
	frame[19] = 40u;
	memcpy(frame + 20, work + 40u * fragment, 40);
	crc = bc3_ztex_crc32c(frame, 60);
	bc3_ztex_put_le32(frame + 60, crc);
	return true;
}

static inline bool bc3_ztex_encode_ack(
	uint8_t frame[BC3_ZTEX_ACK_FRAME_SIZE],
	const struct bc3_ztex_status *status)
{
	uint32_t crc;

	if (!frame || !status ||
	    !(status->flags & BC3_ZTEX_FLAG_HEAD_VALID))
		return false;
	memset(frame, 0, BC3_ZTEX_ACK_FRAME_SIZE);
	memcpy(frame, "B3AK", 4);
	bc3_ztex_put_le32(frame + 4, BC3_ZTEX_ABI_ID);
	bc3_ztex_put_le32(frame + 8, status->head_session);
	bc3_ztex_put_le32(frame + 12, status->head_epoch);
	bc3_ztex_put_le32(frame + 16, status->head_sequence);
	bc3_ztex_put_le32(frame + 20, status->head_nonce);
	bc3_ztex_put_le32(frame + 24, status->head_hash7);
	frame[28] = BC3_ZTEX_PROTOCOL_VERSION;
	frame[29] = BC3_ZTEX_TYPE_ACK;
	crc = bc3_ztex_crc32c(frame, 32);
	bc3_ztex_put_le32(frame + 32, crc);
	return true;
}

/* PAUSE is a one-way, idempotent qualification/rollback barrier.  It is
 * bound to the exact candidate build and remains asserted in RTL until the
 * next configuration-time reset.  The host waits for QUIESCED plus an empty
 * FIFO before releasing work ownership or replacing the candidate. */
static inline bool bc3_ztex_encode_pause(
	uint8_t frame[BC3_ZTEX_PAUSE_FRAME_SIZE], uint32_t build_id)
{
	uint32_t crc;

	if (!frame || build_id == 0)
		return false;
	memset(frame, 0, BC3_ZTEX_PAUSE_FRAME_SIZE);
	memcpy(frame, "B3PS", 4);
	bc3_ztex_put_le32(frame + 4, BC3_ZTEX_ABI_ID);
	bc3_ztex_put_le32(frame + 8, build_id);
	frame[24] = BC3_ZTEX_PROTOCOL_VERSION;
	frame[25] = BC3_ZTEX_TYPE_PAUSE;
	crc = bc3_ztex_crc32c(frame, 28);
	bc3_ztex_put_le32(frame + 28, crc);
	return true;
}

static inline bool bc3_ztex_decode_status(
	struct bc3_ztex_status *status, const uint8_t *frame, size_t length)
{
	uint32_t received_crc;

	if (!status || !frame || length != BC3_ZTEX_STATUS_FRAME_SIZE)
		return false;
	if (memcmp(frame + 16, "B3RS", 4) != 0)
		return false;
	if (bc3_ztex_get_le32(frame + 20) != BC3_ZTEX_ABI_ID)
		return false;
	if (frame[28] != BC3_ZTEX_PROTOCOL_VERSION)
		return false;
	if (frame[29] != BC3_ZTEX_TYPE_RESULT &&
		frame[29] != BC3_ZTEX_TYPE_STATUS)
		return false;
	received_crc = bc3_ztex_get_le32(frame + 60);
	if (received_crc != bc3_ztex_crc32c(frame, 60))
		return false;
	if (((frame[31] & BC3_ZTEX_FLAG_HEAD_VALID) != 0) !=
	    (frame[29] == BC3_ZTEX_TYPE_RESULT))
		return false;

	status->progress_generation = bc3_ztex_get_le32(frame + 0);
	status->progress_nonce = bc3_ztex_get_le32(frame + 4);
	status->progress_hash7 = bc3_ztex_get_le32(frame + 8);
	status->completed_hashes = bc3_ztex_get_le32(frame + 12);
	status->abi_id = bc3_ztex_get_le32(frame + 20);
	status->build_id = bc3_ztex_get_le32(frame + 24);
	status->version = frame[28];
	status->type = frame[29];
	status->occupancy = frame[30];
	status->flags = frame[31];
	status->head_session = bc3_ztex_get_le32(frame + 32);
	status->head_epoch = bc3_ztex_get_le32(frame + 36);
	status->head_sequence = bc3_ztex_get_le32(frame + 40);
	status->head_nonce = bc3_ztex_get_le32(frame + 44);
	status->head_hash7 = bc3_ztex_get_le32(frame + 48);
	status->active_session = bc3_ztex_get_le32(frame + 52);
	status->active_epoch = bc3_ztex_get_le32(frame + 56);
	return true;
}

#endif
