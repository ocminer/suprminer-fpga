#include <stdio.h>
#include <stdlib.h>

#include "bc3_ztex_protocol.h"

static unsigned checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

int main(void)
{
	uint8_t work[BC3_ZTEX_WORK_SIZE];
	uint8_t fragment0[BC3_ZTEX_WORK_FRAME_SIZE];
	uint8_t fragment1[BC3_ZTEX_WORK_FRAME_SIZE];
	uint8_t status_frame[BC3_ZTEX_STATUS_FRAME_SIZE] = { 0 };
	uint8_t mutated[BC3_ZTEX_STATUS_FRAME_SIZE];
	uint8_t ack[BC3_ZTEX_ACK_FRAME_SIZE];
	uint8_t pause[BC3_ZTEX_PAUSE_FRAME_SIZE];
	struct bc3_ztex_status status = { 0 };
	struct bc3_ztex_status decoded = { 0 };
	uint32_t crc;
	size_t i;

	CHECK(bc3_ztex_crc32c((const uint8_t *)"123456789", 9) ==
		UINT32_C(0xe3069283));
	for (i = 0; i < sizeof(work); ++i)
		work[i] = (uint8_t)(3u * i + 1u);
	CHECK(bc3_ztex_encode_work_fragment(fragment0,
		UINT32_C(0x11223344), UINT32_C(0x55667788), 0, work));
	CHECK(bc3_ztex_encode_work_fragment(fragment1,
		UINT32_C(0x11223344), UINT32_C(0x55667788), 1, work));
	CHECK(!bc3_ztex_encode_work_fragment(fragment0, 0, 0, 2, work));
	CHECK(memcmp(fragment0, "B3WF", 4) == 0);
	CHECK(bc3_ztex_get_le32(fragment0 + 4) == BC3_ZTEX_ABI_ID);
	CHECK(bc3_ztex_get_le32(fragment0 + 8) == UINT32_C(0x11223344));
	CHECK(bc3_ztex_get_le32(fragment0 + 12) == UINT32_C(0x55667788));
	CHECK(fragment0[18] == 0 && fragment1[18] == 1);
	CHECK(memcmp(fragment0 + 20, work, 40) == 0);
	CHECK(memcmp(fragment1 + 20, work + 40, 40) == 0);
	CHECK(bc3_ztex_get_le32(fragment0 + 60) ==
		bc3_ztex_crc32c(fragment0, 60));
	CHECK(bc3_ztex_get_le32(fragment1 + 60) ==
		bc3_ztex_crc32c(fragment1, 60));

	bc3_ztex_put_le32(status_frame + 0, UINT32_C(0x01020304));
	bc3_ztex_put_le32(status_frame + 4, UINT32_C(0x11121314));
	bc3_ztex_put_le32(status_frame + 8, UINT32_C(0x21222324));
	bc3_ztex_put_le32(status_frame + 12, UINT32_C(0x31323334));
	memcpy(status_frame + 16, "B3RS", 4);
	bc3_ztex_put_le32(status_frame + 20, BC3_ZTEX_ABI_ID);
	bc3_ztex_put_le32(status_frame + 24, UINT32_C(0x89abcdef));
	status_frame[28] = BC3_ZTEX_PROTOCOL_VERSION;
	status_frame[29] = BC3_ZTEX_TYPE_RESULT;
	status_frame[30] = 7;
	status_frame[31] = 0x1d;
	bc3_ztex_put_le32(status_frame + 32, UINT32_C(0xa1a2a3a4));
	bc3_ztex_put_le32(status_frame + 36, UINT32_C(0xb1b2b3b4));
	bc3_ztex_put_le32(status_frame + 40, UINT32_C(0xc1c2c3c4));
	bc3_ztex_put_le32(status_frame + 44, UINT32_C(0xd1d2d3d4));
	bc3_ztex_put_le32(status_frame + 48, UINT32_C(0x00000007));
	bc3_ztex_put_le32(status_frame + 52, UINT32_C(0xe1e2e3e4));
	bc3_ztex_put_le32(status_frame + 56, UINT32_C(0xf1f2f3f4));
	crc = bc3_ztex_crc32c(status_frame, 60);
	bc3_ztex_put_le32(status_frame + 60, crc);
	CHECK(bc3_ztex_decode_status(&decoded, status_frame,
		sizeof(status_frame)));
	CHECK(decoded.build_id == UINT32_C(0x89abcdef));
	CHECK(decoded.progress_generation == UINT32_C(0x01020304));
	CHECK(decoded.completed_hashes == UINT32_C(0x31323334));
	CHECK(decoded.head_session == UINT32_C(0xa1a2a3a4));
	CHECK(decoded.head_epoch == UINT32_C(0xb1b2b3b4));
	CHECK(decoded.head_sequence == UINT32_C(0xc1c2c3c4));
	CHECK(decoded.head_nonce == UINT32_C(0xd1d2d3d4));
	CHECK(decoded.head_hash7 == UINT32_C(0x00000007));
	CHECK(decoded.active_session == UINT32_C(0xe1e2e3e4));
	CHECK(decoded.active_epoch == UINT32_C(0xf1f2f3f4));
	for (i = 0; i < BC3_ZTEX_STATUS_FRAME_SIZE; ++i)
		CHECK(!bc3_ztex_decode_status(&decoded, status_frame, i));
	for (i = 0; i < BC3_ZTEX_STATUS_FRAME_SIZE; ++i) {
		memcpy(mutated, status_frame, sizeof(mutated));
		mutated[i] ^= 1u;
		CHECK(!bc3_ztex_decode_status(&decoded, mutated, sizeof(mutated)));
	}

	status.head_session = UINT32_C(0xa1a2a3a4);
	status.head_epoch = UINT32_C(0xb1b2b3b4);
	status.head_sequence = 0;
	status.head_nonce = 0;
	status.head_hash7 = UINT32_C(0x89abcdef);
	CHECK(!bc3_ztex_encode_ack(ack, &status));
	status.flags = 1;
	CHECK(bc3_ztex_encode_ack(ack, &status));
	CHECK(memcmp(ack, "B3AK", 4) == 0);
	CHECK(bc3_ztex_get_le32(ack + 16) == 0);
	CHECK(bc3_ztex_get_le32(ack + 20) == 0);
	CHECK(bc3_ztex_get_le32(ack + 24) == UINT32_C(0x89abcdef));
	CHECK(ack[28] == BC3_ZTEX_PROTOCOL_VERSION);
	CHECK(ack[29] == BC3_ZTEX_TYPE_ACK);
	CHECK(ack[30] == 0 && ack[31] == 0);
	CHECK(bc3_ztex_get_le32(ack + 32) == bc3_ztex_crc32c(ack, 32));

	CHECK(!bc3_ztex_encode_pause(NULL, UINT32_C(0x89abcdef)));
	CHECK(!bc3_ztex_encode_pause(pause, 0));
	CHECK(bc3_ztex_encode_pause(pause, UINT32_C(0x89abcdef)));
	CHECK(memcmp(pause, "B3PS", 4) == 0);
	CHECK(bc3_ztex_get_le32(pause + 4) == BC3_ZTEX_ABI_ID);
	CHECK(bc3_ztex_get_le32(pause + 8) == UINT32_C(0x89abcdef));
	CHECK(bc3_ztex_get_le32(pause + 12) == 0);
	CHECK(bc3_ztex_get_le32(pause + 16) == 0);
	CHECK(bc3_ztex_get_le32(pause + 20) == 0);
	CHECK(pause[24] == BC3_ZTEX_PROTOCOL_VERSION);
	CHECK(pause[25] == BC3_ZTEX_TYPE_PAUSE);
	CHECK(pause[26] == 0 && pause[27] == 0);
	CHECK(bc3_ztex_get_le32(pause + 28) ==
		bc3_ztex_crc32c(pause, 28));

	printf("BC3_ZTEX_PROTOCOL_TEST_PASS checks=%u protocol=2 crc32c=known-vector frames=exact ack=full-key pause=build-bound mutation=64\n",
		checks);
	return EXIT_SUCCESS;
}
