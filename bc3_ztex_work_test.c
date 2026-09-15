#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bc3_ztex_work.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		++failures; \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
	} \
} while (0)

static int hex_nibble(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return 10 + value - 'a';
	if (value >= 'A' && value <= 'F')
		return 10 + value - 'A';
	return -1;
}

static bool decode_hex(const char *text, uint8_t *bytes, size_t length)
{
	size_t i;

	if (!text || !bytes || strlen(text) != 2u * length)
		return false;
	for (i = 0; i < length; ++i) {
		int high = hex_nibble(text[2u * i]);
		int low = hex_nibble(text[2u * i + 1u]);
		if (high < 0 || low < 0)
			return false;
		bytes[i] = (uint8_t)((unsigned)high * 16u + (unsigned)low);
	}
	return true;
}

static uint32_t get_be32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] << 24 |
		(uint32_t)bytes[1] << 16 |
		(uint32_t)bytes[2] << 8 |
		(uint32_t)bytes[3];
}

static void test_layout_and_ignored_words(void)
{
	uint32_t header[48];
	uint32_t target[8];
	uint8_t physical[BC3_ZTEX_WORK_SIZE];
	uint8_t frozen[BC3_ZTEX_WORK_SIZE];
	unsigned i;

	for (i = 0; i < 48; ++i)
		header[i] = UINT32_C(0x01020304) + i * UINT32_C(0x11111111);
	for (i = 0; i < 8; ++i)
		target[i] = UINT32_C(0x10203040) + i;
	CHECK(bc3_ztex_pack_work(physical, header, 48, target, 8));
	CHECK(physical[0] == 0x01 && physical[1] == 0x02 &&
		physical[2] == 0x03 && physical[3] == 0x04);
	CHECK(get_be32(physical + 72) == header[18]);
	CHECK(get_be32(physical + 76) == target[7]);
	memcpy(frozen, physical, sizeof(frozen));
	header[19] ^= UINT32_C(0xffffffff);
	header[47] ^= UINT32_C(0xffffffff);
	target[0] ^= UINT32_C(0xffffffff);
	CHECK(bc3_ztex_pack_work(physical, header, 48, target, 8));
	CHECK(memcmp(physical, frozen, sizeof(frozen)) == 0);
	CHECK(!bc3_ztex_pack_work(NULL, header, 48, target, 8));
	CHECK(!bc3_ztex_pack_work(physical, NULL, 48, target, 8));
	CHECK(!bc3_ztex_pack_work(physical, header, 19, target, 8));
	CHECK(!bc3_ztex_pack_work(physical, header, 48, target, 7));
}

static void test_known_bc3_prefix_and_fragments(void)
{
	/* BitcoinIII height-30240 serialized header.  Its first 76 bytes are the
	 * independently checked RTL/C-oracle prefix; the final four header bytes
	 * are a nonce and are intentionally replaced here by the FPGA threshold. */
	static const char header_hex[] =
		"0010002030d2767637fc55d1f70edc5b20a41fddd17d8a12854ba71504000000"
		"0000000018dcbe866321fcf914b8e4f187158d285d7a1e6966e14e2b57e7071d"
		"ed479309a067106affff001d05417434";
	uint8_t serialized[80];
	uint8_t physical[BC3_ZTEX_WORK_SIZE];
	uint8_t frames[2][BC3_ZTEX_WORK_FRAME_SIZE];
	uint8_t joined[BC3_ZTEX_WORK_SIZE];
	uint32_t header[48] = { 0 };
	uint32_t target[8] = { 0 };
	unsigned i;

	CHECK(decode_hex(header_hex, serialized, sizeof(serialized)));
	for (i = 0; i < 19; ++i)
		header[i] = get_be32(serialized + 4u * i);
	header[19] = UINT32_C(0xdeadbeef);
	target[7] = UINT32_C(0x000000ff);
	CHECK(bc3_ztex_pack_work(physical, header, 48, target, 8));
	CHECK(memcmp(physical, serialized, 76) == 0);
	CHECK(get_be32(physical + 76) == UINT32_C(0x000000ff));
	CHECK(bc3_ztex_encode_work_fragment(frames[0],
		UINT32_C(0x52333201), UINT32_C(7), 0, physical));
	CHECK(bc3_ztex_encode_work_fragment(frames[1],
		UINT32_C(0x52333201), UINT32_C(7), 1, physical));
	memcpy(joined, frames[0] + 20, 40);
	memcpy(joined + 40, frames[1] + 20, 40);
	CHECK(memcmp(joined, physical, sizeof(joined)) == 0);
	CHECK(frames[0][18] == 0 && frames[1][18] == 1);
	CHECK(bc3_ztex_get_le32(frames[0] + 60) ==
		bc3_ztex_crc32c(frames[0], 60));
	CHECK(bc3_ztex_get_le32(frames[1] + 60) ==
		bc3_ztex_crc32c(frames[1], 60));
}

int main(void)
{
	test_layout_and_ignored_words();
	test_known_bc3_prefix_and_fragments();
	if (failures != 0) {
		fprintf(stderr, "FAIL: %u/%u BC3 physical-work checks failed\n",
			failures, checks);
		return 1;
	}
	printf("PASS: %u BC3 physical-work checks (76-byte prefix, target byte order, fragment reconstruction)\n",
		checks);
	return 0;
}
