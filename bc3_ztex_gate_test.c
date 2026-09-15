#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bc3_ztex_gate.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		++failures; \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
	} \
} while (0)

static void reject(const char *text)
{
	uint32_t value = UINT32_C(0xa5a5a5a5);

	CHECK(!bc3_ztex_parse_build_id(text, &value));
	CHECK(value == UINT32_C(0xa5a5a5a5));
}

static struct bc3_ztex_status pristine_status(uint32_t build_id)
{
	struct bc3_ztex_status status;

	memset(&status, 0, sizeof(status));
	status.abi_id = BC3_ZTEX_ABI_ID;
	status.build_id = build_id;
	status.version = BC3_ZTEX_PROTOCOL_VERSION;
	status.type = BC3_ZTEX_TYPE_STATUS;
	status.flags = BC3_ZTEX_FLAG_PAUSED;
	return status;
}

static void test_startup_status(void)
{
	const uint32_t build_id = UINT32_C(0x52333201);
	struct bc3_ztex_status status = pristine_status(build_id);

	CHECK(bc3_ztex_startup_status_ok(&status, build_id));
	CHECK(!bc3_ztex_startup_status_ok(NULL, build_id));
	CHECK(!bc3_ztex_startup_status_ok(&status, 0));
	CHECK(!bc3_ztex_startup_status_ok(&status,
		UINT32_C(0x52333202)));

	status.flags = 0;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.flags |= BC3_ZTEX_FLAG_PROTOCOL_ERROR;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.type = BC3_ZTEX_TYPE_RESULT;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.occupancy = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.completed_hashes = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.progress_nonce = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.progress_hash7 = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));

	/* Compatible() supplies the remaining zero-state invariants even though
	 * PAUSED itself carries no active/head bit. */
	status = pristine_status(build_id);
	status.progress_generation = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.head_epoch = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.active_epoch = 1;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.abi_id ^= UINT32_C(1);
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.version++;
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.build_id ^= UINT32_C(1);
	CHECK(!bc3_ztex_startup_status_ok(&status, build_id));
}

static void test_quiesced_empty_status(void)
{
	const uint32_t build_id = UINT32_C(0x52333201);
	struct bc3_ztex_status status = pristine_status(build_id);

	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED |
		BC3_ZTEX_FLAG_PAUSED | BC3_ZTEX_FLAG_QUIESCED;
	CHECK(bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status.flags |= BC3_ZTEX_FLAG_PROTOCOL_ERROR;
	CHECK(bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status = pristine_status(build_id);
	status.flags = BC3_ZTEX_FLAG_PAUSED | BC3_ZTEX_FLAG_QUIESCED;
	CHECK(!bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED |
		BC3_ZTEX_FLAG_PAUSED;
	CHECK(!bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED |
		BC3_ZTEX_FLAG_QUIESCED;
	CHECK(!bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status.flags = BC3_ZTEX_FLAG_PAUSE_LATCHED |
		BC3_ZTEX_FLAG_PAUSED | BC3_ZTEX_FLAG_QUIESCED |
		BC3_ZTEX_FLAG_ACTIVE_VALID;
	status.active_session = 7;
	status.active_epoch = 9;
	CHECK(bc3_ztex_quiesced_empty_status_ok(&status, build_id));
	status.occupancy = 1;
	CHECK(!bc3_ztex_quiesced_empty_status_ok(&status, build_id));
}

int main(void)
{
	uint32_t value = 0;

	CHECK(bc3_ztex_parse_build_id("52333201", &value));
	CHECK(value == UINT32_C(0x52333201));
	CHECK(bc3_ztex_parse_build_id("0x89ABCDEF", &value));
	CHECK(value == UINT32_C(0x89abcdef));
	CHECK(bc3_ztex_parse_build_id("0X00000001", &value));
	CHECK(value == UINT32_C(1));
	CHECK(bc3_ztex_build_id_supported(UINT32_C(0x00000034)));
	CHECK(!bc3_ztex_build_id_supported(UINT32_C(0x00000033)));
	CHECK(!bc3_ztex_build_id_supported(UINT32_C(0x52333201)));
	reject(NULL);
	CHECK(!bc3_ztex_parse_build_id("52333201", NULL));
	reject("");
	reject("0");
	reject("00000000");
	reject("0x00000000");
	reject("5233320");
	reject("523332010");
	reject("0x5233320");
	reject("0x523332010");
	reject(" 52333201");
	reject("+52333201");
	reject("-52333201");
	reject("0x52333z01");
	reject("52333201 ");
	reject("0x52333201junk");
	test_startup_status();
	test_quiesced_empty_status();

	if (failures != 0) {
		fprintf(stderr, "FAIL: %u/%u BC3 gate checks failed\n",
			failures, checks);
		return 1;
	}
	printf("PASS: %u BC3 build-ID/startup gate checks supported=00000034 retired33=rejected\n",
		checks);
	return 0;
}
