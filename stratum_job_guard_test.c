#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stratum_job_guard.h"

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
	char bounded[STRATUM_JOB_ID_MAX + 2];
	uint8_t coinbase[180];
	size_t bytes;
	size_t offset;
	size_t total;
	size_t length;
	size_t cut;
	uint32_t target[8];
	unsigned word;

	CHECK(stratum_hex_exact("", 0));
	CHECK(stratum_hex_exact("00ffA5", 3));
	CHECK(!stratum_hex_exact("00fg", 2));
	CHECK(!stratum_hex_exact("000", 2));
	CHECK(!stratum_hex_exact(NULL, 0));
	CHECK(stratum_hex_bounded("", 0, &bytes) && bytes == 0);
	CHECK(stratum_hex_bounded("0011", 2, &bytes) && bytes == 2);
	CHECK(!stratum_hex_bounded("001", 2, &bytes));
	CHECK(!stratum_hex_bounded("001122", 2, &bytes));
	CHECK(!stratum_hex_bounded("0g", 2, &bytes));

	memset(bounded, 'a', sizeof(bounded));
	bounded[STRATUM_JOB_ID_MAX] = '\0';
	CHECK(stratum_string_bounded(bounded, STRATUM_JOB_ID_MAX, &length));
	CHECK(length == STRATUM_JOB_ID_MAX);
	bounded[STRATUM_JOB_ID_MAX] = 'a';
	bounded[STRATUM_JOB_ID_MAX + 1] = '\0';
	CHECK(!stratum_string_bounded(bounded, STRATUM_JOB_ID_MAX, &length));

	CHECK(stratum_coinbase_layout(108, 4, 4, 28, &offset, &total));
	CHECK(offset == 112 && total == 144);
	CHECK(stratum_xnonce_layout_valid(total, offset, 4));
	CHECK(!stratum_xnonce_layout_valid(total, total + 1, 0));
	CHECK(!stratum_xnonce_layout_valid(total, total - 1, 2));
	CHECK(!stratum_coinbase_layout(STRATUM_COINBASE_MAX, 1, 0, 0,
		&offset, &total));
	CHECK(!stratum_coinbase_layout(0, 0, 0, 0, &offset, &total));

	memset(coinbase, 0, sizeof(coinbase));
	coinbase[92] = 0xe8;
	coinbase[93] = 0x33;
	coinbase[94] = 0x13;
	CHECK(stratum_coinbase_height(coinbase, 143) == 0);
	CHECK(stratum_coinbase_height(coinbase, 144) == UINT32_C(0x1333e8));

	/* Disable the Decred heuristic and place the bounded legacy/BIP34 tag. */
	memset(coinbase, 0, sizeof(coinbase));
	coinbase[40] = 0xff;
	coinbase[41] = 0xff;
	coinbase[42] = 0x27;
	coinbase[43] = 3;
	coinbase[44] = 0xe8;
	coinbase[45] = 0x33;
	coinbase[46] = 0x13;
	for (cut = 0; cut <= 46; ++cut)
		CHECK(stratum_coinbase_height(coinbase, cut) == 0);
	CHECK(stratum_coinbase_height(coinbase, 47) == UINT32_C(0x1333e8));
	coinbase[43] = 0;
	CHECK(stratum_coinbase_height(coinbase, sizeof(coinbase)) == 0);
	coinbase[43] = 5;
	CHECK(stratum_coinbase_height(coinbase, sizeof(coinbase)) == 0);
	coinbase[43] = 4;
	coinbase[47] = 1;
	CHECK(stratum_coinbase_height(coinbase, 48) == UINT32_C(0x011333e8));
	coinbase[40] = 0;
	coinbase[41] = 0;
	coinbase[158] = 0xff;
	coinbase[159] = 0xff;
	CHECK(stratum_coinbase_height(coinbase, sizeof(coinbase)) == 0);
	coinbase[158] = 0;
	coinbase[159] = 0;
	coinbase[160] = 0xff;
	coinbase[161] = 0xff;
	CHECK(stratum_coinbase_height(coinbase, sizeof(coinbase)) == 0);
	CHECK(stratum_coinbase_height(NULL, sizeof(coinbase)) == 0);

	CHECK(stratum_diff_to_target(target, 1.0));
	CHECK(target[6] == UINT32_C(0xffff0000) && target[7] == 0);
	CHECK(stratum_diff_to_target(target, 0.5));
	CHECK(target[6] == UINT32_C(0xfffe0000) && target[7] == 1);
	CHECK(stratum_diff_to_target(target, 1e-300));
	for (word = 0; word < 8; ++word)
		CHECK(target[word] == UINT32_MAX);
	CHECK(!stratum_diff_to_target(target, 0.0));
	CHECK(!stratum_diff_to_target(target, -1.0));
	CHECK(!stratum_diff_to_target(target, INFINITY));
	CHECK(!stratum_diff_to_target(target, NAN));
	for (word = 0; word < 8; ++word)
		CHECK(target[word] == 0);

	printf("STRATUM_JOB_GUARD_TEST_PASS checks=%u hex=bounded "
		"layout=checked height=truncation_safe difficulty=defined "
		"caps=explicit\n", checks);
	return EXIT_SUCCESS;
}
