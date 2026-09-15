#include <stdio.h>
#include "ztex_rb_test.h"

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

int main(void)
{
	enum ztex_rb_test_mode mode = ZTEX_RB_TEST_STAGGER_RETRY;

	CHECK(ztex_rb_parse_mode(NULL, &mode));
	CHECK(mode == ZTEX_RB_TEST_OFF);
	CHECK(ztex_rb_parse_mode("observe", &mode));
	CHECK(mode == ZTEX_RB_TEST_OBSERVE);
	CHECK(ztex_rb_parse_mode("stagger", &mode));
	CHECK(mode == ZTEX_RB_TEST_STAGGER);
	CHECK(ztex_rb_parse_mode("retry", &mode));
	CHECK(mode == ZTEX_RB_TEST_RETRY);
	CHECK(ztex_rb_parse_mode("stagger-retry", &mode));
	CHECK(mode == ZTEX_RB_TEST_STAGGER_RETRY);
	CHECK(!ztex_rb_parse_mode("", &mode));
	CHECK(!ztex_rb_parse_mode("on", &mode));
	CHECK(!ztex_rb_parse_mode("Stagger", &mode));

	CHECK(ztex_rb_board_phase_us(0, 16) == 0);
	CHECK(ztex_rb_board_phase_us(1, 16) == 15625);
	CHECK(ztex_rb_board_phase_us(15, 16) == 234375);
	CHECK(ztex_rb_lane_gap_us(1) == 2000);
	CHECK(ztex_rb_lane_gap_us(16) == 2000);
	CHECK(ztex_rb_lane_gap_us(64) == 781);
	CHECK(ztex_rb_next_slot_us(250000, 0) == 250000);
	CHECK(ztex_rb_next_slot_us(250001, 0) == 500000);
	CHECK(ztex_rb_next_slot_us(260000, 15625) == 265625);

	CHECK(ztex_rb_classify_frame(-99, 0, 0, 0, 0, true) == ZTEX_RB_SHORT);
	CHECK(ztex_rb_classify_frame(-7, 0, 0, 0, 0, true) == ZTEX_RB_USB_ERROR);
	CHECK(ztex_rb_classify_frame(16, 0, 1, 0, 2000001, true) == ZTEX_RB_ZERO);
	CHECK(ztex_rb_classify_frame(16, 60000001, 1, 0, 0, true) == ZTEX_RB_JUMP);
	CHECK(ztex_rb_classify_frame(16, 0, 1, 2, 0, true) == ZTEX_RB_NOISE);
	CHECK(ztex_rb_classify_frame(16, 42, 42, 0, 0, true) == ZTEX_RB_NOISE);
	CHECK(ztex_rb_classify_frame(16, 42, 43, 0, 0, true) == ZTEX_RB_CLEAN);

	CHECK(ztex_rb_match_hash7(10, 10, true, 11) == ZTEX_RB_MATCH_CURRENT);
	CHECK(ztex_rb_match_hash7(11, 10, true, 11) == ZTEX_RB_MATCH_PREVIOUS);
	CHECK(ztex_rb_match_hash7(10, 10, true, 10) == ZTEX_RB_MATCH_BOTH);
	CHECK(ztex_rb_match_hash7(12, 10, true, 11) == ZTEX_RB_MATCH_NEITHER);
	CHECK(ztex_rb_match_hash7(11, 10, false, 11) == ZTEX_RB_MATCH_NEITHER);

	CHECK(ztex_rb_retry_delay_ms(ZTEX_RB_SHORT, 0) == 1);
	CHECK(ztex_rb_retry_delay_ms(ZTEX_RB_SHORT, 3) == 8);
	CHECK(ztex_rb_retry_delay_ms(ZTEX_RB_ZERO, 0) == 1);
	CHECK(ztex_rb_retry_delay_ms(ZTEX_RB_JUMP, 2) == 16);

	if (failures)
		return 1;
	puts("ZTEX readback test helpers: PASS");
	return 0;
}
