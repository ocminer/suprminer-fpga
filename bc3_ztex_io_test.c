#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bc3_ztex_io.h"

static unsigned checks;
static unsigned failures;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		++failures; \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
	} \
} while (0)

struct mock_io {
	int selected;
	unsigned selects;
	unsigned sends;
	unsigned reads;
	unsigned event_count;
	char events[32];
	int fail_select_call;
	int fault_send_call;
	int fault_send_rc;
	bool deliver_faulted_send;
	uint8_t staged;
	uint32_t staged_session;
	uint32_t staged_epoch;
	uint32_t committed_session;
	uint32_t committed_epoch;
	unsigned activations;
};

static void event(struct mock_io *mock, char value)
{
	if (mock->event_count < sizeof(mock->events))
		mock->events[mock->event_count++] = value;
}

static bool mock_select(void *opaque, int lane)
{
	struct mock_io *mock = opaque;

	mock->selects++;
	event(mock, 'L');
	if ((int)mock->selects == mock->fail_select_call)
		return false;
	mock->selected = lane;
	return true;
}

static void mock_deliver_work(struct mock_io *mock, const uint8_t *frame,
	int length)
{
	uint32_t session;
	uint32_t epoch;
	unsigned fragment;

	if (length != (int)BC3_ZTEX_WORK_FRAME_SIZE ||
	    memcmp(frame, "B3WF", 4) != 0 ||
	    bc3_ztex_get_le32(frame + 60) != bc3_ztex_crc32c(frame, 60))
		return;
	session = bc3_ztex_get_le32(frame + 8);
	epoch = bc3_ztex_get_le32(frame + 12);
	fragment = frame[18];
	if (fragment > 1)
		return;
	if (mock->staged != 0 &&
	    (mock->staged_session != session || mock->staged_epoch != epoch))
		return;
	mock->staged_session = session;
	mock->staged_epoch = epoch;
	mock->staged |= (uint8_t)(1u << fragment);
	if (mock->staged == 3u &&
	    (mock->committed_session != session ||
	     mock->committed_epoch != epoch)) {
		mock->committed_session = session;
		mock->committed_epoch = epoch;
		mock->activations++;
		mock->staged = 0;
	}
}

static int mock_send(void *opaque, const uint8_t *frame, int length,
	unsigned timeout_ms)
{
	struct mock_io *mock = opaque;
	bool fault;

	(void)timeout_ms;
	mock->sends++;
	event(mock, 'S');
	fault = (int)mock->sends == mock->fault_send_call;
	if (!fault || mock->deliver_faulted_send)
		mock_deliver_work(mock, frame, length);
	return fault ? mock->fault_send_rc : length;
}

static int mock_read(void *opaque, uint8_t *frame, int length,
	unsigned timeout_ms)
{
	struct mock_io *mock = opaque;

	(void)timeout_ms;
	mock->reads++;
	event(mock, 'R');
	memset(frame, 0x5a, (size_t)length);
	return mock->fault_send_call == (int)mock->reads ?
		mock->fault_send_rc : length;
}

static struct bc3_ztex_io_ops make_ops(struct mock_io *mock)
{
	struct bc3_ztex_io_ops ops;

	ops.opaque = mock;
	ops.select_lane = mock_select;
	ops.send_exact = mock_send;
	ops.read_exact = mock_read;
	return ops;
}

static void build_frames(uint8_t frames[2][BC3_ZTEX_WORK_FRAME_SIZE])
{
	uint8_t work[BC3_ZTEX_WORK_SIZE];
	unsigned i;

	for (i = 0; i < sizeof(work); ++i)
		work[i] = (uint8_t)(3u + 7u * i);
	CHECK(bc3_ztex_encode_work_fragment(frames[0], UINT32_C(0x11112222),
		UINT32_C(9), 0, work));
	CHECK(bc3_ztex_encode_work_fragment(frames[1], UINT32_C(0x11112222),
		UINT32_C(9), 1, work));
}

static void test_selected_exact_io(void)
{
	struct mock_io mock;
	struct bc3_ztex_io_ops ops;
	uint8_t frame[64] = { 0 };
	int rc;

	memset(&mock, 0, sizeof(mock));
	ops = make_ops(&mock);
	rc = bc3_ztex_io_send_selected(&ops, 3, frame, 64, 500);
	CHECK(rc == 64);
	CHECK(mock.selected == 3 && mock.selects == 1 && mock.sends == 1);
	CHECK(mock.event_count == 2 && mock.events[0] == 'L' &&
		mock.events[1] == 'S');
	rc = bc3_ztex_io_read_selected(&ops, 2, frame, 64, 500);
	CHECK(rc == 64);
	CHECK(mock.selected == 2 && mock.selects == 2 && mock.reads == 1);
	CHECK(mock.event_count == 4 && mock.events[2] == 'L' &&
		mock.events[3] == 'R');

	mock.fail_select_call = 3;
	rc = bc3_ztex_io_send_selected(&ops, 1, frame, 64, 500);
	CHECK(rc == BC3_ZTEX_IO_SELECT_ERROR);
	CHECK(mock.sends == 1);
	mock.fail_select_call = 4;
	rc = bc3_ztex_io_read_selected(&ops, 1, frame, 64, 500);
	CHECK(rc == BC3_ZTEX_IO_SELECT_ERROR);
	CHECK(mock.reads == 1);

	mock.fail_select_call = 0;
	mock.fault_send_call = 2;
	mock.fault_send_rc = 17;
	rc = bc3_ztex_io_send_selected(&ops, 0, frame, 64, 500);
	CHECK(rc == BC3_ZTEX_IO_SHORT_ERROR);
	mock.fault_send_call = 2;
	mock.fault_send_rc = 0;
	rc = bc3_ztex_io_read_selected(&ops, 0, frame, 64, 500);
	CHECK(rc == BC3_ZTEX_IO_SHORT_ERROR);

	CHECK(bc3_ztex_io_send_selected(NULL, 0, frame, 64, 1) ==
		BC3_ZTEX_IO_INVALID_ERROR);
	CHECK(bc3_ztex_io_send_selected(&ops, -1, frame, 64, 1) ==
		BC3_ZTEX_IO_INVALID_ERROR);
	CHECK(bc3_ztex_io_read_selected(&ops, 0, NULL, 64, 1) ==
		BC3_ZTEX_IO_INVALID_ERROR);
}

static void run_pair_fault(int fault_call, int fault_rc, bool delivered)
{
	struct mock_io mock;
	struct bc3_ztex_io_ops ops;
	uint8_t frames[2][BC3_ZTEX_WORK_FRAME_SIZE];
	uint8_t frozen[sizeof(frames)];
	unsigned failed_fragment = 99;
	int error_code = 0;

	memset(&mock, 0, sizeof(mock));
	build_frames(frames);
	memcpy(frozen, frames, sizeof(frozen));
	mock.fault_send_call = fault_call;
	mock.fault_send_rc = fault_rc;
	mock.deliver_faulted_send = delivered;
	ops = make_ops(&mock);
	CHECK(!bc3_ztex_io_send_work_pair(&ops, 2, &frames[0][0], 500,
		&failed_fragment, &error_code));
	CHECK(failed_fragment == (unsigned)(fault_call - 1));
	CHECK(error_code == (fault_rc < 0 ? fault_rc :
		BC3_ZTEX_IO_SHORT_ERROR));
	CHECK(memcmp(frames, frozen, sizeof(frames)) == 0);

	/* Clear only the one-shot transport fault.  A retry must begin with
	 * fragment zero even when the ambiguous failed call reached hardware. */
	mock.fault_send_call = 0;
	mock.event_count = 0;
	CHECK(bc3_ztex_io_send_work_pair(&ops, 2, &frames[0][0], 500,
		&failed_fragment, &error_code));
	CHECK(failed_fragment == 2 && error_code == 0);
	CHECK(mock.event_count == 4 &&
		memcmp(mock.events, "LSLS", 4) == 0);
	CHECK(mock.selects == mock.sends);
	CHECK(mock.activations == 1);
	CHECK(mock.committed_session == UINT32_C(0x11112222) &&
		mock.committed_epoch == UINT32_C(9));
	CHECK(memcmp(frames, frozen, sizeof(frames)) == 0);
}

static void test_work_pair_retries(void)
{
	/* Negative error means undelivered in this model; positive shorts are
	 * exercised both undelivered and ambiguously fully delivered. */
	run_pair_fault(1, -7, false);
	run_pair_fault(2, -7, false);
	run_pair_fault(1, 31, false);
	run_pair_fault(2, 31, false);
	run_pair_fault(1, 31, true);
	run_pair_fault(2, 31, true);
}

int main(void)
{
	test_selected_exact_io();
	test_work_pair_retries();
	if (failures != 0) {
		fprintf(stderr, "FAIL: %u/%u BC3 ZTEX I/O checks failed\n",
			failures, checks);
		return 1;
	}
	printf("PASS: %u BC3 ZTEX I/O checks (select-every-transfer, exact length, immutable whole-pair retry)\n",
		checks);
	return 0;
}
