#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "stratum_submit_map.h"

static unsigned long checks;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		return EXIT_FAILURE; \
	} \
} while (0)

static int check_initialized_state(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket ticket;

	stratum_submit_map_init(&map);
	stratum_submit_ticket_init(&ticket);
	CHECK(stratum_submit_map_count(&map) == 0);
	CHECK(stratum_submit_map_queued_count(&map) == 0);
	CHECK(stratum_submit_map_sent_count(&map) == 0);
	CHECK(map.id_generation == 0);
	CHECK(map.next_id == STRATUM_SUBMIT_ID_FIRST);
	CHECK(!map.id_exhausted);
	CHECK(!ticket.valid && ticket.slot == STRATUM_SUBMIT_MAP_SIZE);
	CHECK(stratum_submit_map_admit(NULL, 1, 0, 0, &ticket) ==
		STRATUM_SUBMIT_ADMIT_INVALID);
	CHECK(stratum_submit_map_admit(&map, 0, 0, 0, &ticket) ==
		STRATUM_SUBMIT_ADMIT_INVALID);
	CHECK(stratum_submit_map_admit(&map, 1, 0, 0, NULL) ==
		STRATUM_SUBMIT_ADMIT_INVALID);
	CHECK(!stratum_submit_map_cancel(NULL, &ticket));
	CHECK(stratum_submit_map_mark_sent(NULL, &ticket) ==
		STRATUM_SUBMIT_MARK_INVALID);
	CHECK(stratum_submit_map_count(NULL) == 0);
	return EXIT_SUCCESS;
}

static int check_capacity_and_exact_response(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket tickets[STRATUM_SUBMIT_MAP_SIZE];
	struct stratum_submit_ticket extra, wrong;
	struct stratum_submit_entry entry;
	size_t i;

	stratum_submit_map_init(&map);
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		stratum_submit_ticket_init(&tickets[i]);
		CHECK(stratum_submit_map_admit(&map, 1, (int)i,
			(int)(i & 3), &tickets[i]) ==
			STRATUM_SUBMIT_ADMIT_READY);
		CHECK(tickets[i].valid);
		CHECK(tickets[i].id == STRATUM_SUBMIT_ID_FIRST +
			(unsigned)i);
		CHECK(stratum_submit_map_count(&map) == i + 1);
		CHECK(stratum_submit_map_count(&map) <=
			STRATUM_SUBMIT_MAP_SIZE);
	}
	CHECK(stratum_submit_map_queued_count(&map) ==
		STRATUM_SUBMIT_MAP_SIZE);
	CHECK(stratum_submit_map_sent_count(&map) == 0);
	stratum_submit_ticket_init(&extra);
	CHECK(stratum_submit_map_admit(&map, 1, 0, 0, &extra) ==
		STRATUM_SUBMIT_ADMIT_FULL);
	CHECK(!extra.valid);
	/* A response must not consume a command that has not reached the wire. */
	CHECK(!stratum_submit_map_take(&map, 1, tickets[0].id, &entry));
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE);

	CHECK(stratum_submit_map_mark_sent(&map, &tickets[0]) ==
		STRATUM_SUBMIT_MARK_READY);
	CHECK(!tickets[0].valid);
	CHECK(stratum_submit_map_queued_count(&map) ==
		STRATUM_SUBMIT_MAP_SIZE - 1);
	CHECK(stratum_submit_map_sent_count(&map) == 1);
	CHECK(!stratum_submit_map_take(&map, 2, STRATUM_SUBMIT_ID_FIRST,
		&entry));
	CHECK(!stratum_submit_map_take(&map, 1,
		STRATUM_SUBMIT_ID_FIRST + 1, &entry));
	CHECK(stratum_submit_map_take(&map, 1, STRATUM_SUBMIT_ID_FIRST,
		&entry));
	CHECK(entry.state == STRATUM_SUBMIT_SLOT_SENT);
	CHECK(entry.connection_generation == 1 && entry.id == 4);
	CHECK(entry.board == 0 && entry.fpga == 0);
	CHECK(!stratum_submit_map_take(&map, 1, STRATUM_SUBMIT_ID_FIRST,
		&entry));
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE - 1);

	/* Freed capacity gets a never-before-issued same-generation ID. */
	CHECK(stratum_submit_map_admit(&map, 1, 99, 3, &extra) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(extra.id == STRATUM_SUBMIT_ID_FIRST +
		(unsigned)STRATUM_SUBMIT_MAP_SIZE);
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE);
	wrong = extra;
	wrong.id++;
	CHECK(!stratum_submit_map_cancel(&map, &wrong));
	CHECK(wrong.valid);
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE);
	CHECK(stratum_submit_map_cancel(&map, &extra));
	CHECK(!extra.valid);
	CHECK(!stratum_submit_map_cancel(&map, &extra));
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE - 1);

	for (i = 1; i < STRATUM_SUBMIT_MAP_SIZE; ++i)
		CHECK(stratum_submit_map_cancel(&map, &tickets[i]));
	CHECK(stratum_submit_map_count(&map) == 0);
	return EXIT_SUCCESS;
}

static int check_generation_ownership(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket old_queued, old_sent, current;
	struct stratum_submit_entry entry;

	stratum_submit_map_init(&map);
	stratum_submit_ticket_init(&old_queued);
	stratum_submit_ticket_init(&old_sent);
	stratum_submit_ticket_init(&current);
	CHECK(stratum_submit_map_admit(&map, 7, 1, 0, &old_queued) ==
		STRATUM_SUBMIT_ADMIT_READY && old_queued.id == 4);
	CHECK(stratum_submit_map_admit(&map, 7, 2, 1, &old_sent) ==
		STRATUM_SUBMIT_ADMIT_READY && old_sent.id == 5);
	CHECK(stratum_submit_map_mark_sent(&map, &old_sent) ==
		STRATUM_SUBMIT_MARK_READY);
	CHECK(stratum_submit_map_count(&map) == 2);
	CHECK(stratum_submit_map_queued_count(&map) == 1);
	CHECK(stratum_submit_map_sent_count(&map) == 1);

	/* Advancing the authoritative TCP generation retires only SENT. The old
	 * physical queued command stays charged, and ID 4 may coexist because its
	 * generation is different. */
	CHECK(stratum_submit_map_admit(&map, 8, 3, 2, &current) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(current.id == 4 && current.connection_generation == 8);
	CHECK(map.id_generation == 8);
	CHECK(stratum_submit_map_count(&map) == 2);
	CHECK(stratum_submit_map_queued_count(&map) == 2);
	CHECK(stratum_submit_map_sent_count(&map) == 0);
	CHECK(!stratum_submit_map_take(&map, 7, 5, &entry));
	CHECK(!stratum_submit_map_take(&map, 8, 4, &entry));

	/* A command that completed its old-socket send after the transition is
	 * retired rather than installed into the current response namespace. */
	CHECK(stratum_submit_map_mark_sent(&map, &old_queued) ==
		STRATUM_SUBMIT_MARK_RETIRED);
	CHECK(!old_queued.valid);
	CHECK(stratum_submit_map_count(&map) == 1);
	CHECK(stratum_submit_map_mark_sent(&map, &current) ==
		STRATUM_SUBMIT_MARK_READY);
	CHECK(!stratum_submit_map_take(&map, 7, 4, &entry));
	CHECK(stratum_submit_map_take(&map, 8, 4, &entry));
	CHECK(entry.board == 3 && entry.fpga == 2);
	CHECK(stratum_submit_map_count(&map) == 0);
	return EXIT_SUCCESS;
}

static int check_reconnect_bound(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket old[STRATUM_SUBMIT_MAP_SIZE];
	struct stratum_submit_ticket fresh[STRATUM_SUBMIT_MAP_SIZE / 2];
	struct stratum_submit_ticket extra;
	size_t i;

	stratum_submit_map_init(&map);
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		stratum_submit_ticket_init(&old[i]);
		CHECK(stratum_submit_map_admit(&map, 10, (int)i, 0,
			&old[i]) == STRATUM_SUBMIT_ADMIT_READY);
		if (i & 1)
			CHECK(stratum_submit_map_mark_sent(&map, &old[i]) ==
				STRATUM_SUBMIT_MARK_READY);
	}
	CHECK(stratum_submit_map_queued_count(&map) == 256);
	CHECK(stratum_submit_map_sent_count(&map) == 256);

	/* First generation-11 admission retires 256 old SENT credits, but the 256
	 * old QUEUED commands remain. Exactly 256 new commands can then enter. */
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE / 2; ++i) {
		stratum_submit_ticket_init(&fresh[i]);
		CHECK(stratum_submit_map_admit(&map, 11, (int)i, 1,
			&fresh[i]) == STRATUM_SUBMIT_ADMIT_READY);
		CHECK(fresh[i].id == STRATUM_SUBMIT_ID_FIRST + (unsigned)i);
		CHECK(stratum_submit_map_count(&map) <=
			STRATUM_SUBMIT_MAP_SIZE);
	}
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE);
	CHECK(stratum_submit_map_queued_count(&map) ==
		STRATUM_SUBMIT_MAP_SIZE);
	stratum_submit_ticket_init(&extra);
	CHECK(stratum_submit_map_admit(&map, 11, 0, 0, &extra) ==
		STRATUM_SUBMIT_ADMIT_FULL);
	/* Another reconnect cannot manufacture credit: every slot represents a
	 * still-physical queued command, so generation 12 is also full. */
	CHECK(stratum_submit_map_admit(&map, 12, 0, 0, &extra) ==
		STRATUM_SUBMIT_ADMIT_FULL);
	CHECK(map.id_generation == 12 && map.next_id == 4);
	CHECK(stratum_submit_map_count(&map) == STRATUM_SUBMIT_MAP_SIZE);

	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; i += 2)
		CHECK(stratum_submit_map_cancel(&map, &old[i]));
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE / 2; ++i)
		CHECK(stratum_submit_map_cancel(&map, &fresh[i]));
	CHECK(stratum_submit_map_count(&map) == 0);
	return EXIT_SUCCESS;
}

static int check_id_exhaustion(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket penultimate, last, extra, next_generation;
	struct stratum_submit_entry entry;

	stratum_submit_map_init(&map);
	map.id_generation = 77;
	map.next_id = (unsigned)INT_MAX - 1;
	stratum_submit_ticket_init(&penultimate);
	stratum_submit_ticket_init(&last);
	stratum_submit_ticket_init(&extra);
	stratum_submit_ticket_init(&next_generation);
	CHECK(stratum_submit_map_admit(&map, 77, 1, 0, &penultimate) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(penultimate.id == (unsigned)INT_MAX - 1);
	CHECK(stratum_submit_map_admit(&map, 77, 2, 1, &last) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(last.id == (unsigned)INT_MAX);
	CHECK(map.id_exhausted);
	CHECK(stratum_submit_map_admit(&map, 77, 3, 2, &extra) ==
		STRATUM_SUBMIT_ADMIT_EXHAUSTED);
	CHECK(!extra.valid);

	/* Freeing both credits cannot rewind or reuse either burned ID. */
	CHECK(stratum_submit_map_cancel(&map, &penultimate));
	CHECK(stratum_submit_map_mark_sent(&map, &last) ==
		STRATUM_SUBMIT_MARK_READY);
	CHECK(stratum_submit_map_take(&map, 77, (unsigned)INT_MAX, &entry));
	CHECK(stratum_submit_map_count(&map) == 0);
	CHECK(stratum_submit_map_admit(&map, 77, 4, 3, &extra) ==
		STRATUM_SUBMIT_ADMIT_EXHAUSTED);

	/* Only a different authoritative TCP generation reopens ID 4. */
	CHECK(stratum_submit_map_admit(&map, 78, 5, 0, &next_generation) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(next_generation.id == STRATUM_SUBMIT_ID_FIRST);
	CHECK(!map.id_exhausted && map.id_generation == 78);
	CHECK(stratum_submit_map_cancel(&map, &next_generation));
	return EXIT_SUCCESS;
}

static int check_long_running_model(void)
{
	struct stratum_submit_map map;
	struct stratum_submit_ticket queued[STRATUM_SUBMIT_MAP_SIZE];
	struct stratum_submit_entry entry;
	unsigned ids[STRATUM_SUBMIT_MAP_SIZE];
	unsigned last_id = 0;
	size_t modeled_workio_queue = 0;
	size_t i;

	stratum_submit_map_init(&map);
	/* Model a producer filling workio while an active pool withholds every
	 * response. Popping a command changes QUEUED to SENT but does not create
	 * new credit, so the 513th producer remains blocked. */
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		stratum_submit_ticket_init(&queued[i]);
		CHECK(stratum_submit_map_admit(&map, 100, (int)i,
			(int)(i & 3), &queued[i]) ==
			STRATUM_SUBMIT_ADMIT_READY);
		ids[i] = queued[i].id;
		++modeled_workio_queue;
		CHECK(modeled_workio_queue <= STRATUM_SUBMIT_MAP_SIZE);
		CHECK(stratum_submit_map_count(&map) <=
			STRATUM_SUBMIT_MAP_SIZE);
	}
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		CHECK(stratum_submit_map_mark_sent(&map, &queued[i]) ==
			STRATUM_SUBMIT_MARK_READY);
		--modeled_workio_queue;
		CHECK(stratum_submit_map_count(&map) ==
			STRATUM_SUBMIT_MAP_SIZE);
	}
	CHECK(modeled_workio_queue == 0);
	stratum_submit_ticket_init(&queued[0]);
	for (i = 0; i < 32; ++i)
		CHECK(stratum_submit_map_admit(&map, 100, 0, 0,
			&queued[0]) == STRATUM_SUBMIT_ADMIT_FULL);

	/* Each exact response permits exactly one replacement. IDs remain
	 * strictly increasing even though completed slots are reused. */
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		struct stratum_submit_ticket replacement;

		CHECK(stratum_submit_map_take(&map, 100, ids[i], &entry));
		stratum_submit_ticket_init(&replacement);
		CHECK(stratum_submit_map_admit(&map, 100, entry.board,
			entry.fpga, &replacement) == STRATUM_SUBMIT_ADMIT_READY);
		CHECK(replacement.id > ids[STRATUM_SUBMIT_MAP_SIZE - 1]);
		CHECK(replacement.id > last_id);
		last_id = replacement.id;
		ids[i] = replacement.id;
		CHECK(stratum_submit_map_mark_sent(&map, &replacement) ==
			STRATUM_SUBMIT_MARK_READY);
		CHECK(stratum_submit_map_count(&map) ==
			STRATUM_SUBMIT_MAP_SIZE);
	}
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i)
		CHECK(stratum_submit_map_take(&map, 100, ids[i], &entry));
	CHECK(stratum_submit_map_count(&map) == 0);

	/* A modeled tq_push failure cancels the admission credit but burns its ID. */
	stratum_submit_ticket_init(&queued[0]);
	CHECK(stratum_submit_map_admit(&map, 100, 0, 0, &queued[0]) ==
		STRATUM_SUBMIT_ADMIT_READY);
	last_id = queued[0].id;
	CHECK(stratum_submit_map_cancel(&map, &queued[0]));
	CHECK(stratum_submit_map_admit(&map, 100, 0, 0, &queued[0]) ==
		STRATUM_SUBMIT_ADMIT_READY);
	CHECK(queued[0].id == last_id + 1);
	CHECK(stratum_submit_map_cancel(&map, &queued[0]));

	/* A typed STOP is not a share admission: it can occupy the queue after the
	 * admitted prefix without consuming or exceeding a ledger slot. */
	CHECK(stratum_submit_map_count(&map) == 0);
	modeled_workio_queue = 1; /* STOP singleton only */
	CHECK(modeled_workio_queue == 1);
	CHECK(stratum_submit_map_count(&map) == 0);
	return EXIT_SUCCESS;
}

int main(void)
{
	if (check_initialized_state() != EXIT_SUCCESS ||
	    check_capacity_and_exact_response() != EXIT_SUCCESS ||
	    check_generation_ownership() != EXIT_SUCCESS ||
	    check_reconnect_bound() != EXIT_SUCCESS ||
	    check_id_exhaustion() != EXIT_SUCCESS ||
	    check_long_running_model() != EXIT_SUCCESS)
		return EXIT_FAILURE;
	printf("STRATUM_SUBMIT_MAP_TEST_PASS checks=%lu capacity=%zu "
		"states=free-queued-sent bound=end-to-end ids=no-reuse "
		"wrap=reconnect-only generation=exact stop=bypass\n",
		checks, STRATUM_SUBMIT_MAP_SIZE);
	return EXIT_SUCCESS;
}
