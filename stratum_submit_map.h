#ifndef STRATUM_SUBMIT_MAP_H
#define STRATUM_SUBMIT_MAP_H

#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define STRATUM_SUBMIT_MAP_SIZE ((size_t)512)
#define STRATUM_SUBMIT_ID_FIRST ((unsigned)4)

/* A slot is the end-to-end admission credit for one standard-Stratum share.
 * QUEUED includes commands waiting in workio and the command currently being
 * encoded/sent. SENT includes requests written completely to the socket and
 * awaiting a terminal response. Thus QUEUED + SENT is globally bounded by
 * STRATUM_SUBMIT_MAP_SIZE, rather than bounding only the response map after
 * workio has already dequeued a command. */
enum stratum_submit_slot_state {
	STRATUM_SUBMIT_SLOT_FREE = 0,
	STRATUM_SUBMIT_SLOT_QUEUED,
	STRATUM_SUBMIT_SLOT_SENT
};

struct stratum_submit_entry {
	unsigned id;
	uint64_t connection_generation;
	int board;
	int fpga;
	enum stratum_submit_slot_state state;
};

/* Exact, move-only ownership token carried by a queued workio command.
 * Callers must initialize a ticket before first use and must not copy a valid
 * ticket. Every successful admission ends in exactly one of cancel(),
 * mark_sent(), or process termination. */
struct stratum_submit_ticket {
	size_t slot;
	unsigned id;
	uint64_t connection_generation;
	bool valid;
};

struct stratum_submit_map {
	struct stratum_submit_entry entries[STRATUM_SUBMIT_MAP_SIZE];
	/* ID allocation belongs to one authoritative TCP generation. It is reset
	 * only when admit() is called with a different, authoritatively current
	 * generation. */
	uint64_t id_generation;
	unsigned next_id;
	bool id_exhausted;
};

enum stratum_submit_admit_result {
	STRATUM_SUBMIT_ADMIT_INVALID = -2,
	STRATUM_SUBMIT_ADMIT_EXHAUSTED = -1,
	STRATUM_SUBMIT_ADMIT_FULL = 0,
	STRATUM_SUBMIT_ADMIT_READY = 1
};

enum stratum_submit_mark_result {
	STRATUM_SUBMIT_MARK_INVALID = -1,
	STRATUM_SUBMIT_MARK_RETIRED = 0,
	STRATUM_SUBMIT_MARK_READY = 1
};

static inline void stratum_submit_ticket_init(
	struct stratum_submit_ticket *ticket)
{
	if (!ticket)
		return;
	ticket->slot = STRATUM_SUBMIT_MAP_SIZE;
	ticket->id = 0;
	ticket->connection_generation = 0;
	ticket->valid = false;
}

static inline void stratum_submit_map_init(struct stratum_submit_map *map)
{
	size_t i;

	if (!map)
		return;
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		map->entries[i].id = 0;
		map->entries[i].connection_generation = 0;
		map->entries[i].board = 0;
		map->entries[i].fpga = 0;
		map->entries[i].state = STRATUM_SUBMIT_SLOT_FREE;
	}
	map->id_generation = 0;
	map->next_id = STRATUM_SUBMIT_ID_FIRST;
	map->id_exhausted = false;
}

static inline void stratum_submit_map_clear_entry(
	struct stratum_submit_entry *entry)
{
	if (!entry)
		return;
	entry->id = 0;
	entry->connection_generation = 0;
	entry->board = 0;
	entry->fpga = 0;
	entry->state = STRATUM_SUBMIT_SLOT_FREE;
}

static inline size_t stratum_submit_map_count_state(
	const struct stratum_submit_map *map,
	enum stratum_submit_slot_state state)
{
	size_t i, count = 0;

	if (!map)
		return 0;
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i)
		if (map->entries[i].state == state)
			++count;
	return count;
}

static inline size_t stratum_submit_map_count(
	const struct stratum_submit_map *map)
{
	return stratum_submit_map_count_state(map,
		STRATUM_SUBMIT_SLOT_QUEUED) +
		stratum_submit_map_count_state(map, STRATUM_SUBMIT_SLOT_SENT);
}

static inline size_t stratum_submit_map_queued_count(
	const struct stratum_submit_map *map)
{
	return stratum_submit_map_count_state(map,
		STRATUM_SUBMIT_SLOT_QUEUED);
}

static inline size_t stratum_submit_map_sent_count(
	const struct stratum_submit_map *map)
{
	return stratum_submit_map_count_state(map, STRATUM_SUBMIT_SLOT_SENT);
}

/* Advance the ID namespace to an authoritatively current TCP generation.
 * Requests SENT on the retired socket can no longer receive a response and
 * release their credits here. Old QUEUED commands remain charged until the
 * physical workio command is dequeued and canceled; dropping those credits
 * here would permit another 512 queued commands on every reconnect. */
static inline size_t stratum_submit_map_begin_generation(
	struct stratum_submit_map *map, uint64_t connection_generation)
{
	size_t i, retired = 0;

	if (!map || !connection_generation ||
	    map->id_generation == connection_generation)
		return 0;
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		if (map->entries[i].state != STRATUM_SUBMIT_SLOT_SENT)
			continue;
		stratum_submit_map_clear_entry(&map->entries[i]);
		++retired;
	}
	map->id_generation = connection_generation;
	map->next_id = STRATUM_SUBMIT_ID_FIRST;
	map->id_exhausted = false;
	return retired;
}

/* Caller serializes access and must hold whatever transport lock proves that
 * connection_generation is the currently authenticated TCP generation. */
static inline enum stratum_submit_admit_result stratum_submit_map_admit(
	struct stratum_submit_map *map, uint64_t connection_generation,
	int board, int fpga, struct stratum_submit_ticket *ticket)
{
	size_t i, free_slot = STRATUM_SUBMIT_MAP_SIZE;
	unsigned id;

	if (!map || !connection_generation || !ticket || ticket->valid)
		return STRATUM_SUBMIT_ADMIT_INVALID;
	stratum_submit_ticket_init(ticket);
	(void)stratum_submit_map_begin_generation(map,
		connection_generation);
	if (map->id_exhausted)
		return STRATUM_SUBMIT_ADMIT_EXHAUSTED;
	if (map->next_id < STRATUM_SUBMIT_ID_FIRST ||
	    map->next_id > (unsigned)INT_MAX)
		return STRATUM_SUBMIT_ADMIT_INVALID;
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i)
		if (map->entries[i].state == STRATUM_SUBMIT_SLOT_FREE) {
			free_slot = i;
			break;
		}
	if (free_slot == STRATUM_SUBMIT_MAP_SIZE)
		return STRATUM_SUBMIT_ADMIT_FULL;

	id = map->next_id;
	map->entries[free_slot].id = id;
	map->entries[free_slot].connection_generation =
		connection_generation;
	map->entries[free_slot].board = board;
	map->entries[free_slot].fpga = fpga;
	map->entries[free_slot].state = STRATUM_SUBMIT_SLOT_QUEUED;
	if (id == (unsigned)INT_MAX)
		map->id_exhausted = true;
	else
		map->next_id = id + 1;

	ticket->slot = free_slot;
	ticket->id = id;
	ticket->connection_generation = connection_generation;
	ticket->valid = true;
	return STRATUM_SUBMIT_ADMIT_READY;
}

static inline bool stratum_submit_map_ticket_matches(
	const struct stratum_submit_map *map,
	const struct stratum_submit_ticket *ticket,
	enum stratum_submit_slot_state state)
{
	const struct stratum_submit_entry *entry;

	if (!map || !ticket || !ticket->valid ||
	    ticket->slot >= STRATUM_SUBMIT_MAP_SIZE)
		return false;
	entry = &map->entries[ticket->slot];
	return entry->state == state && entry->id == ticket->id &&
		entry->connection_generation == ticket->connection_generation;
}

/* Cancel only a command that still owns a QUEUED credit. */
static inline bool stratum_submit_map_cancel(struct stratum_submit_map *map,
	struct stratum_submit_ticket *ticket)
{
	if (!stratum_submit_map_ticket_matches(map, ticket,
		    STRATUM_SUBMIT_SLOT_QUEUED))
		return false;
	stratum_submit_map_clear_entry(&map->entries[ticket->slot]);
	stratum_submit_ticket_init(ticket);
	return true;
}

/* Transfer ownership from the workio command to the response ledger after an
 * exact complete wire send. If a newer TCP generation was admitted while
 * the old send completed, the retired socket cannot produce a usable response
 * and the obsolete credit is released instead. */
static inline enum stratum_submit_mark_result stratum_submit_map_mark_sent(
	struct stratum_submit_map *map, struct stratum_submit_ticket *ticket)
{
	if (!stratum_submit_map_ticket_matches(map, ticket,
		    STRATUM_SUBMIT_SLOT_QUEUED))
		return STRATUM_SUBMIT_MARK_INVALID;
	if (ticket->connection_generation != map->id_generation) {
		stratum_submit_map_clear_entry(&map->entries[ticket->slot]);
		stratum_submit_ticket_init(ticket);
		return STRATUM_SUBMIT_MARK_RETIRED;
	}
	map->entries[ticket->slot].state = STRATUM_SUBMIT_SLOT_SENT;
	stratum_submit_ticket_init(ticket);
	return STRATUM_SUBMIT_MARK_READY;
}

/* Consume one terminal response from the exact socket generation. QUEUED
 * slots deliberately do not match, so a guessed or premature response cannot
 * release an unsent workio command's admission credit. */
static inline bool stratum_submit_map_take(struct stratum_submit_map *map,
	uint64_t connection_generation, unsigned id,
	struct stratum_submit_entry *entry)
{
	size_t i, found = STRATUM_SUBMIT_MAP_SIZE;

	if (!map || !connection_generation || id < STRATUM_SUBMIT_ID_FIRST ||
	    id > (unsigned)INT_MAX || !entry)
		return false;
	for (i = 0; i < STRATUM_SUBMIT_MAP_SIZE; ++i) {
		if (map->entries[i].state != STRATUM_SUBMIT_SLOT_SENT ||
		    map->entries[i].connection_generation !=
			    connection_generation ||
		    map->entries[i].id != id)
			continue;
		/* Duplicate SENT identities indicate ledger corruption. Fail without
		 * mutating either slot so the caller can poison the connection. */
		if (found != STRATUM_SUBMIT_MAP_SIZE)
			return false;
		found = i;
	}
	if (found == STRATUM_SUBMIT_MAP_SIZE)
		return false;
	*entry = map->entries[found];
	stratum_submit_map_clear_entry(&map->entries[found]);
	return true;
}

#endif
