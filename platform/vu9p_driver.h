/* vu9p_driver.h - what an algorithm must provide to mine on a VU9P board.
 *
 * The miner thread (vu9p_miner_thread in fpga-miner.c) is algorithm-agnostic:
 * it hands the current stratum work to the driver, polls it for verified
 * results, submits them, and keeps the statistics / thermal guard.  Each
 * bitstream family ships one driver that knows its register map.
 */
#ifndef VU9P_DRIVER_H
#define VU9P_DRIVER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "vu9p_bridge.h"

struct work;
struct thr_info;

typedef int (*vu9p_submit_fn)(void *ctx, struct work *w);

/* Work ownership helpers provided by fpga-miner.c (deep copies of every owned field). */
bool vu9p_work_clone(struct work *dest, const struct work *src);
void vu9p_work_release(struct work *w);

struct vu9p_algo_driver {
	const char *name;
	uint32_t    build_id_addr;                   /* register holding the bitstream's build id */
	uint32_t    build_id_mask, build_id_value;   /* identifies the bitstream family; mask 0 = no check */

	/* Called once after the bridge is connected: read the bitstream's
	 * parameters, allocate dev->algo_state.  0 = ok. */
	int (*open)(struct vu9p_dev *d);

	/* Load a job and start searching.  0 = running, 1 = job not minable by
	 * this core (skip, stay idle), <0 = bridge error. */
	int (*start)(struct vu9p_dev *d, const struct work *w);

	/* Stop the search (idempotent). */
	int (*stop)(struct vu9p_dev *d);

	/* Read back results; every verified share is passed to submit(ctx, w)
	 * with the solution filled into a copy of w.  Hardware errors count in
	 * d->hw_errors.  Returns number of results handled or <0. */
	int (*poll)(struct vu9p_dev *d, const struct work *w, vu9p_submit_fn submit, void *ctx);

	/* Attempts done since start (for the hash-rate display). */
	int (*hashes)(struct vu9p_dev *d, uint64_t *done);

	/* 1 when the job cannot produce valid shares any more (pool ttl). */
	int (*work_expired)(const struct work *w);

	/* 1 when the nonce space of the current work is used up and fresh work
	 * (next extranonce2) is needed; NULL when the core never runs out. */
	int (*exhausted)(struct vu9p_dev *d);

	/* Built-in test against the known-answer vectors.  0 = pass. */
	int (*selftest)(struct vu9p_dev *d);

	/* One-line status for the periodic log. */
	void (*status)(struct vu9p_dev *d, char *buf, size_t len);
};

extern const struct vu9p_algo_driver vu9p_proxima_driver;
extern const struct vu9p_algo_driver vu9p_sha3t_driver;

/* Tunables the drivers may read (set from the command line). */
extern int    opt_vu9p_kmin;     /* minimum hardware difficulty (hit-rate limiter) */
extern double opt_vu9p_tmax;     /* thermal guard: stop above, resume 5 C below */

#endif /* VU9P_DRIVER_H */
