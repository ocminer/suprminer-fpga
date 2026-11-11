/* vu9p_sha3t.c - VU9P driver for the SHA3-256t (BC3) "bitstream #1" family,
 * spoken over the generic register bridge (platform/vu9p_bridge.tcl).
 *
 * Register map (byte addresses, 32-bit words):
 *   0x00..0x48  W  header words 0..18 (host word order, nonce word 19 is enumerated by the core)
 *   0x50        W  hash7 target (work.target[7])
 *   0x54        W  nonce base
 *   0x58        RW ctrl: bit0 run, bit1 flush
 *   0x5C        R  status: bit0 found
 *   0x60        R  found nonce        0x64 R found hash word 7
 *   0x68/0x6C   R  hashes done lo/hi  0x70 R last hash word 7
 *   0x74        R  build id (magic)   0x78 W  write 1 to clear "found"
 *
 * A 32-bit nonce space is exhausted in seconds on a VU9P, so the driver asks
 * the miner thread for fresh work (next extranonce2) once the core has done
 * opt_vu9p_epoch hashes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "vu9p_bridge.h"
#include "vu9p_driver.h"

#define R_HDR        0x00
#define R_TARGET     0x50
#define R_BASE       0x54
#define R_CTRL       0x58
#define R_STATUS     0x5C
#define R_NONCE      0x60
#define R_HASH7      0x64
#define R_DONE_LO    0x68
#define R_DONE_HI    0x6C
#define R_LAST7      0x70
#define R_BUILD_ID   0x74
#define R_CLEAR      0x78

#define CTRL_RUN     1
#define CTRL_FLUSH   2

uint64_t opt_vu9p_epoch = 0xFFFFFFFFULL;      /* hashes per work item before fresh work is requested */

struct sha3t_state {
	uint32_t data[20];
	uint32_t target[8];
	uint32_t htarg;
	int      running;
	uint64_t found_total, submitted;
};

static int s3_stop(struct vu9p_dev *d)
{
	struct sha3t_state *s = (struct sha3t_state *) d->algo_state;
	if (s) s->running = 0;
	return vu9p_wr(d, R_CTRL, 0);
}

static int s3_open(struct vu9p_dev *d)
{
	struct sha3t_state *s = (struct sha3t_state *) calloc(1, sizeof(*s));
	if (!s) return -1;
	d->algo_state = s;
	applog(LOG_INFO, "VU9P %d: sha3t bitstream %08x", d->index, d->build_id);
	return s3_stop(d);
}

static int s3_start(struct vu9p_dev *d, const struct work *w)
{
	struct sha3t_state *s = (struct sha3t_state *) d->algo_state;
	memcpy(s->data, w->data, sizeof(s->data));
	memcpy(s->target, w->target, sizeof(s->target));
	s->htarg = w->target[7];
	if (vu9p_wr(d, R_CTRL, CTRL_FLUSH) || vu9p_wr(d, R_CTRL, 0)) return -1;
	if (vu9p_wb(d, R_HDR, s->data, 19)) return -1;
	if (vu9p_wr(d, R_TARGET, s->htarg) || vu9p_wr(d, R_BASE, 0) || vu9p_wr(d, R_CLEAR, 1)) return -1;
	if (vu9p_wr(d, R_CTRL, CTRL_RUN)) return -1;
	s->running = 1;
	return 0;
}

static int s3_poll(struct vu9p_dev *d, const struct work *w, vu9p_submit_fn submit, void *ctx)
{
	struct sha3t_state *s = (struct sha3t_state *) d->algo_state;
	uint32_t st, nonce, h7, edata[20], hash[8];
	int k;

	if (!s->running) return 0;
	if (vu9p_rd(d, R_STATUS, &st)) return -1;
	if (!(st & 1)) return 0;
	if (vu9p_rd(d, R_NONCE, &nonce) || vu9p_rd(d, R_HASH7, &h7) || vu9p_wr(d, R_CLEAR, 1)) return -1;
	s->found_total++;
	for (k = 0; k < 19; k++) be32enc(&edata[k], s->data[k]);
	be32enc(&edata[19], nonce);
	sha3256t_hash(hash, edata);
	if (hash[7] != h7) {
		d->hw_errors++;
		applog(LOG_ERR, "VU9P %d: HARDWARE ERROR nonce %08x fpga hash7 %08x host %08x (hw_errors %llu)", d->index, nonce, h7,
		       hash[7], (unsigned long long) d->hw_errors);
		return 1;
	}
	if (hash[7] <= s->htarg && fulltest(hash, s->target)) {
		struct work sol;
		memset(&sol, 0, sizeof(sol));
		if (!vu9p_work_clone(&sol, w)) { applog(LOG_ERR, "VU9P %d: out of memory cloning work", d->index); return 1; }
		sol.data[19] = nonce;
		sol.dev_board = -1; sol.dev_fpga = -1;
		s->submitted++;
		applog(LOG_NOTICE, "VU9P %d: share nonce %08x hash7 %08x", d->index, nonce, h7);
		submit(ctx, &sol);
		vu9p_work_release(&sol);
	}
	return 1;
}

static int s3_hashes(struct vu9p_dev *d, uint64_t *done)
{
	uint32_t lo, hi;
	if (vu9p_rd(d, R_DONE_LO, &lo) || vu9p_rd(d, R_DONE_HI, &hi)) return -1;
	*done = ((uint64_t) hi << 32) | lo;
	return 0;
}

static int s3_exhausted(struct vu9p_dev *d)
{
	uint64_t done;
	if (s3_hashes(d, &done)) return 0;
	return done >= opt_vu9p_epoch;
}

static int s3_expired(const struct work *w) { (void) w; return 0; }

static int s3_selftest(struct vu9p_dev *d)
{
	applog(LOG_WARNING, "VU9P %d: sha3t has no built-in vector test yet; mine against a pool and watch hw_errors", d->index);
	return 0;
}

static void s3_status(struct vu9p_dev *d, char *buf, size_t len)
{
	struct sha3t_state *s = (struct sha3t_state *) d->algo_state;
	snprintf(buf, len, "found %llu submitted %llu hw_errors %llu", (unsigned long long) s->found_total,
	         (unsigned long long) s->submitted, (unsigned long long) d->hw_errors);
}

const struct vu9p_algo_driver vu9p_sha3t_driver = {
	.name = "sha3t",
	.build_id_addr = R_BUILD_ID, .build_id_mask = 0, .build_id_value = 0,
	.open = s3_open, .start = s3_start, .stop = s3_stop, .poll = s3_poll, .hashes = s3_hashes,
	.work_expired = s3_expired, .exhausted = s3_exhausted, .selftest = s3_selftest, .status = s3_status,
};
