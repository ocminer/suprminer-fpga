/* vu9p_proxima.c - VU9P driver for the Proxima txid-blake2b "b2b" bitstream family.
 *
 * Register map of the b2b core (byte addresses, 32-bit words; job registers
 * are written with run = 0 only):
 *   0x000..0x07C  W  const[16]  final block, low word first
 *   0x080..0x0FC  W  M[16]      extranonce2 bit masks
 *   0x100..0x17C  W  vi[16]     initial compression state
 *   0x180/0x184   W  cv3 lo/hi
 *   0x188/0x18C   W  kmask lo/hi
 *   0x190         W  s1 (counter byte rotation)
 *   0x194/0x198   W  cnt_start lo / hi (8 bits)
 *   0x19C         W  gid_base: core i searches counters with gid = gid_base + i in bits 47:40
 *   0x200         RW ctrl: bit0 run, bit1 flush (self-clearing), bit2 load cfg chain
 *   0x204         R  status: bit0 run, bit1 hit available, bit2 cfg busy, bits 31:16 fifo count
 *   0x208         W  pop (write 1 to advance the hit FIFO)
 *   0x210/0x214   R  head: counter lo / {valid, 15'b0, counter hi 16}
 *   0x218/0x21C   R  head: h3 lo / hi
 *   0x220 R build id   0x224 R cores   0x228/0x22C R core0 counter lo/hi   0x230 R drops
 *   0x234 R core kHz   0x23C R bit0: cfg chain present
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "miner.h"
#include "proxima.h"
#include "vu9p_bridge.h"
#include "vu9p_driver.h"

#define R_JOB        0x000
#define R_CTRL       0x200
#define R_STATUS     0x204
#define R_POP        0x208
#define R_HEAD       0x210
#define R_BUILD_ID   0x220
#define R_NCORES     0x224
#define R_COUNTER    0x228
#define R_DROPS      0x230
#define R_CORE_KHZ   0x234
#define R_FEATURES   0x23C

#define CTRL_RUN     1
#define CTRL_FLUSH   2
#define CTRL_CFG     4
#define ST_HIT       2
#define ST_CFG_BUSY  4

#define GID_PER_DEVICE 32          /* gid = device index * 32 + core; cores per bitstream must stay <= 32 */
#define CNT40_MASK   0xFFFFFFFFFFULL

int    opt_vu9p_kmin = 27;
double opt_vu9p_tmax = 85.0;

struct proxi_state {
	uint32_t ncores, core_khz;
	int      has_cfg;
	uint32_t gid_base;
	struct proxi_job job;
	uint8_t *prefix;
	size_t   prefix_len;
	int      k_pool, k_hw;
	uint64_t cnt_at_load;
	int      running;
	uint64_t hits_total, submitted;
};

static int st_stop(struct vu9p_dev *d)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	if (s) s->running = 0;
	return vu9p_wr(d, R_CTRL, 0);
}

static int st_open(struct vu9p_dev *d)
{
	struct proxi_state *s = (struct proxi_state *) calloc(1, sizeof(*s));
	uint32_t feat = 0;
	if (!s) return -1;
	if (vu9p_rd(d, R_NCORES, &s->ncores) || vu9p_rd(d, R_CORE_KHZ, &s->core_khz)) { free(s); return -1; }
	if (vu9p_rd(d, R_FEATURES, &feat) == 0) s->has_cfg = feat & 1;
	if (s->ncores == 0 || s->ncores > GID_PER_DEVICE) {
		applog(LOG_ERR, "VU9P %d: bitstream reports %u cores (expected 1..%d)", d->index, s->ncores, GID_PER_DEVICE);
		free(s); return -1;
	}
	s->gid_base = (uint32_t) d->index * GID_PER_DEVICE;
	d->algo_state = s;
	applog(LOG_INFO, "VU9P %d: proxima b2b bitstream %08x: %u cores at %.1f MHz, nominal %.2f GH/s, gid base %u%s",
	       d->index, d->build_id, s->ncores, s->core_khz / 1000.0, s->ncores * s->core_khz / 1e6, s->gid_base,
	       s->has_cfg ? ", cfg chain" : "");
	return st_stop(d);
}

static int counter(struct vu9p_dev *d, uint64_t *c)
{
	uint32_t v[2];
	if (vu9p_rb(d, R_COUNTER, v, 2)) return -1;
	*c = ((uint64_t)(v[1] & 0xff) << 32) | v[0];
	return 0;
}

static int load_job(struct vu9p_dev *d, const struct proxi_job *j, uint64_t kmask, uint64_t cnt_start, uint32_t gid_base)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	uint32_t words[104];
	int i, n = 0;

	if (vu9p_wr(d, R_CTRL, CTRL_FLUSH) || vu9p_wr(d, R_CTRL, 0)) return -1;
	for (i = 0; i < 16; i++) { words[n++] = (uint32_t) j->cst[i]; words[n++] = (uint32_t)(j->cst[i] >> 32); }
	for (i = 0; i < 16; i++) { words[n++] = (uint32_t) j->M[i];   words[n++] = (uint32_t)(j->M[i] >> 32); }
	for (i = 0; i < 16; i++) { words[n++] = (uint32_t) j->vi[i];  words[n++] = (uint32_t)(j->vi[i] >> 32); }
	words[n++] = (uint32_t) j->cv[3]; words[n++] = (uint32_t)(j->cv[3] >> 32);
	words[n++] = (uint32_t) kmask;    words[n++] = (uint32_t)(kmask >> 32);
	words[n++] = (uint32_t) j->s1;
	words[n++] = (uint32_t) cnt_start; words[n++] = (uint32_t)((cnt_start >> 32) & 0xff);
	words[n++] = gid_base;
	if (vu9p_wb(d, R_JOB, words, n)) return -1;
	if (s->has_cfg) {
		uint32_t st; int t;
		if (vu9p_wr(d, R_CTRL, CTRL_CFG)) return -1;
		for (t = 0; t < 500; t++) {
			if (vu9p_rd(d, R_STATUS, &st)) return -1;
			if (!(st & ST_CFG_BUSY)) break;
			usleep(10000);
		}
		if (st & ST_CFG_BUSY) { applog(LOG_ERR, "VU9P %d: cfg chain load timeout", d->index); return -1; }
	}
	/* drain stale hits */
	for (i = 0; i < 4096; i++) {
		uint32_t st;
		if (vu9p_rd(d, R_STATUS, &st)) return -1;
		if (!(st & ST_HIT)) break;
		if (vu9p_wr(d, R_POP, 1)) return -1;
	}
	return vu9p_wr(d, R_CTRL, CTRL_RUN);
}

/* Pop up to max hits: (counter48, h3).  Returns count or <0. */
static int read_hits(struct vu9p_dev *d, uint64_t *c48, uint64_t *h3, int max)
{
	uint32_t st, v[4];
	int n = 0;
	if (vu9p_rd(d, R_STATUS, &st)) return -1;
	while ((st & ST_HIT) && n < max) {
		if (vu9p_rb(d, R_HEAD, v, 4)) return -1;
		if (!(v[1] >> 31)) break;
		c48[n] = ((uint64_t)(v[1] & 0xffff) << 32) | v[0];
		h3[n]  = ((uint64_t) v[3] << 32) | v[2];
		n++;
		if (vu9p_wr(d, R_POP, 1)) return -1;
		if (vu9p_rd(d, R_STATUS, &st)) return -1;
	}
	return n;
}

static int st_start(struct vu9p_dev *d, const struct work *w)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	int k;

	if (!w->proxi_prefix || w->xnonce1_len != PROXI_EN1_LEN) {
		applog(LOG_ERR, "VU9P %d: work without proxima prefix/extranonce1", d->index);
		return -1;
	}
	if (w->proxi_k < 0) {
		/* never submit below the pool's difficulty: wait for mining.set_difficulty (2026-11-11 lesson: a dropped
		 * set_difficulty produced ~500 low-difficulty shares and a pool ban) */
		applog(LOG_WARNING, "VU9P %d: job %s: pool difficulty unknown yet, waiting for mining.set_difficulty", d->index, w->job_id);
		st_stop(d);
		return 1;
	}
	if (proxi_job_init(&s->job, w->proxi_prefix, w->proxi_prefix_len, w->xnonce1)) {
		applog(LOG_ERR, "VU9P %d: job %s: prefix too long (%zu)", d->index, w->job_id, w->proxi_prefix_len);
		return 1;
	}
	if (s->job.straddle) {
		applog(LOG_WARNING, "VU9P %d: job %s: nonce straddles a block boundary (prefix_len %zu %% 128 = %zu), skipped",
		       d->index, w->job_id, w->proxi_prefix_len, w->proxi_prefix_len % 128);
		st_stop(d);
		return 1;
	}
	free(s->prefix);
	s->prefix = (uint8_t *) malloc(w->proxi_prefix_len);
	memcpy(s->prefix, w->proxi_prefix, w->proxi_prefix_len);
	s->prefix_len = w->proxi_prefix_len;
	k = w->proxi_k;
	s->k_pool = k;
	s->k_hw = k > opt_vu9p_kmin ? k : opt_vu9p_kmin;
	s->cnt_at_load = 0;
	if (load_job(d, &s->job, proxi_kmask(s->k_hw), 0, s->gid_base)) return -1;
	s->running = 1;
	applog(LOG_INFO, "VU9P %d: job %s slot %u prefix_len %zu shape W=%d r=%d k_pool=%d k_hw=%d ttl=%.0fs%s",
	       d->index, w->job_id, w->proxi_slot, s->prefix_len, s->job.W, s->job.r, s->k_pool, s->k_hw, w->proxi_ttl,
	       w->proxi_clean ? " clean" : "");
	return 0;
}

static int st_poll(struct vu9p_dev *d, const struct work *w, vu9p_submit_fn submit, void *ctx)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	uint64_t c48[64], h3[64];
	int n, i;

	if (!s->running) return 0;
	n = read_hits(d, c48, h3, 64);
	if (n < 0) return -1;
	for (i = 0; i < n; i++) {
		uint8_t digest[32];
		int wb;
		proxi_hash_attempt(&s->job, s->prefix, c48[i], digest);
		wb = proxi_work_bits(digest);
		s->hits_total++;
		if (proxi_h3_of_digest(digest) != h3[i] || wb < s->k_hw) {
			d->hw_errors++;
			applog(LOG_ERR, "VU9P %d: HARDWARE ERROR counter %012llx fpga h3 %016llx host h3 %016llx work %d (hw_errors %llu)",
			       d->index, (unsigned long long) c48[i], (unsigned long long) h3[i],
			       (unsigned long long) proxi_h3_of_digest(digest), wb, (unsigned long long) d->hw_errors);
			continue;
		}
		{
			struct work sol;
			memset(&sol, 0, sizeof(sol));
			if (!vu9p_work_clone(&sol, w)) { applog(LOG_ERR, "VU9P %d: out of memory cloning work", d->index); continue; }
			sol.xnonce2_len = PROXI_EN2_LEN;
			sol.xnonce2 = (unsigned char *) realloc(sol.xnonce2, PROXI_EN2_LEN);
			proxi_en2_from_c48(c48[i], sol.xnonce2);
			memcpy(sol.proxi_hash, digest, 32);
			sol.dev_board = -1; sol.dev_fpga = -1;
			s->submitted++;
			applog(LOG_NOTICE, "VU9P %d: share job %s counter %012llx work %d (k_pool %d, k_hw %d)", d->index, w->job_id,
			       (unsigned long long) c48[i], wb, s->k_pool, s->k_hw);
			submit(ctx, &sol);
			vu9p_work_release(&sol);
		}
	}
	return n;
}

static int st_hashes(struct vu9p_dev *d, uint64_t *done)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	uint64_t c;
	if (!s->running) { *done = 0; return 0; }
	if (counter(d, &c)) return -1;
	*done = (c > s->cnt_at_load ? c - s->cnt_at_load : 0) * s->ncores;
	return 0;
}

static int st_expired(const struct work *w)
{
	struct timeval now;
	double age;
	if (w->proxi_ttl <= 0) return 0;
	gettimeofday(&now, NULL);
	age = (now.tv_sec - w->proxi_t0.tv_sec) + (now.tv_usec - w->proxi_t0.tv_usec) / 1e6;
	return age > w->proxi_ttl;
}

static void st_status(struct vu9p_dev *d, char *buf, size_t len)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	snprintf(buf, len, "hits %llu submitted %llu hw_errors %llu", (unsigned long long) s->hits_total,
	         (unsigned long long) s->submitted, (unsigned long long) d->hw_errors);
}

/* ---- self-test against the known-answer vectors (mirrors the host model test) */
static int st_selftest(struct vu9p_dev *d)
{
	struct proxi_state *s = (struct proxi_state *) d->algo_state;
	uint8_t prefix[PROXI_MAX_PREFIX], en1[2], en2[6], exp[32], digest[32];
	uint64_t c48[600], h3[600];
	int i, fails = 0, checked = 0, skipped = 0;
	struct proxi_job job;

	for (i = 0; i < proxi_nvectors; i++) {
		const struct proxi_vector *v = &proxi_vectors[i];
		uint64_t C; int n, k, bad = 0, first_ok = 0;
		proxi_vector_prefix(v, prefix);
		hex2bin(en1, v->en1_hex, 2); hex2bin(en2, v->en2_hex, 6); hex2bin(exp, v->hash_hex, 32);
		C = proxi_c48_from_en2(en2);
		if (proxi_job_init(&job, prefix, v->prefix_len, en1) || job.straddle) { skipped++; continue; }
		/* kmask 0: every attempt hits; the FIFO captures the first few hundred attempts, which must be
		 * C, C+1, ... per core, each with the right digest tail */
		if (load_job(d, &job, 0, C & CNT40_MASK, (uint32_t)(C >> 40))) return -1;
		usleep(20000);
		if (vu9p_wr(d, R_CTRL, 0)) return -1;
		usleep(20000);
		n = read_hits(d, c48, h3, 600);
		if (n <= 0) { applog(LOG_ERR, "selftest vector %d: no hits read back", i); fails++; continue; }
		for (k = 0; k < n; k++) {
			proxi_hash_attempt(&job, prefix, c48[k], digest);
			if (proxi_h3_of_digest(digest) != h3[k]) bad++;
			if (c48[k] == C && !memcmp(digest, exp, 32)) first_ok = 1;
			checked++;
		}
		if (bad || !first_ok) fails++;
		applog(bad || !first_ok ? LOG_ERR : LOG_INFO, "selftest vector %d (prefix_len %d): %d attempts read back, %d h3 mismatches, vector nonce %s",
		       i, v->prefix_len, n, bad, first_ok ? "OK" : "MISSING");
	}
	{	/* search test: k = 10 over a short window, the hit set must equal the host's */
		const struct proxi_vector *v = &proxi_vectors[0];
		int n, k, wrong = 0, missing = 0, gid;
		uint64_t cmax;
		proxi_vector_prefix(v, prefix); hex2bin(en1, v->en1_hex, 2);
		proxi_job_init(&job, prefix, v->prefix_len, en1);
		if (load_job(d, &job, proxi_kmask(10), 0, 0)) return -1;
		usleep(50000);
		if (vu9p_wr(d, R_CTRL, 0)) return -1;
		usleep(20000);
		n = read_hits(d, c48, h3, 600);
		if (counter(d, &cmax)) return -1;
		for (k = 0; k < n; k++) {
			proxi_hash_attempt(&job, prefix, c48[k], digest);
			if (proxi_work_bits(digest) < 10 || proxi_h3_of_digest(digest) != h3[k]) wrong++;
		}
		for (gid = 0; gid < (int)(s->ncores < 4 ? s->ncores : 4); gid++) {
			uint64_t top = 0, c;
			for (k = 0; k < n; k++) if ((int)(c48[k] >> 40) == gid && (c48[k] & CNT40_MASK) > top) top = c48[k] & CNT40_MASK;
			for (c = 0; c <= top; c++) {
				int found = 0;
				proxi_hash_attempt(&job, prefix, ((uint64_t) gid << 40) | c, digest);
				if (proxi_work_bits(digest) < 10) continue;
				for (k = 0; k < n; k++) if (c48[k] == (((uint64_t) gid << 40) | c)) { found = 1; break; }
				if (!found) missing++;
			}
		}
		applog(wrong || missing ? LOG_ERR : LOG_INFO, "selftest search k=10: %d hits, %d wrong, %d missing in the covered windows (cores 0-3), counter %llu",
		       n, wrong, missing, (unsigned long long) cmax);
		fails += (wrong > 0) + (missing > 0);
	}
	st_stop(d);
	applog(fails ? LOG_ERR : LOG_INFO, "VU9P %d: proxima SELFTEST %s: %d attempts verified against the host hash, %d failures, %d straddle vectors skipped",
	       d->index, fails ? "FAIL" : "PASS", checked, fails, skipped);
	return fails ? -1 : 0;
}

const struct vu9p_algo_driver vu9p_proxima_driver = {
	.name = "proxima",
	.build_id_addr = R_BUILD_ID, .build_id_mask = 0xFFFFF000, .build_id_value = 0x50B2B000,
	.open = st_open, .start = st_start, .stop = st_stop, .poll = st_poll, .hashes = st_hashes,
	.work_expired = st_expired, .exhausted = NULL, .selftest = st_selftest, .status = st_status,
};
