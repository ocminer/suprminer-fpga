/* ztex_proxima.c - ZTEX USB-FPGA 1.15y driver for the Proxima txid-blake2b "b2b" bitstream family.
 *
 * Transport (same FX2 firmware and EP0 vendor requests as every other ZTEX image, see libztex.c):
 *   VR 0x51 select FPGA    the four FPGAs of a board share read/write/rd_clk/wr_clk/wr_start, so every
 *                          transaction selects its FPGA first and holds the board lock meanwhile
 *   VR 0x80 send bytes     job frame, 408 bytes in <= 64-byte packets (the FPGA counts bytes across packets;
 *                          a select edge or ~84 ms idle resets the byte counter)
 *   VR 0x81 read 16 bytes  one record: a hit (valid=1) popped from the FPGA's hit FIFO, or the status
 *                          record (valid=0) when the FIFO is empty
 *
 * Job frame (little-endian fields):
 *   0 cst[16] | 128 M[16] | 256 vi[16] | 384 cv3 | 392 kmask | 400 s1 | 401..405 cnt_start (40 bits)
 *   406 gid_base | 407 ctrl: bit0 run, bit1 flush
 * Record:
 *   hit:    [0..5] counter48 (gid in bits 47:40) | [6..13] h3 | [14] flags | [15] 0xB2
 *   status: [0..4] core0 counter | [5] gid_base | [6..9] build id | [10..12] core kHz | [13] cores | [14] | [15] 0xB2
 *   flags:  bit7 valid (hit record), bit6 run, bits 5:0 FIFO count
 * The attempt counter restarts at cnt_start with every frame; hashes done = (counter - cnt_start) * cores.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <libusb.h>

#include "miner.h"
#include "proxima.h"
#include "libztex.h"
#include "vu9p_bridge.h"
#include "vu9p_driver.h"

#define ZB2B_FRAME_BYTES  408
#define ZB2B_MAGIC        0xB2
#define ZB2B_CTRL_RUN     1
#define ZB2B_CTRL_FLUSH   2
#define ZB2B_CNT40_MASK   0xFFFFFFFFFFULL
#define ZB2B_READ_TRIES   3
#define ZB2B_SEND_TIMEOUT 2000
#define ZB2B_READ_TIMEOUT 1000

struct zb2b_state {
	uint32_t build_id, core_khz, ncores;
	uint32_t gid_base;
	struct proxi_job job;
	uint8_t *prefix;
	size_t   prefix_len;
	int      k_pool, k_hw;
	int      running;
	int      have_frame;
	uint8_t  frame[ZB2B_FRAME_BYTES];
	uint64_t cnt;                 /* last counter seen in a status record */
	uint64_t cnt_at_load;
	uint64_t hits_total, submitted, bad_records, usb_errors, short_reads;
	int      consecutive_errors;
	time_t   last_err_log;
};

static uint32_t g_gid_next = 0;    /* gid allocation across the devices of this process (8 bits on the wire) */

/* The FX2 answers a VR 0x81 issued right after the previous EP0 transaction with a short/empty reply now and
 * then, and the FPGA has already popped the record by then (lost hit).  Pacing the bus of each board to one
 * transaction per ZB2B_BUS_GAP_US makes those short replies disappear (the Python host was naturally that slow). */
#define ZB2B_BUS_GAP_US 1000
struct zb2b_bus { pthread_mutex_t *lock; uint64_t last_us; };
static struct zb2b_bus g_bus[VU9P_MAX_DEVICES];
static int g_nbus = 0;
static pthread_mutex_t g_bus_table_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_us(void) { struct timeval tv; gettimeofday(&tv, NULL); return (uint64_t) tv.tv_sec * 1000000ULL + tv.tv_usec; }

static struct zb2b_bus *bus_of(struct vu9p_dev *d)
{
	int i;
	pthread_mutex_lock(&g_bus_table_lock);
	for (i = 0; i < g_nbus; i++) if (g_bus[i].lock == d->bus_lock) break;
	if (i == g_nbus && g_nbus < VU9P_MAX_DEVICES) { g_bus[g_nbus].lock = d->bus_lock; g_bus[g_nbus].last_us = 0; g_nbus++; }
	pthread_mutex_unlock(&g_bus_table_lock);
	return i < g_nbus ? &g_bus[i] : NULL;
}

/* call with the board lock held, before each USB transaction of the board */
static void bus_pace(struct zb2b_bus *b)
{
	uint64_t t;
	if (!b) return;
	t = now_us();
	if (t < b->last_us + ZB2B_BUS_GAP_US) usleep((useconds_t)(b->last_us + ZB2B_BUS_GAP_US - t));
}
static void bus_done(struct zb2b_bus *b) { if (b) b->last_us = now_us(); }

static struct zb2b_state *ST(struct vu9p_dev *d) { return (struct zb2b_state *) d->algo_state; }

static void err_log(struct vu9p_dev *d, const char *what, int rc)
{
	struct zb2b_state *s = ST(d);
	time_t now = time(NULL);
	s->usb_errors++;
	s->consecutive_errors++;
	if (now != s->last_err_log || s->consecutive_errors < 3) {
		applog(LOG_ERR, "%s: USB %s failed (%d%s%s), %d consecutive, %llu total", d->label, what, rc,
		       rc < 0 && rc != LIBZTEX_ERROR_SHORT_TRANSFER ? ": " : "",
		       rc < 0 && rc != LIBZTEX_ERROR_SHORT_TRANSFER ? libusb_error_name(rc) : "",
		       s->consecutive_errors, (unsigned long long) s->usb_errors);
		s->last_err_log = now;
	}
	/* never spin on a dead board: the miner thread retries immediately after an error */
	nmsleep(s->consecutive_errors > 20 ? 1000 : 50);
}

/* Select this FPGA and read one 16-byte record.  Board lock held for the whole transaction. */
static int zb2b_read_record(struct vu9p_dev *d, uint8_t rec[16])
{
	struct libztex_device *z = (struct libztex_device *) d->ztex;
	int rc = -1, t;

	struct zb2b_bus *bus = bus_of(d);
	pthread_mutex_lock(d->bus_lock);
	for (t = 0; t < ZB2B_READ_TRIES; t++) {
		bus_pace(bus);
		if (!libztex_selectFpga(z, d->ztex_fpga)) { bus_done(bus); rc = LIBUSB_ERROR_IO; usleep(10000); continue; }
		bus_done(bus); bus_pace(bus);
		rc = libztex_readFrameExact(z, rec, 16, ZB2B_READ_TIMEOUT);
		bus_done(bus);
		if (rc == 16) break;
		ST(d)->short_reads++;
		usleep(10000);      /* sporadic 0-byte EP0 replies on these FX2s: re-select and retry */
	}
	pthread_mutex_unlock(d->bus_lock);
	if (rc != 16) { err_log(d, "record read", rc); return -1; }
	if (rec[15] != ZB2B_MAGIC) {
		ST(d)->bad_records++;
		applog(LOG_ERR, "%s: bad record magic %02x (%llu bad records)", d->label, rec[15], (unsigned long long) ST(d)->bad_records);
		err_log(d, "record magic", 0);
		return -1;
	}
	ST(d)->consecutive_errors = 0;
	return 0;
}

static int zb2b_send_frame(struct vu9p_dev *d, const uint8_t *frame)
{
	struct libztex_device *z = (struct libztex_device *) d->ztex;
	int off = 0, rc = 0;

	struct zb2b_bus *bus = bus_of(d);
	pthread_mutex_lock(d->bus_lock);
	bus_pace(bus);
	if (!libztex_selectFpga(z, d->ztex_fpga)) rc = LIBUSB_ERROR_IO;
	bus_done(bus);
	while (rc >= 0 && off < ZB2B_FRAME_BYTES) {
		int len = ZB2B_FRAME_BYTES - off < 64 ? ZB2B_FRAME_BYTES - off : 64;
		bus_pace(bus);
		rc = libztex_sendFrameExact(z, frame + off, len, ZB2B_SEND_TIMEOUT);
		bus_done(bus);
		if (rc == len) off += len; else if (rc >= 0) rc = LIBZTEX_ERROR_SHORT_TRANSFER;
	}
	pthread_mutex_unlock(d->bus_lock);
	if (rc < 0) { err_log(d, "frame send", rc); return -1; }
	memcpy(ST(d)->frame, frame, ZB2B_FRAME_BYTES);
	ST(d)->have_frame = 1;
	ST(d)->consecutive_errors = 0;
	return 0;
}

static uint64_t le_u64(const uint8_t *p, int n)
{
	uint64_t v = 0; int i;
	for (i = n - 1; i >= 0; i--) v = (v << 8) | p[i];
	return v;
}
static void put_le(uint8_t *p, uint64_t v, int n)
{
	int i;
	for (i = 0; i < n; i++) { p[i] = (uint8_t) v; v >>= 8; }
}

/* Read records until the status record; hits (counter48, h3) go to c48/h3 (up to max).
 * Returns the number of hits, or <0 on a transport error.  Refreshes s->cnt. */
static int zb2b_read_hits(struct vu9p_dev *d, uint64_t *c48, uint64_t *h3, int max)
{
	struct zb2b_state *s = ST(d);
	uint8_t rec[16];
	int n = 0, i;

	for (i = 0; i <= max; i++) {
		if (zb2b_read_record(d, rec)) return -1;
		if (!(rec[14] & 0x80)) {                       /* status record: FIFO empty */
			s->cnt = le_u64(rec, 5);
			return n;
		}
		if (n < max) { c48[n] = le_u64(rec, 6); h3[n] = le_u64(rec + 6, 8); n++; }
	}
	return n;                                          /* FIFO still not empty: the caller polls again */
}

static int zb2b_status(struct vu9p_dev *d, uint8_t st[16])
{
	int i;
	for (i = 0; i < 4096; i++) {                       /* drain hits left by a previous miner */
		if (zb2b_read_record(d, st)) return -1;
		if (!(st[14] & 0x80)) return 0;
	}
	applog(LOG_ERR, "%s: no status record after draining 4096 hit records", d->label);
	return -1;
}

static int zb2b_stop(struct vu9p_dev *d)
{
	struct zb2b_state *s = ST(d);
	uint8_t fr[ZB2B_FRAME_BYTES];
	if (!s) return 0;
	s->running = 0;
	if (s->have_frame) memcpy(fr, s->frame, sizeof(fr)); else memset(fr, 0, sizeof(fr));
	fr[407] = 0;                                        /* run = 0: the core resets, the counter stops */
	return zb2b_send_frame(d, fr);
}

static int zb2b_open(struct vu9p_dev *d)
{
	struct zb2b_state *s = ST(d);
	uint8_t st[16];

	if (!s) {
		s = (struct zb2b_state *) calloc(1, sizeof(*s));
		if (!s) return -1;
		d->algo_state = s;
	}
	if (zb2b_status(d, st)) return -1;
	s->build_id = (uint32_t) le_u64(st + 6, 4);
	s->core_khz = (uint32_t) le_u64(st + 10, 3);
	s->ncores   = st[13];
	s->cnt      = le_u64(st, 5);
	d->build_id = s->build_id;
	if (s->ncores == 0 || s->core_khz == 0) {
		applog(LOG_ERR, "%s: implausible status record (cores %u, core kHz %u)", d->label, s->ncores, s->core_khz);
		return -1;
	}
	if (!s->have_frame) {                               /* first open: allocate the gid range of this device */
		if (g_gid_next + s->ncores > 256) {
			applog(LOG_ERR, "%s: gid space exhausted (%u cores already allocated in this process)", d->label, g_gid_next);
			return -1;
		}
		s->gid_base = g_gid_next;
		g_gid_next += s->ncores;
	}
	applog(LOG_INFO, "%s: proxima b2b bitstream %08x: %u core%s at %.2f MHz, nominal %.1f MH/s, gid base %u",
	       d->label, s->build_id, s->ncores, s->ncores == 1 ? "" : "s", s->core_khz / 1000.0,
	       s->ncores * s->core_khz / 1e3, s->gid_base);
	return 0;
}

static void zb2b_build_frame(uint8_t *fr, const struct proxi_job *j, uint64_t kmask, uint64_t cnt_start, uint32_t gid_base, int ctrl)
{
	int i;
	memset(fr, 0, ZB2B_FRAME_BYTES);
	for (i = 0; i < 16; i++) put_le(fr + 8 * i, j->cst[i], 8);
	for (i = 0; i < 16; i++) put_le(fr + 128 + 8 * i, j->M[i], 8);
	for (i = 0; i < 16; i++) put_le(fr + 256 + 8 * i, j->vi[i], 8);
	put_le(fr + 384, j->cv[3], 8);
	put_le(fr + 392, kmask, 8);
	fr[400] = (uint8_t)(j->s1 & 0x3f);
	put_le(fr + 401, cnt_start & ZB2B_CNT40_MASK, 5);
	fr[406] = (uint8_t) gid_base;
	fr[407] = (uint8_t) ctrl;
}

static int zb2b_load(struct vu9p_dev *d, const struct proxi_job *j, uint64_t kmask, uint64_t cnt_start, uint32_t gid_base)
{
	uint8_t fr[ZB2B_FRAME_BYTES];
	zb2b_build_frame(fr, j, kmask, cnt_start, gid_base, ZB2B_CTRL_RUN | ZB2B_CTRL_FLUSH);
	if (zb2b_send_frame(d, fr)) return -1;
	ST(d)->cnt_at_load = cnt_start & ZB2B_CNT40_MASK;
	ST(d)->cnt = ST(d)->cnt_at_load;
	return 0;
}

static int zb2b_start(struct vu9p_dev *d, const struct work *w)
{
	struct zb2b_state *s = ST(d);
	int k;

	if (!w->proxi_prefix || w->xnonce1_len != PROXI_EN1_LEN) {
		applog(LOG_ERR, "%s: work without proxima prefix/extranonce1", d->label);
		return -1;
	}
	if (w->proxi_k < 0) {
		applog(LOG_WARNING, "%s: job %s: pool difficulty unknown yet, waiting for mining.set_difficulty", d->label, w->job_id);
		zb2b_stop(d);
		return 1;
	}
	if (proxi_job_init(&s->job, w->proxi_prefix, w->proxi_prefix_len, w->xnonce1)) {
		applog(LOG_ERR, "%s: job %s: prefix too long (%zu)", d->label, w->job_id, w->proxi_prefix_len);
		return 1;
	}
	if (s->job.straddle) {
		applog(LOG_WARNING, "%s: job %s: nonce straddles a block boundary (prefix_len %zu %% 128 = %zu), skipped",
		       d->label, w->job_id, w->proxi_prefix_len, w->proxi_prefix_len % 128);
		zb2b_stop(d);
		return 1;
	}
	free(s->prefix);
	s->prefix = (uint8_t *) malloc(w->proxi_prefix_len);
	if (!s->prefix) return -1;
	memcpy(s->prefix, w->proxi_prefix, w->proxi_prefix_len);
	s->prefix_len = w->proxi_prefix_len;
	k = w->proxi_k;
	s->k_pool = k;
	s->k_hw = k > opt_vu9p_kmin ? k : opt_vu9p_kmin;
	if (zb2b_load(d, &s->job, proxi_kmask(s->k_hw), 0, s->gid_base)) return -1;
	s->running = 1;
	applog(LOG_INFO, "%s: job %s slot %u prefix_len %zu shape W=%d r=%d k_pool=%d k_hw=%d ttl=%.0fs%s",
	       d->label, w->job_id, w->proxi_slot, s->prefix_len, s->job.W, s->job.r, s->k_pool, s->k_hw, w->proxi_ttl,
	       w->proxi_clean ? " clean" : "");
	return 0;
}

static int zb2b_poll(struct vu9p_dev *d, const struct work *w, vu9p_submit_fn submit, void *ctx)
{
	struct zb2b_state *s = ST(d);
	uint64_t c48[128], h3[128];
	int n, i;

	if (!s->running) return 0;
	n = zb2b_read_hits(d, c48, h3, 128);
	if (n < 0) return -1;
	for (i = 0; i < n; i++) {
		uint8_t digest[32];
		int wb;
		struct work sol;
		proxi_hash_attempt(&s->job, s->prefix, c48[i], digest);
		wb = proxi_work_bits(digest);
		s->hits_total++;
		if (proxi_h3_of_digest(digest) != h3[i] || wb < s->k_hw) {
			d->hw_errors++;
			applog(LOG_ERR, "%s: HARDWARE ERROR counter %012llx fpga h3 %016llx host h3 %016llx work %d (hw_errors %llu)",
			       d->label, (unsigned long long) c48[i], (unsigned long long) h3[i],
			       (unsigned long long) proxi_h3_of_digest(digest), wb, (unsigned long long) d->hw_errors);
			continue;
		}
		if (wb < s->k_pool) continue;                   /* below pool difficulty (kmin < k_pool never happens, but be exact) */
		memset(&sol, 0, sizeof(sol));
		if (!vu9p_work_clone(&sol, w)) { applog(LOG_ERR, "%s: out of memory cloning work", d->label); continue; }
		sol.xnonce2_len = PROXI_EN2_LEN;
		sol.xnonce2 = (unsigned char *) realloc(sol.xnonce2, PROXI_EN2_LEN);
		proxi_en2_from_c48(c48[i], sol.xnonce2);
		memcpy(sol.proxi_hash, digest, 32);
		sol.dev_board = -1; sol.dev_fpga = -1;
		s->submitted++;
		applog(LOG_NOTICE, "%s: share job %s counter %012llx work %d (k_pool %d, k_hw %d)", d->label, w->job_id,
		       (unsigned long long) c48[i], wb, s->k_pool, s->k_hw);
		submit(ctx, &sol);
		vu9p_work_release(&sol);
	}
	return n;
}

static int zb2b_hashes(struct vu9p_dev *d, uint64_t *done)
{
	/* poll() reads to the status record every cycle and caches the counter there; reading again here could
	 * pop a hit record, so the cache (at most one poll interval old) is the right source */
	struct zb2b_state *s = ST(d);
	if (!s->running) { *done = 0; return 0; }
	*done = (s->cnt > s->cnt_at_load ? s->cnt - s->cnt_at_load : 0) * s->ncores;
	return 0;
}

static int zb2b_expired(const struct work *w)
{
	struct timeval now;
	double age;
	if (w->proxi_ttl <= 0) return 0;
	gettimeofday(&now, NULL);
	age = (now.tv_sec - w->proxi_t0.tv_sec) + (now.tv_usec - w->proxi_t0.tv_usec) / 1e6;
	return age > w->proxi_ttl;
}

static void zb2b_status_line(struct vu9p_dev *d, char *buf, size_t len)
{
	struct zb2b_state *s = ST(d);
	snprintf(buf, len, "hits %llu submitted %llu hw_errors %llu usb_errors %llu short_reads %llu", (unsigned long long) s->hits_total,
	         (unsigned long long) s->submitted, (unsigned long long) d->hw_errors, (unsigned long long) s->usb_errors,
	         (unsigned long long) s->short_reads);
}

/* ---- self-test against the known-answer vectors (same procedure as the VU9P driver / the Python host) */
static int zb2b_selftest(struct vu9p_dev *d)
{
	struct zb2b_state *s = ST(d);
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
		/* kmask 0: every attempt hits; the FIFO captures the first attempts, which must be C, C+1, ... per
		 * core, each with the right digest tail */
		if (zb2b_load(d, &job, 0, C & ZB2B_CNT40_MASK, (uint32_t)(C >> 40))) return -1;
		usleep(20000);
		if (zb2b_stop(d)) return -1;
		usleep(20000);
		n = zb2b_read_hits(d, c48, h3, 600);
		if (n <= 0) { applog(LOG_ERR, "%s: selftest vector %d: no hits read back", d->label, i); fails++; continue; }
		for (k = 0; k < n; k++) {
			proxi_hash_attempt(&job, prefix, c48[k], digest);
			if (proxi_h3_of_digest(digest) != h3[k]) bad++;
			if (c48[k] == C && !memcmp(digest, exp, 32)) first_ok = 1;
			checked++;
		}
		if (bad || !first_ok) fails++;
		applog(bad || !first_ok ? LOG_ERR : LOG_INFO, "%s: selftest vector %d (prefix_len %d): %d attempts read back, %d h3 mismatches, vector nonce %s",
		       d->label, i, v->prefix_len, n, bad, first_ok ? "OK" : "MISSING");
	}
	{	/* search test: k = 10 over a short window, the hit set must equal the host's */
		const struct proxi_vector *v = &proxi_vectors[0];
		int n, k, wrong = 0, missing = 0, gid;
		proxi_vector_prefix(v, prefix); hex2bin(en1, v->en1_hex, 2);
		proxi_job_init(&job, prefix, v->prefix_len, en1);
		if (zb2b_load(d, &job, proxi_kmask(10), 0, 0)) return -1;
		usleep(50000);
		if (zb2b_stop(d)) return -1;
		usleep(20000);
		n = zb2b_read_hits(d, c48, h3, 600);
		if (n < 0) return -1;
		for (k = 0; k < n; k++) {
			proxi_hash_attempt(&job, prefix, c48[k], digest);
			if (proxi_work_bits(digest) < 10 || proxi_h3_of_digest(digest) != h3[k]) wrong++;
		}
		for (gid = 0; gid < (int)(s->ncores < 4 ? s->ncores : 4); gid++) {
			uint64_t top = 0, c;
			for (k = 0; k < n; k++) if ((int)(c48[k] >> 40) == gid && (c48[k] & ZB2B_CNT40_MASK) > top) top = c48[k] & ZB2B_CNT40_MASK;
			for (c = 0; c <= top; c++) {
				int found = 0;
				proxi_hash_attempt(&job, prefix, ((uint64_t) gid << 40) | c, digest);
				if (proxi_work_bits(digest) < 10) continue;
				for (k = 0; k < n; k++) if (c48[k] == (((uint64_t) gid << 40) | c)) { found = 1; break; }
				if (!found) { missing++; applog(LOG_WARNING, "%s: selftest search: hit at counter %llu (gid %d) not reported; top %llu", d->label, (unsigned long long) c, gid, (unsigned long long) top); }
			}
		}
		applog(wrong || missing ? LOG_ERR : LOG_INFO, "%s: selftest search k=10: %d hits, %d wrong, %d missing in the covered windows (short USB reads so far: %llu)",
		       d->label, n, wrong, missing, (unsigned long long) s->short_reads);
		fails += (wrong > 0) + (missing > 0);
	}
	zb2b_stop(d);
	applog(fails ? LOG_ERR : LOG_INFO, "%s: proxima SELFTEST %s: %d attempts verified against the host hash, %d failures, %d straddle vectors skipped",
	       d->label, fails ? "FAIL" : "PASS", checked, fails, skipped);
	return fails ? -1 : 0;
}

const struct vu9p_algo_driver ztex_proxima_driver = {
	.name = "proxima",
	.build_id_addr = 0, .build_id_mask = 0xFFF00000, .build_id_value = 0x5B200000,   /* 0x5B2xxxxx: b2b images (0x5B2A0124 = 80 MHz quarter-rate) */
	.open = zb2b_open, .start = zb2b_start, .stop = zb2b_stop, .poll = zb2b_poll, .hashes = zb2b_hashes,
	.work_expired = zb2b_expired, .exhausted = NULL, .selftest = zb2b_selftest, .status = zb2b_status_line,
};
