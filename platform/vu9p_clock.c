/* vu9p_clock.c - run-time core clock of tunable b2b bitstreams; see vu9p_clock.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "miner.h"
#include "vu9p_clock.h"

#define R_CLKCTL   0x240
#define R_DRP      0x244
#define CLK_CE     1
#define CLK_RST    2
#define CLK_ABORT  4
#define CLK_LOCKED 0x100

char  *opt_vu9p_clock_table = NULL;
double opt_vu9p_clock = 0;
int    opt_vu9p_autotune = 0;
int    opt_vu9p_tune_margin = 1;
double opt_vu9p_clock_max = 0;

static struct vu9p_clk_entry *tab;
static int ntab;

static int cmp_entry(const void *a, const void *b)
{
	const struct vu9p_clk_entry *x = (const struct vu9p_clk_entry *) a, *y = (const struct vu9p_clk_entry *) b;
	int c = strcmp(x->bw, y->bw);
	if (c) return c;
	return x->khz < y->khz ? -1 : x->khz > y->khz;
}

int vu9p_clk_table_load(const char *path)
{
	FILE *f;
	char line[1024];
	int lineno = 0;

	if (tab) return 0;
	f = fopen(path, "r");
	if (!f) { applog(LOG_ERR, "clock table %s: cannot open", path); return -1; }
	while (fgets(line, sizeof(line), f)) {
		struct vu9p_clk_entry e;
		char *p = line, *tok;
		int i;
		lineno++;
		if (line[0] == '#' || line[0] == '\n') continue;
		memset(&e, 0, sizeof(e));
		if (sscanf(p, "%u %u %7s %d", &e.khz, &e.mult_x1000, e.bw, &e.n) != 4 || e.n < 1 || e.n > VU9P_CLK_MAX_REG) {
			applog(LOG_ERR, "clock table %s:%d: bad line", path, lineno); fclose(f); return -1;
		}
		for (i = 0; i < 4; i++) { p += strspn(p, " \t"); p += strcspn(p, " \t"); }
		for (i = 0; i < e.n; i++) {
			unsigned a, m, v;
			p += strspn(p, " \t");
			tok = p; p += strcspn(p, " \t\n");
			if (sscanf(tok, "%x:%x:%x", &a, &m, &v) != 3 || a > 0x7f || m > 0xffff || v > 0xffff) {
				applog(LOG_ERR, "clock table %s:%d: bad register %d", path, lineno, i); fclose(f); return -1;
			}
			e.addr[i] = a; e.mask[i] = m; e.val[i] = v;
		}
		tab = (struct vu9p_clk_entry *) realloc(tab, (ntab + 1) * sizeof(*tab));
		tab[ntab++] = e;
	}
	fclose(f);
	if (!ntab) { applog(LOG_ERR, "clock table %s: empty", path); return -1; }
	qsort(tab, ntab, sizeof(*tab), cmp_entry);
	applog(LOG_INFO, "clock table %s: %d settings", path, ntab);
	return 0;
}

static int first_of(const char *bw)
{
	int i;
	for (i = 0; i < ntab; i++) if (!strcmp(tab[i].bw, bw)) return i;
	return -1;
}

int vu9p_clk_count(const char *bw)
{
	int i, n = 0;
	for (i = 0; i < ntab; i++) if (!strcmp(tab[i].bw, bw)) n++;
	return n;
}

const struct vu9p_clk_entry *vu9p_clk_get(const char *bw, int pos)
{
	int f = first_of(bw);
	if (f < 0 || pos < 0 || pos >= vu9p_clk_count(bw)) return NULL;
	return &tab[f + pos];
}

int vu9p_clk_pos_for_khz(const char *bw, uint32_t khz)
{
	int i, n = vu9p_clk_count(bw), best = -1;
	for (i = 0; i < n; i++) if (vu9p_clk_get(bw, i)->khz <= khz + 500) best = i;
	return best;
}

static int drp_wait(struct vu9p_dev *d, uint32_t *st)
{
	int t;
	for (t = 0; t < 100; t++) {
		if (vu9p_rd(d, R_DRP, st)) return -1;
		if (*st & 1) return 0;
	}
	applog(LOG_ERR, "%s: MMCM DRP access timed out", d->label);
	vu9p_wr(d, R_CLKCTL, CLK_ABORT);    /* note: also writes ce 0 / rst 0; callers restore clkctl */
	return -1;
}

static int drp_read(struct vu9p_dev *d, uint8_t a, uint16_t *v)
{
	uint32_t st;
	if (vu9p_wr(d, R_DRP, a) || drp_wait(d, &st)) return -1;
	*v = st >> 16;
	return 0;
}

static int drp_write(struct vu9p_dev *d, uint8_t a, uint16_t v)
{
	uint32_t st;
	if (vu9p_wr(d, R_DRP, ((uint32_t) v << 16) | 0x100 | a)) return -1;
	return drp_wait(d, &st);
}

static int entry_matches(struct vu9p_dev *d, const struct vu9p_clk_entry *e, int *io_err)
{
	int i;
	for (i = 0; i < e->n; i++) {
		uint16_t v;
		if (e->mask[i] == 0 && e->val[i] == 0xffff) continue;       /* power register: write-only setting */
		if (drp_read(d, e->addr[i], &v)) { *io_err = 1; return 0; }
		if ((v & (uint16_t) ~e->mask[i]) != e->val[i]) return 0;
	}
	return 1;
}

int vu9p_clk_identify(struct vu9p_dev *d, uint32_t nominal_khz, const char **bw)
{
	static const char *bws[] = { "HIGH", "LOW" };
	int b, i, io = 0;

	/* the nominal frequency first (fresh image), then every entry (a previous run left it retuned) */
	for (b = 0; b < 2; b++) {
		int pos = vu9p_clk_pos_for_khz(bws[b], nominal_khz);
		const struct vu9p_clk_entry *e = vu9p_clk_get(bws[b], pos);
		if (e && e->khz + 500 >= nominal_khz && entry_matches(d, e, &io)) { *bw = bws[b]; return pos; }
		if (io) return -1;
	}
	for (b = 0; b < 2; b++)
		for (i = 0; i < vu9p_clk_count(bws[b]); i++) {
			if (entry_matches(d, vu9p_clk_get(bws[b], i), &io)) { *bw = bws[b]; return i; }
			if (io) return -1;
		}
	applog(LOG_ERR, "%s: the core MMCM registers match no clock table entry: table does not fit this bitstream, "
	       "clock left unchanged", d->label);
	return -1;
}

int vu9p_clk_set(struct vu9p_dev *d, const char *bw, int pos)
{
	const struct vu9p_clk_entry *e = vu9p_clk_get(bw, pos);
	uint32_t st = 0;
	int i, t;

	if (!e) return -1;
	if (vu9p_wr(d, R_CLKCTL, 0)) return -1;                   /* gate the core clock */
	usleep(1000);
	if (vu9p_wr(d, R_CLKCTL, CLK_RST)) return -1;             /* MMCM in reset */
	for (i = 0; i < e->n; i++) {
		uint16_t v = 0;
		if (e->mask[i] && drp_read(d, e->addr[i], &v)) goto fail;
		v = (v & e->mask[i]) | (e->val[i] & (uint16_t) ~e->mask[i]);
		if (drp_write(d, e->addr[i], v)) goto fail;
	}
	if (vu9p_wr(d, R_CLKCTL, 0)) return -1;                   /* release reset, still gated */
	for (t = 0; t < 200; t++) {
		usleep(1000);
		if (vu9p_rd(d, R_CLKCTL, &st)) return -1;
		if (st & CLK_LOCKED) break;
	}
	if (!(st & CLK_LOCKED)) { applog(LOG_ERR, "%s: core MMCM did not lock at %.3f MHz", d->label, e->khz / 1000.0); return -1; }
	if (vu9p_wr(d, R_CLKCTL, CLK_CE)) return -1;              /* ungate */
	usleep(1000);
	return 0;
fail:
	vu9p_wr(d, R_CLKCTL, 0);
	return -1;
}
