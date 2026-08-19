/*
 * tui.c — cgminer/sgminer-style ncurses dashboard for suprminer-fpga.
 *
 * Layout:
 *   - header: pool / algo / diff / clock / uptime + cluster totals
 *   - device table: per-board, per-FPGA clock, MH/s, W, MH/s/W, A, R, last-share
 *   - log pane: live color-coded applog output (also mirrored to --log-file)
 *
 * Only tui_thread() touches ncurses. Every other thread interacts through the
 * mutex-protected log ring buffer (tui_log) and plain reads of the registered
 * fpga_info stats, so there are no ncurses calls off the render thread.
 */

#include <ncurses.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

#include "miner.h"
#include "tui.h"

/* ---- externs from the rest of the miner ---- */
extern char *rpc_url;
extern const char *tui_algo_name(void);
extern double stratum_diff;
extern uint32_t accepted_count;
extern uint32_t rejected_count;
extern double opt_watts_per_fpga;
extern double g_hash_clock_mhz;

bool opt_tui = false;
char *opt_log_file = NULL;

/* ---- device registry ---- */
#define TUI_MAX_BOARDS 64
static struct fpga_info *g_board[TUI_MAX_BOARDS];
static int g_nboards = 0;

void tui_register_board(int board_idx, struct fpga_info *fpga)
{
	if (board_idx < 0 || board_idx >= TUI_MAX_BOARDS)
		return;
	g_board[board_idx] = fpga;
	if (board_idx + 1 > g_nboards)
		g_nboards = board_idx + 1;
}

void tui_record_share(int board_idx, int fpga_idx, bool accepted)
{
	struct fpga_info *f;
	if (board_idx < 0 || board_idx >= g_nboards)
		return;
	f = g_board[board_idx];
	if (!f || !f->ztex_stats)
		return;
	if (fpga_idx < 0 || fpga_idx >= f->ztex_info->numberOfFpgas)
		return;
	if (accepted) f->ztex_stats[fpga_idx].accepted++;
	else          f->ztex_stats[fpga_idx].rejected++;
	gettimeofday(&f->ztex_stats[fpga_idx].last_share_tv, NULL);
}

const char *tui_board_name(int board_idx)
{
	if (board_idx < 0 || board_idx >= g_nboards || !g_board[board_idx])
		return NULL;
	return g_board[board_idx]->name;
}

/* ---- log ring buffer ---- */
#define LOG_CAP  1000
#define LOG_LINE 256
static char g_log[LOG_CAP][LOG_LINE];
static int  g_log_prio[LOG_CAP];
static int  g_log_head = 0;    /* index of next write */
static int  g_log_count = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_logf = NULL;

static struct timeval g_start_tv;

void tui_log(int prio, const char *msg)
{
	struct timeval tv;
	struct tm tm, *tp;
	char stamp[16];
	int slot;

	gettimeofday(&tv, NULL);
	tp = localtime(&tv.tv_sec);
	memcpy(&tm, tp, sizeof(tm));
	snprintf(stamp, sizeof(stamp), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

	pthread_mutex_lock(&g_log_lock);
	slot = g_log_head;
	snprintf(g_log[slot], LOG_LINE, "[%s] %s", stamp, msg);
	g_log_prio[slot] = prio;
	g_log_head = (g_log_head + 1) % LOG_CAP;
	if (g_log_count < LOG_CAP) g_log_count++;
	if (g_logf) { fprintf(g_logf, "%s\n", g_log[slot]); fflush(g_logf); }
	pthread_mutex_unlock(&g_log_lock);
}

/* ---- helpers ---- */
static void fmt_ago(char *out, size_t n, struct timeval *when)
{
	struct timeval now;
	long s;
	if (when->tv_sec == 0) { snprintf(out, n, "-"); return; }
	gettimeofday(&now, NULL);
	s = now.tv_sec - when->tv_sec;
	if (s < 0) s = 0;
	if (s < 60)          snprintf(out, n, "%lds", s);
	else if (s < 3600)   snprintf(out, n, "%ldm%02lds", s / 60, s % 60);
	else                 snprintf(out, n, "%ldh%02ldm", s / 3600, (s % 3600) / 60);
}

static void fmt_dur(char *out, size_t n, long s)
{
	if (s < 0) s = 0;
	snprintf(out, n, "%ld:%02ld:%02ld", s / 3600, (s % 3600) / 60, s % 60);
}

/* color pairs */
enum { CP_HDR = 1, CP_OK, CP_BAD, CP_DIM, CP_WARN, CP_COLHDR };

static int prio_cp(int prio, const char *line)
{
	if (line && strstr(line, "ACCEPTED")) return CP_OK;
	if (line && (strstr(line, "REJECTED") || strstr(line, "stale"))) return CP_BAD;
	switch (prio) {
		case LOG_ERR:     return CP_BAD;
		case LOG_WARNING: return CP_WARN;
		default:          return 0;
	}
}

static int g_dev_scroll = 0;
static volatile int g_quit = 0;

static void draw(void)
{
	int rows = LINES, cols = COLS;
	int y, i, j;
	double total_mhps = 0.0;
	int total_fpgas = 0, total_boards = 0;
	char buf[512];

	/* ---- gather totals ---- */
	for (i = 0; i < g_nboards; i++) {
		struct fpga_info *f = g_board[i];
		if (!f || !f->ztex_stats) continue;
		total_boards++;
		for (j = 0; j < f->ztex_info->numberOfFpgas; j++) {
			if (!f->ztex_stats[j].enabled) continue;
			total_mhps += f->ztex_stats[j].hashrate_smooth / 1e6;
			total_fpgas++;
		}
	}
	double total_w   = total_fpgas * opt_watts_per_fpga;
	double total_mhw = (total_w > 0.01) ? total_mhps / total_w : 0.0;
	unsigned long tot = accepted_count + rejected_count;
	double pct = tot ? 100.0 * accepted_count / tot : 100.0;

	erase();

	/* ---- header ---- */
	{
		struct timeval now; gettimeofday(&now, NULL);
		char up[32]; fmt_dur(up, sizeof(up), now.tv_sec - g_start_tv.tv_sec);
		struct tm tm, *tp = localtime(&now.tv_sec); memcpy(&tm, tp, sizeof(tm));
		char clk[16];
		snprintf(buf, sizeof(buf),
			" suprminer-fpga  |  %s  |  %s  |  diff %.4g  |  %02d:%02d:%02d  |  up %s",
			rpc_url ? rpc_url : "(no pool)",
			tui_algo_name(), stratum_diff,
			tm.tm_hour, tm.tm_min, tm.tm_sec, up);
		attron(COLOR_PAIR(CP_HDR) | A_BOLD);
		mvprintw(0, 0, "%-*.*s", cols, cols, buf);
		attroff(COLOR_PAIR(CP_HDR) | A_BOLD);

		snprintf(buf, sizeof(buf),
			" %d boards / %d FPGAs    %.2f MH/s   %.0f W   %.2f MH/s/W   A:%lu  R:%lu  (%.1f%%)",
			total_boards, total_fpgas, total_mhps, total_w, total_mhw,
			(unsigned long)accepted_count, (unsigned long)rejected_count, pct);
		(void)clk;
		mvprintw(1, 0, "%-*.*s", cols, cols, buf);
	}
	attron(COLOR_PAIR(CP_DIM));
	mvhline(2, 0, ACS_HLINE, cols);
	attroff(COLOR_PAIR(CP_DIM));

	/* ---- device table ---- */
	int table_top = 3;
	attron(COLOR_PAIR(CP_COLHDR) | A_BOLD);
	mvprintw(table_top, 0, " %-16s %-4s %6s %7s %5s %7s %6s %5s %6s",
		"DEVICE", "FPGA", "CLK", "MH/s", "W", "MH/s/W", "A", "R", "LAST");
	attroff(COLOR_PAIR(CP_COLHDR) | A_BOLD);

	/* build flat list of rows so scrolling is simple */
	int log_h = rows / 3; if (log_h < 6) log_h = 6; if (log_h > 16) log_h = 16;
	int dev_area_top = table_top + 1;
	int dev_area_bot = rows - log_h - 2;      /* leave 1 sep + log area */
	if (dev_area_bot < dev_area_top + 1) dev_area_bot = dev_area_top + 1;
	int dev_rows_avail = dev_area_bot - dev_area_top;

	/* total device rows */
	int total_rows = 0;
	for (i = 0; i < g_nboards; i++) {
		struct fpga_info *f = g_board[i];
		if (!f || !f->ztex_stats) continue;
		total_rows += f->ztex_info->numberOfFpgas;
	}
	if (g_dev_scroll < 0) g_dev_scroll = 0;
	if (g_dev_scroll > total_rows - dev_rows_avail && total_rows > dev_rows_avail)
		g_dev_scroll = total_rows - dev_rows_avail;
	if (total_rows <= dev_rows_avail) g_dev_scroll = 0;

	int rownum = 0;   /* logical row index across all boards/fpgas */
	y = dev_area_top;
	for (i = 0; i < g_nboards && y < dev_area_bot; i++) {
		struct fpga_info *f = g_board[i];
		if (!f || !f->ztex_stats) continue;
		for (j = 0; j < f->ztex_info->numberOfFpgas; j++, rownum++) {
			if (rownum < g_dev_scroll) continue;
			if (y >= dev_area_bot) break;
			struct ztex_stats *s = &f->ztex_stats[j];
			double mhps = s->hashrate_smooth / 1e6;
			double w = opt_watts_per_fpga;
			double mhw = (w > 0.01) ? mhps / w : 0.0;
			char ago[16]; fmt_ago(ago, sizeof(ago), &s->last_share_tv);
			const char *dev = (j == 0) ? f->name : "";
			/* per-FPGA clock: variant governor stores MHz in s->freq
			 * (legacy fixed-clock mode stores an M-index <= 32 there) */
			double clk = (s->freq > 50) ? (double)s->freq : g_hash_clock_mhz;
			snprintf(buf, sizeof(buf),
				" %-16.16s -%d   %5.1f  %6.2f  %4.1f   %5.2f   %5d %4d %6s",
				dev, j, clk, mhps, w, mhw,
				s->accepted, s->rejected, ago);
			if (!s->enabled) attron(COLOR_PAIR(CP_DIM));
			mvprintw(y, 0, "%-*.*s", cols, cols, buf);
			if (!s->enabled) attroff(COLOR_PAIR(CP_DIM));
			y++;
		}
	}
	if (total_rows > dev_rows_avail) {
		attron(COLOR_PAIR(CP_DIM));
		mvprintw(dev_area_bot - 1, cols - 22, "[PgUp/PgDn to scroll]");
		attroff(COLOR_PAIR(CP_DIM));
	}

	/* ---- log pane ---- */
	int log_sep = rows - log_h - 1;
	attron(COLOR_PAIR(CP_DIM));
	mvhline(log_sep, 0, ACS_HLINE, cols);
	attroff(COLOR_PAIR(CP_DIM));

	pthread_mutex_lock(&g_log_lock);
	int show = log_h;
	if (show > g_log_count) show = g_log_count;
	for (int k = 0; k < show; k++) {
		int idx = (g_log_head - show + k + LOG_CAP) % LOG_CAP;
		int cp = prio_cp(g_log_prio[idx], g_log[idx]);
		int ly = log_sep + 1 + k;
		if (ly >= rows) break;
		if (cp) attron(COLOR_PAIR(cp));
		mvprintw(ly, 0, "%-*.*s", cols, cols, g_log[idx]);
		if (cp) attroff(COLOR_PAIR(cp));
	}
	pthread_mutex_unlock(&g_log_lock);

	/* footer hint on the last row of header area already; refresh */
	refresh();
}

void tui_init(void)
{
	if (opt_log_file) {
		g_logf = fopen(opt_log_file, "w");
		/* if it fails we simply don't mirror; not fatal */
	}
	gettimeofday(&g_start_tv, NULL);

	atexit(tui_shutdown);   /* restore terminal even on non-'q' exit paths */
	initscr();
	cbreak();
	noecho();
	nodelay(stdscr, TRUE);
	keypad(stdscr, TRUE);
	curs_set(0);
	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(CP_HDR,    COLOR_CYAN,   -1);
		init_pair(CP_OK,     COLOR_GREEN,  -1);
		init_pair(CP_BAD,    COLOR_RED,    -1);
		init_pair(CP_DIM,    COLOR_BLUE,   -1);
		init_pair(CP_WARN,   COLOR_YELLOW, -1);
		init_pair(CP_COLHDR, COLOR_WHITE,  -1);
	}
}

void *tui_thread(void *userdata)
{
	(void)userdata;
	while (!g_quit) {
		int ch = getch();
		while (ch != ERR) {
			switch (ch) {
				case 'q': case 'Q':
					g_quit = 1;
					break;
				case KEY_NPAGE: g_dev_scroll += 5; break;
				case KEY_PPAGE: g_dev_scroll -= 5; break;
				case KEY_DOWN:  g_dev_scroll += 1; break;
				case KEY_UP:    g_dev_scroll -= 1; break;
				default: break;
			}
			ch = getch();
		}
		draw();
		if (g_quit) break;
		napms(500);
	}
	tui_shutdown();
	/* trigger a normal miner shutdown */
	kill(getpid(), SIGINT);
	return NULL;
}

void tui_shutdown(void)
{
	if (!isendwin())
		endwin();
	if (g_logf) { fflush(g_logf); }
}
