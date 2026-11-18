/* vu9p_clock.h - run-time core clock of tunable b2b bitstreams (FEATURES bit1).
 *
 * The bitstream's core clock comes from an MMCME4_ADV whose DRP port is reachable through two registers:
 *   0x240 RW clkctl: bit0 core clock enable, bit1 MMCM reset, W bit2 abort a hung DRP access; R bit8 MMCM locked
 *   0x244 W  DRP access {DI[15:0] << 16, DWE << 8, DADDR[6:0]};  R {DO[15:0] << 16, busy << 1, done}
 * The register values per frequency come from a table file (--vu9p-clock-table), one line per setting:
 *   <core_khz> <mult_x1000> <bandwidth> <n> <addr>:<mask>:<value> ...      (hex; mask = bits kept)
 * Before changing anything the driver reads the MMCM registers back and requires an exact match with the
 * table line of the bitstream's nominal frequency, so a table that does not fit the image is never applied.
 */
#ifndef VU9P_CLOCK_H
#define VU9P_CLOCK_H

#include <stdint.h>
#include "vu9p_bridge.h"

#define VU9P_FEAT_TUNE   2
#define VU9P_CLK_MAX_REG 16

struct vu9p_clk_entry {
	uint32_t khz, mult_x1000;
	char     bw[8];
	int      n;
	uint8_t  addr[VU9P_CLK_MAX_REG];
	uint16_t mask[VU9P_CLK_MAX_REG], val[VU9P_CLK_MAX_REG];
};

extern char  *opt_vu9p_clock_table;   /* --vu9p-clock-table FILE */
extern double opt_vu9p_clock;          /* --vu9p-clock MHZ (0 = keep the bitstream's) */
extern int    opt_vu9p_autotune;       /* --vu9p-autotune: probe upwards at start, step down on errors */
extern int    opt_vu9p_tune_margin;    /* --vu9p-tune-margin N: steps below the highest passing one (default 1) */
extern double opt_vu9p_clock_max;      /* --vu9p-clock-max MHZ: autotune ceiling (0 = table end) */

/* Load the table once (all devices share it); entries of one bandwidth sorted by frequency.  0 = ok. */
int  vu9p_clk_table_load(const char *path);

/* Find the table index whose registers match the MMCM right now (tries the bitstream's nominal kHz first).
 * Selects the bandwidth for this device.  Returns the index or -1 (logs why). */
int  vu9p_clk_identify(struct vu9p_dev *d, uint32_t nominal_khz, const char **bw);

/* Number of entries for a bandwidth and access by position (ascending frequency). */
int  vu9p_clk_count(const char *bw);
const struct vu9p_clk_entry *vu9p_clk_get(const char *bw, int pos);
int  vu9p_clk_pos_for_khz(const char *bw, uint32_t khz);      /* highest entry <= khz, -1 if none */

/* Reprogram the core MMCM to table position pos (core must be stopped).  Gates the clock, resets the MMCM,
 * writes the registers read-modify-write, waits for lock, ungates.  0 = locked at the new frequency. */
int  vu9p_clk_set(struct vu9p_dev *d, const char *bw, int pos);

#endif
