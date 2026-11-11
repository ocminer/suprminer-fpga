/* algo_table.h - the one place that says which algorithm runs on which
 * platform with which bitstream and which driver.  Nothing else in the miner
 * switches on an algorithm name to pick hardware behaviour.
 *
 * Platform selection is a command-line matter (--fpga ztex|vu9p); the
 * bitstream defaults below are overridden by --bitstream <file>.
 */
#ifndef ALGO_TABLE_H
#define ALGO_TABLE_H

#include <stdbool.h>

enum algos {
	ALGO_DMD_GR,      /* Groestl (double SHA256 on merkle) */
	ALGO_GROESTL,     /* Groestl (single SHA256 on merkle) */
	ALGO_MYR_GR,      /* Myriad Groestl (double SHA256 on merkle) */
	ALGO_BLAKECOIN,   /* Blake 256 - 8 rounds (single SHA256 on merkle) */
	ALGO_VCASH,       /* Blake 256 - 8 rounds (double SHA256 on merkle) */
	ALGO_BLAKE3,      /* BLAKE3 - Decred DCP-0011 (180-byte header) */
	ALGO_ODO,         /* OdoCrypt - DigiByte (standard 80-byte header) */
	ALGO_SHA3T,       /* SHA3-256t - BitcoinIII/BC3 (standard 80-byte header) */
	ALGO_PROXIMA,     /* txid-blake2b - Proxima (prefix + 8-byte nonce, BLAKE2b-256) */
	ALGO_COUNT
};

/* How the pool talks: classic Bitcoin-style stratum, or the Proxima dialect
 * (mining.notify carries a transaction prefix and a ttl; shares are
 * [worker, job_id, extranonce2, hash]). */
enum stratum_dialect {
	STRATUM_BTC = 0,
	STRATUM_PROXIMA = 1
};

enum fpga_platform {
	PLATFORM_NONE = 0,
	PLATFORM_ZTEX,    /* ZTEX USB-FPGA 1.15y boards (libusb) */
	PLATFORM_VU9P     /* Xilinx VU9P boards (BCU-1525 ...) via a JTAG-AXI register bridge */
};

struct vu9p_algo_driver;

struct algo_info {
	const char *name;
	const char *description;
	int         dialect;              /* enum stratum_dialect */
	const char *ztex_bitstream;       /* default under bitstreams/, NULL when the algorithm has no ZTEX image */
	const char *vu9p_bitstream;       /* default under bitstreams/, NULL when none is bundled (pass --bitstream) */
	const struct vu9p_algo_driver *vu9p_driver;   /* NULL: no VU9P support for this algorithm */
	int         fpga_work_len;        /* serial/ZTEX work format */
	int         nonce_word;
	bool        midstate;
	bool        cpu_minable;          /* -C makes sense */
};

extern const struct algo_info algo_table[ALGO_COUNT];
extern const char *algo_names[];      /* ALGO_COUNT names + "" terminator (option parser, TUI) */
extern const char *fpga_platform_names[];

int algo_lookup(const char *name);               /* enum algos or -1 */
int fpga_platform_lookup(const char *name);      /* enum fpga_platform or -1 */

#endif /* ALGO_TABLE_H */
