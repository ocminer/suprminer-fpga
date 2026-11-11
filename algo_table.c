/* algo_table.c - algorithm x platform table.  See algo_table.h. */
#include <string.h>
#include <strings.h>
#include <stddef.h>

#include "algo_table.h"
#include "platform/vu9p_driver.h"

const struct algo_info algo_table[ALGO_COUNT] = {
	[ALGO_DMD_GR]    = { "dmd-gr",    "Groestl (DMD)",            STRATUM_BTC,     "ztex_groestl.bit",      NULL, NULL,                 80, 19, false, true },
	[ALGO_GROESTL]   = { "groestl",   "Groestl (GRS)",            STRATUM_BTC,     "ztex_groestl.bit",      NULL, NULL,                 80, 19, false, true },
	[ALGO_MYR_GR]    = { "myr-gr",    "Myriad-Groestl (XMY)",     STRATUM_BTC,     "ztex_myr_groestl.bit",  NULL, NULL,                 80, 19, false, true },
	[ALGO_BLAKECOIN] = { "blakecoin", "Blake256-8 (BLC)",         STRATUM_BTC,     "ztex_blake256_8.bit",   NULL, NULL,                 44, 19, true,  true },
	[ALGO_VCASH]     = { "vcash",     "Blake256-8 (VCASH)",       STRATUM_BTC,     "ztex_blake256_8.bit",   NULL, NULL,                 44, 19, true,  true },
	[ALGO_BLAKE3]    = { "blake3",    "BLAKE3 Decred DCP-0011",   STRATUM_BTC,     "blake3_dcr.bit",        NULL, NULL,                 84, 35, false, true },
	[ALGO_ODO]       = { "odo",       "OdoCrypt (DGB)",           STRATUM_BTC,     "odo_dgb.bit",           NULL, NULL,                 76, 19, false, true },
	[ALGO_SHA3T]     = { "sha3t",     "SHA3-256t (BC3)",          STRATUM_BTC,     "ztex_sha3.bit",         "vu9p_sha3t.bit",    &vu9p_sha3t_driver,   80, 19, false, true },
	[ALGO_PROXIMA]   = { "proxima",   "txid-blake2b (Proxima)",   STRATUM_PROXIMA, NULL,                    "vu9p_proxima.bit",  &vu9p_proxima_driver, 80, 19, false, false },
};

const char *algo_names[] = {
	"dmd-gr", "groestl", "myr-gr", "blakecoin", "vcash", "blake3", "odo", "sha3t", "proxima", "\0"
};

const char *fpga_platform_names[] = { "none", "ztex", "vu9p", NULL };

int algo_lookup(const char *name)
{
	int i;
	if (!name) return -1;
	for (i = 0; i < ALGO_COUNT; i++)
		if (!strcasecmp(algo_table[i].name, name)) return i;
	return -1;
}

int fpga_platform_lookup(const char *name)
{
	int i;
	if (!name) return -1;
	for (i = 0; fpga_platform_names[i]; i++)
		if (!strcasecmp(fpga_platform_names[i], name)) return i;
	return -1;
}
