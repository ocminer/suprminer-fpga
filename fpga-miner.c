/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <jansson.h>

#include <getopt.h>

#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "miner.h"
#include "tui.h"
#include "libvu9p.h"
#include "vu9p_bs1_policy.h"
#include "fpgautils.h"
#include "hashrate_total.h"
#include "bc3_ztex_gate.h"
#include "bc3_ztex_heartbeat_policy.h"
#include "bc3_ztex_io.h"
#include "bc3_ztex_lane_policy.h"
#include "bc3_ztex_liveness.h"
#include "bc3_ztex_progress.h"
#include "bc3_ztex_protocol.h"
#include "bc3_ztex_result.h"
#include "bc3_ztex_session.h"
#include "bc3_ztex_shutdown.h"
#include "bc3_ztex_work.h"
#include "sha3_nonce_zero.h"
#include "sha3_variant_catalog.h"
#include "sha3_variant_file.h"
#include "sha3_variant_ladder.h"
#include "sha3_variant_reconfig.h"
#include "sha3_variant_state.h"
#include "stratum_job_guard.h"
#include "stratum_submit_map.h"
#include "work_clone_checked.h"
#include "work_publish_guard.h"
#include "ztex_golden_dedup.h"
#include "ztex_rb_test.h"
#include "algo/blake256-8.h"
#include "algo/blake3.h"

#ifdef WIN32
#include "compat/winansi.h"
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#define LP_SCANTIME		60

/* Keep VU9P status polling responsive without turning the miner loop into a
 * busy wait or multiplying JTAG traffic too aggressively. */
#define VU9P_POLL_INTERVAL_MS	VU9P_POLL_PERIOD_MS
#define VU9P_TEMP_INTERVAL_S	10
#if VU9P_POLL_INTERVAL_MS < 1
#error "VU9P_POLL_INTERVAL_MS must retain a positive sleep"
#endif

enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
	WC_STOP,
};

struct workio_cmd {
	enum workio_commands cmd;
	struct thr_info *thr;
	struct stratum_submit_ticket submit_ticket;
	union {
		struct work *work;
	} u;
};

static struct workio_cmd bc3_ztex_v2_workio_stop_command = {
	.cmd = WC_STOP
};

enum algos {
	ALGO_DMD_GR,      // Groestl (double SHA256 on merkle)
	ALGO_GROESTL,     // Groestl (single SHA256 on merkle)
	ALGO_MYR_GR,      // Myriad Groestl (double SHA256 on merkle)
	ALGO_BLAKECOIN,   // Blake 256 - 8 Rounds (single SHA256 on merkle)
	ALGO_VCASH,       // Blake 256 - 8 Rounds (double SHA256 on merkle)
	ALGO_BLAKE3,      // BLAKE3 - Decred DCP-0011 (180-byte header)
	ALGO_ODO,         // OdoCrypt - DigiByte (standard 80-byte header)
	ALGO_SHA3T,       // SHA3-256t - BitcoinIII/BC3 (standard 80-byte header)
	ALGO_COUNT
};

static const char *algo_names[] = {
	"dmd-gr",
	"groestl",
	"myr-gr",
	"blakecoin",
	"vcash",
	"blake3",
	"odo",
	"sha3t",
	"\0"
};

bool opt_debug = false;
bool opt_protocol = false;
bool opt_redirect = true;
bool opt_extranonce = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true;
bool have_stratum = false;
bool allow_mininginfo = true;
bool use_colors = true;
bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
int opt_timeout = 300;
static int opt_scantime = 5;
static const bool opt_time = true;
static enum algos opt_algo = ALGO_GROESTL;
int opt_n_threads = 0;
int opt_affinity = -1;
int opt_priority = 0;
int num_cpus;
char *rpc_url;
char *rpc_userpass;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
static unsigned char pk_script[25] = { 0 };
static size_t pk_script_size = 0;
static char coinbase_sig[101] = { 0 };
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum = {
	.sock_lock = PTHREAD_MUTEX_INITIALIZER,
	.work_lock = PTHREAD_MUTEX_INITIALIZER
};
bool jsonrpc_2 = false;
char rpc2_id[64] = "";
char *rpc2_blob = NULL;
size_t rpc2_bloblen = 0;
uint32_t rpc2_target = 0;
char *rpc2_job_id = NULL;
bool aes_ni_supported = false;
double opt_diff_factor = 1.0;
pthread_mutex_t rpc2_job_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rpc2_login_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t applog_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

bool rpc2_id_copy(char *dst, size_t dst_size)
{
	size_t id_len;
	bool present = false;

	if (!dst || !dst_size)
		return false;

	pthread_mutex_lock(&rpc2_login_lock);
	id_len = strnlen(rpc2_id, sizeof(rpc2_id));
	if (id_len && id_len < sizeof(rpc2_id) && id_len < dst_size) {
		memcpy(dst, rpc2_id, id_len + 1);
		present = true;
	} else {
		dst[0] = '\0';
	}
	pthread_mutex_unlock(&rpc2_login_lock);

	return present;
}

uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
static size_t thr_hashrates_count;

/* Hash-clock of the currently deployed bitstream, MHz (shown in the TUI). */
double g_hash_clock_mhz = 90.0;
static bool opt_hash_clock_explicit = false;
static bool opt_hash_clock_exact_96 = false;

/* Production remains exactly 30 seconds.  The sole 20-second override is
 * admitted only by the fail-closed, pre-USB single-lane canary policy. */
static unsigned g_ztex_heartbeat_interval_seconds =
	BC3_ZTEX_HEARTBEAT_DEFAULT_SECONDS;
static bool opt_heartbeat_interval_seen = false;
static bool opt_ztex_frequency_explicit = false;
static bool opt_ztex_frequency_exact_96 = false;

/* Per-share submit-id -> originating device, for TUI per-FPGA attribution.
 * Stratum responses carry only the JSON-RPC id. Producer threads charge a
 * credit before queueing, workio moves it to SENT, and the exact socket
 * generation plus JSON-RPC id releases it on a terminal response. */
static struct stratum_submit_map g_submit_map = {
	.next_id = STRATUM_SUBMIT_ID_FIRST
};
static pthread_mutex_t g_submit_map_lock = PTHREAD_MUTEX_INITIALIZER;
/* A complete submit write and its QUEUED -> SENT transition are atomic with
 * respect to response lookup.  Otherwise a very fast pool response could be
 * consumed after the bytes reached the socket but before the ledger changed
 * state. */
static pthread_mutex_t g_submit_dispatch_lock = PTHREAD_MUTEX_INITIALIZER;

/* TUI accessor — algo_names[]/opt_algo are static to this file. */
const char *tui_algo_name(void) { return algo_names[opt_algo]; }

/* ---- Fixed-bitstream variant governor ---------------------------------
 * The DCM_CLKGEN programmable-clock bitstream proved unplaceable, so the
 * governor works by BITSTREAM SELECTION instead: fixed-clock variants
 * form a hash-rate-sorted, SHA-256-bound implementation family. Each FPGA is
 * configured with its exact rung ID, never a rounded MHz alias. */
#define VG_NRUNGS SHA3_VARIANT_CATALOG_COUNT
static bool vg_avail[SHA3_VARIANT_FAMILY_MAX_RUNGS];
static bool vg_enabled = false;
static int  vg_rung_tbl[64][4];               /* startup assignment per board/fpga */
static pthread_mutex_t vg_lock = PTHREAD_MUTEX_INITIALIZER;
#define VG_STATE_FILE "fleet_variant_state_v1.conf"

/* Explicit candidate-bitstream escape hatch for controlled SHA3T hardware
 * tests.  Keep only a validated bare filename: open_bitstream() supplies the
 * fixed ./bitstreams/ prefix.  The separate active flag makes every ladder
 * bypass explicit instead of relying only on vg_enabled's current value. */
#define SHA3_OVERRIDE_NAME_MAX 255
static bool sha3_bitstream_override_active = false;
static char sha3_bitstream_override[SHA3_OVERRIDE_NAME_MAX + 1];

/* Fail-closed opt-in for the incompatible R34 typed transport.  Merely
 * choosing a candidate bitstream cannot enter this path: the operator must
 * independently allowlist its nonzero status BUILD_ID. */
static bool bc3_ztex_v2_active = false;
static uint32_t bc3_ztex_v2_build_id = 0;
/* The v2 canary has exactly one board worker, which remains the sole USB
 * owner through PAUSE and drain. Signal handlers only publish these
 * sig_atomic requests; the worker performs every protocol operation. */
static volatile sig_atomic_t bc3_ztex_v2_signal_drain_mode = 0;
static volatile sig_atomic_t bc3_ztex_v2_signal_stop_requested = 0;
static volatile sig_atomic_t bc3_ztex_v2_stop_signal = 0;
static pthread_mutex_t bc3_ztex_v2_control_lock = PTHREAD_MUTEX_INITIALIZER;
static struct bc3_ztex_shutdown_state bc3_ztex_v2_shutdown;
#define BC3_ZTEX_V2_WORKIO_FLUSH_TIMEOUT_SEC 15
#define BC3_ZTEX_V2_WORKIO_FLUSH_TIMEOUT_US UINT64_C(15000000)
/* Set only after an exact v2 status frame proves the configured lane's ABI
 * and build. Pre-worker cleanup must never send typed bytes to an unknown
 * image. The v2 gate permits exactly one four-lane board. */
static uint8_t bc3_ztex_v2_compatible_lane_mask = 0;
static uint8_t bc3_ztex_v2_configured_lane_mask = 0;
static uint8_t bc3_ztex_v2_attempted_lane_mask = 0;

/* Dormant-by-default host experiment for classifying and mitigating the
 * bounded 10-second ZTEX transport episodes.  Unset means the legacy poll,
 * select, retry, and log paths below are used without entering test code. */
static enum ztex_rb_test_mode ztex_rb_mode = ZTEX_RB_TEST_OFF;

static bool ztex_get_readback_test(void)
{
	const char *value = getenv("ZTEX_RB_TEST");
	enum ztex_rb_test_mode parsed = ZTEX_RB_TEST_OFF;

	ztex_rb_mode = ZTEX_RB_TEST_OFF;
	if (!ztex_rb_parse_mode(value, &parsed)) {
		applog(LOG_ERR, "ZTEX_RB_TEST rejected: expected observe, stagger, retry, or stagger-retry");
		return false;
	}
	if (!value)
		return true;
	if (opt_algo != ALGO_SHA3T) {
		applog(LOG_ERR, "ZTEX_RB_TEST=%s rejected: experiment is restricted to sha3t", value);
		return false;
	}

	ztex_rb_mode = parsed;
	applog(LOG_WARNING,
		"ZTEX_RB_TEST=%s active (trace v1, period=%llu us, retry path is opt-in)",
		value, (unsigned long long)ZTEX_RB_PERIOD_US);
	return true;
}

/* Optional single-board safety interlock for controlled hardware tests.  The
 * filter is intentionally an exact, case-sensitive match against the USB
 * serial descriptor and is resolved for the complete scan before any FPGA is
 * selected or configured. */
static bool ztex_get_serial_only(const char **serial_only)
{
	const char *value = getenv("ZTEX_SERIAL_ONLY");
	size_t i, len;

	*serial_only = NULL;
	if (!value)
		return true;

	len = strlen(value);
	if (len == 0 || len > LIBZTEX_SNSTRING_LEN) {
		applog(LOG_ERR, "ZTEX_SERIAL_ONLY rejected: expected 1..%d characters",
			LIBZTEX_SNSTRING_LEN);
		return false;
	}
	for (i = 0; i < len; i++) {
		char c = value[i];
		if (!((c >= '0' && c <= '9') ||
		      (c >= 'A' && c <= 'Z') ||
		      (c >= 'a' && c <= 'z') || c == '-' || c == '_')) {
			applog(LOG_ERR, "ZTEX_SERIAL_ONLY rejected: serial may contain only ASCII letters, digits, '-' and '_'");
			return false;
		}
	}

	*serial_only = value;
	applog(LOG_WARNING, "ZTEX_SERIAL_ONLY=%s requested (fail-closed single-board mode)", value);
	return true;
}

static bool sha3_activate_bitstream_override(const char *name)
{
	char probe[sizeof("bitstreams/") + SHA3_OVERRIDE_NAME_MAX];
	size_t len;
	FILE *f;

	sha3_bitstream_override_active = false;
	sha3_bitstream_override[0] = '\0';
	bc3_ztex_v2_active = false;
	bc3_ztex_v2_build_id = 0;

	len = name ? strlen(name) : 0;
	if (len == 0 || len > SHA3_OVERRIDE_NAME_MAX ||
	    strchr(name, '/') || strchr(name, '\\') || strstr(name, "..")) {
		applog(LOG_ERR, "SHA3_BITSTREAM rejected: expected a non-empty bare filename (max %d bytes; no slashes or '..')",
			SHA3_OVERRIDE_NAME_MAX);
		return false;
	}

	memcpy(sha3_bitstream_override, name, len + 1);
	snprintf(probe, sizeof(probe), "bitstreams/%s", sha3_bitstream_override);
	f = fopen(probe, "rb");
	if (!f) {
		applog(LOG_ERR, "SHA3_BITSTREAM override is not readable: ./%s", probe);
		return false;
	}
	fclose(f);

	/* No discovery, persisted rung, startup ladder choice, or later ladder
	 * reconfiguration may replace the requested candidate in this process. */
	memset(vg_avail, 0, sizeof(vg_avail));
	vg_enabled = false;
	sha3_bitstream_override_active = true;
	applog(LOG_WARNING, "SHA3_BITSTREAM override active: ./%s (variant ladder disabled)", probe);
	return true;
}

static const char *vg_bitfile(int rung)
{
	/* Immutable strings avoid a data race when board workers reconfigure
	 * different lanes concurrently. open_bitstream() adds "./bitstreams/". */
	if (rung < 0 || rung >= (int)VG_NRUNGS)
		return NULL;
	return sha3_variant_catalog[rung].bitfile;
}

static const struct sha3_variant_spec *vg_spec(int rung)
{
	if (rung < 0 || rung >= (int)VG_NRUNGS)
		return NULL;
	return &sha3_variant_catalog[rung];
}

static bool vg_verify_rung_file(int rung, bool report_missing)
{
	const struct sha3_variant_spec *spec = vg_spec(rung);
	char path[sizeof("bitstreams/") + 255];
	char actual[SHA3_VARIANT_FILE_SHA256_HEX_SIZE];
	enum sha3_variant_file_status status;
	int written;

	if (!spec)
		return false;
	written = snprintf(path, sizeof(path), "bitstreams/%s", spec->bitfile);
	if (written < 0 || (size_t)written >= sizeof(path))
		return false;
	status = sha3_variant_file_check(path, spec->sha256_hex, actual);
	if (status == SHA3_VARIANT_FILE_OK)
		return true;
	if (status == SHA3_VARIANT_FILE_DIGEST_MISMATCH)
		applog(LOG_ERR,
			"variant governor rejected %s: SHA-256 mismatch (observed %.12s...)",
			spec->bitfile, actual);
	else if (status != SHA3_VARIANT_FILE_MISSING || report_missing)
		applog(LOG_ERR, "variant governor rejected %s: file status %d",
			spec->bitfile, (int)status);
	return false;
}

static int vg_discover(void)
{
	int r, n = 0;

	memset(vg_avail, 0, sizeof(vg_avail));
	vg_enabled = false;
	if (!SHA3_VARIANT_CATALOG_BOUND ||
	    !sha3_variant_family_valid(SHA3_VARIANT_CATALOG_FAMILY_ID,
			sha3_variant_catalog, VG_NRUNGS,
			SHA3_VARIANT_CATALOG_DEFAULT_RUNG)) {
		applog(LOG_ERR,
			"variant governor catalog is not bound to at least two qualified images");
		return 0;
	}
	for (r = 0; r < (int)VG_NRUNGS; r++) {
		vg_avail[r] = vg_verify_rung_file(r, false);
		if (vg_avail[r])
			n++;
	}
	vg_enabled = (n >= 2);   /* a ladder needs at least two rungs */
	if (vg_enabled)
		applog(LOG_WARNING, "variant governor: family %s, %d exact rungs available",
			SHA3_VARIANT_CATALOG_FAMILY_ID, n);
	return n;
}

static int vg_load_rung(const char *serial, int fpga)
{
	char state_id[64];
	bool found = false;
	int r, preferred = SHA3_VARIANT_CATALOG_DEFAULT_RUNG;

	if (!sha3_variant_state_lookup(VG_STATE_FILE, serial, (unsigned)fpga,
			SHA3_VARIANT_CATALOG_FAMILY_ID, state_id,
			sizeof(state_id), &found)) {
		applog(LOG_ERR,
			"variant governor ignored malformed state for %s-%d: %s",
			serial, fpga, strerror(errno));
	} else if (found) {
		for (r = 0; r < (int)VG_NRUNGS; ++r)
			if (strcmp(sha3_variant_catalog[r].state_id, state_id) == 0) {
				preferred = r;
				break;
			}
	}
	return sha3_variant_initial_rung(vg_avail, VG_NRUNGS, preferred);
}

static bool vg_save_rung(const char *serial, int fpga, int rung)
{
	bool saved;
	int saved_errno;

	if (!serial || fpga < 0 || rung < 0 || rung >= (int)VG_NRUNGS)
		return false;
	pthread_mutex_lock(&vg_lock);
	saved = sha3_variant_state_save_atomic(VG_STATE_FILE, serial,
		(unsigned)fpga, SHA3_VARIANT_CATALOG_FAMILY_ID,
		sha3_variant_catalog[rung].state_id);
	saved_errno = errno;
	pthread_mutex_unlock(&vg_lock);
	errno = saved_errno;
	return saved;
}
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;

uint32_t opt_work_size = 0; /* default */
char *opt_api_allow = NULL;
int opt_api_remote = 0;
int opt_api_listen = 4048; /* 0 to disable */


//
// Begin FPGA
//


bool opt_use_cpu = false;
bool opt_use_serial = false;
bool opt_use_ztex = false;
bool opt_use_vu9p = false;
static bool opt_vu9p_build_id_set = false;
static bool opt_vu9p_options_seen = false;
static uint32_t opt_vu9p_build_id = 0;
static uint32_t opt_vu9p_active_lanes = 0;
static uint64_t opt_vu9p_rate_hps = 0;
static uint32_t opt_vu9p_poll_work_ms = 0;
bool opt_auto_freq = false;
double opt_watts_per_fpga = 7.5;  /* measured wall-power per FPGA (tune to your meter); for W/MH efficiency display */
bool opt_fpga_summary = false;
bool opt_firmware = false;
unsigned char g_saved_send[4][84]; /* DIAG: saved send buffers for verification */

int g_miner_count;
int g_fpga_count;
int g_serial_fpga_count;
int g_ztex_fpga_count;
int g_serial_device_count;

int g_ztex_freq = 24;	// Default = 100 Mhz
int g_fpga_work_len = 80;
int g_nonce_word_index = 19;  // word index of nonce in work.data (19 for 80-byte, 35 for Decred)
bool g_fpga_use_midstate = false;

int g_block_count = 0;
double g_net_diff = 0.0;

int g_serial_device_count;
char* serial_fpga_list[MAX_SERIAL_DEVICES];
struct libztex_device *ztex_info;
static struct bc3_ztex_lane_policy *ztex_lane_policies;

struct timeval g_miner_start_time;

//
// End FPGA
//


static char const usage[] = "\
Usage: " PACKAGE_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo <algo>          The mining algorithm to use\n\
                               dmd-gr       Diamond-Groestl\n\
                               groestl      GroestlCoin\n\
                               odo          OdoCrypt (DigiByte)\n\
                               myr-gr       Myriad-Groestl\n\
							   blake256-8  Blake256 - 8 Rounds\n\
  -o, --url=URL              URL of mining server\n\
  -O, --userpass <u:p>       Username:password pair for mining server\n\
  -u, --user <username>      Username for mining server\n\
  -p, --pass <password>      Password for mining server\n\
      --cert <file>          Certificate for mining server using SSL\n\
  -x, --proxy [PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads <n>          Number of miner threads (Default: Number of CPUs)\n\
  -r, --retries <n>          Number of times to retry if a network call fails\n\
                             (Default: Retry indefinitely)\n\
  -R, --retry-pause <n>      Time to pause between retries (Default: 30 sec)\n\
  -T, --timeout <n>          Timeout for longpoll and stratum (Default: 300 sec)\n\
  -s, --scan-time <n>        Max time to scan work for nonces (Default: 5 sec)\n\
  -S, --scan-serial          Serial port of Serial FPGA, (\\\\.\\COM1,\\\\.\\COM2,etc)\n\
  -f, --diff-factor          Divide target diff by this factor (Default: 1.0)\n\
  -m, --diff-multiplier      Multiply target diff by this factor (Default: 1.0)\n\
      --coinbase-addr <addr> Payout address for solo mining\n\
      --coinbase-sig <text>  Data to insert in the coinbase when possible\n\
      --no-longpoll          Disable long polling support\n\
      --no-getwork           Disable getwork support\n\
      --no-gbt               Disable getblocktemplate support\n\
      --no-stratum           Disable X-Stratum support\n\
      --no-extranonce        Disable Stratum extranonce support\n\
      --no-redirect          Ignore request to change URL of the mining server\n\
  -q, --quiet                Display minimal output\n\
      --no-color             Don't display colored output\n\
  -D, --debug                Display debug output\n\
  -P, --protocol-dump        Display dump of protocol-level activities\n\
      --cpu-affinity         Set process affinity to cpu core(s)\n\
      --cpu-priority         Set process priority (default: 0 idle to 5 highest)\n\
  -b, --api-bind             IP/Port for the miner API (default: 127.0.0.1:4048)\n\
      --api-remote           Allow remote control\n\
  -c, --config <file>        Use JSON-formated configuration file\n\
  -C, --cpu                  Use CPU for mining\n\
  -V, --version              Display version information and exit\n\
  -z, --ztex <freqency>      Use ZTEX FPGA for mining (Clock frequency in Mhz)\n\
      --vu9p <host:port,...>  Use VU9P BS1 cards through JTAG-AXI TCP bridges\n\
      --vu9p-build-id <hex8>  BS1 requires 5a3d0001\n\
      --vu9p-active-lanes <n> BS1 requires 1\n\
      --vu9p-rate-hps <n>     BS1 requires 300000000\n\
      --vu9p-poll-work-ms <n> Poll interval + POLL + STOP latency bound\n\
      --auto-freq            Automatically adjust ZTEX chip frequency\n\
      --heartbeat-interval 20  Canary-only heartbeat cadence (default: 30 sec)\n\
  -F, --firmware             Reload firmware on ZTEX FPGAs\n\
  -h, --help                 Display this help text and exit\n\n\
Options while mining ----------------------------------------------------------\n\n\
   s + <enter>               Display mining summary\n\
   f + <enter>               Display fpga summary\n\
   d + <enter>               Toggle Debug mode\n\
   q + <enter>               Toggle Quite mode\n\
";


static char const short_options[] =
	"a:b:c:C:Df:Fh:m:p:Px:q:r:R:s:S:t:T:o:u:O:V:z:";

static struct option const options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "api-bind", 1, NULL, 'b' },
	{ "api-remote", 0, NULL, 1030 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1013 },
	{ "coinbase-sig", 1, NULL, 1015 },
	{ "config", 1, NULL, 'c' },
	{ "cpu", 0, NULL, 'C' },
	{ "cpu-affinity", 1, NULL, 1020 },
	{ "cpu-priority", 1, NULL, 1021 },
	{ "no-color", 0, NULL, 1002 },
	{ "debug", 0, NULL, 'D' },
	{ "diff-factor", 1, NULL, 'f' },
	{ "diff-multiplier", 1, NULL, 'm' },
	{ "help", 0, NULL, 'h' },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-getwork", 0, NULL, 1010 },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "no-redirect", 0, NULL, 1009 },
	{ "no-stratum", 0, NULL, 1007 },
	{ "no-extranonce", 0, NULL, 1012 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol", 0, NULL, 'P' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scan-time", 1, NULL, 's' },
	{ "scan-serial", 1, NULL, 'S' },
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "ztex", 1, NULL, 'z' },
	{ "vu9p", 1, NULL, 1050 },
	{ "vu9p-build-id", 1, NULL, 1051 },
	{ "vu9p-active-lanes", 1, NULL, 1052 },
	{ "vu9p-rate-hps", 1, NULL, 1053 },
	{ "vu9p-poll-work-ms", 1, NULL, 1054 },
	{ "auto-freq", 0, NULL, 1004 },
	{ "watts-per-fpga", 1, NULL, 1008 },
	{ "tui", 0, NULL, 1040 },
	{ "log-file", 1, NULL, 1041 },
	{ "hash-clock", 1, NULL, 1042 },
	{ "heartbeat-interval", 1, NULL, 1043 },
	{ "firmware", 0, NULL, 'F' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};

static struct work g_work = {{ 0 }};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
static bool submit_old = false;
static char *lp_id;
static pthread_mutex_t work_generation_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t work_generation = 1;

static time_t current_work_time(void)
{
	time_t work_time;

	pthread_mutex_lock(&g_work_lock);
	work_time = g_work_time;
	pthread_mutex_unlock(&g_work_lock);

	return work_time;
}

void stratum_work_invalidated(void)
{
	pthread_mutex_lock(&g_work_lock);
	g_work_time = 0;
	pthread_mutex_unlock(&g_work_lock);
	restart_threads();
}

static void workio_cmd_free(struct workio_cmd *wc);
static uint64_t ztex_rb_now_us(void);
static void vg_arm_reconfig_guard(struct ztex_stats *stats,
	int fallback_rung, bool recovery_attempted);


#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid,sz,s) {} /* only do process affinity */
#endif

static void affine_to_cpu_mask(int id, uint8_t mask) {
	cpu_set_t set;
	CPU_ZERO(&set);
	uint8_t i;
	for ( i = 0; i < num_cpus; i++) {
		// cpu mask
		if (mask & (1<<i)) { CPU_SET(i, &set); }
	}
	if (id == -1) {
		// process affinity
		sched_setaffinity(0, sizeof(&set), &set);
	} else {
		// thread only
		pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
	}
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, uint8_t mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, uint8_t mask) { }
#endif

void get_currentalgo(char* buf, int sz)
{
	snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason)
{
	exit(reason);
}

static void bc3_ztex_v2_request_control_stop(bool failure)
{
	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	(void)bc3_ztex_shutdown_request(&bc3_ztex_v2_shutdown, failure);
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
}

static void bc3_ztex_v2_control_snapshot(bool *requested, bool *failure)
{
	if (!requested || !failure)
		return;
	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	*requested = bc3_ztex_v2_shutdown.stop_requested;
	*failure = bc3_ztex_v2_shutdown.failure;
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
}

static bool bc3_ztex_v2_enqueue_workio_stop(void)
{
	bool enqueued = false;
	uint64_t now_us = ztex_rb_now_us();

	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	if (now_us != 0 &&
	    bc3_ztex_shutdown_can_enqueue(&bc3_ztex_v2_shutdown)) {
		enqueued = tq_push(thr_info[work_thr_id].q,
			&bc3_ztex_v2_workio_stop_command);
		if (enqueued && !bc3_ztex_shutdown_mark_enqueued(
			    &bc3_ztex_v2_shutdown, now_us))
			enqueued = false; /* impossible under the held control lock */
	}
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
	return enqueued;
}

static bool bc3_ztex_v2_mark_workio_stop_consumed(void)
{
	bool consumed;

	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	consumed = bc3_ztex_shutdown_mark_consumed(&bc3_ztex_v2_shutdown);
	if (!consumed)
		(void)bc3_ztex_shutdown_request(&bc3_ztex_v2_shutdown, true);
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
	return consumed;
}

static bool bc3_ztex_v2_workio_stop_handshake_complete(void)
{
	bool complete;

	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	complete = bc3_ztex_shutdown_handshake_complete(
		&bc3_ztex_v2_shutdown);
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
	return complete;
}

static bool bc3_ztex_v2_final_success(int worker_result)
{
	bool success;

	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	success = bc3_ztex_shutdown_final_success(&bc3_ztex_v2_shutdown,
		worker_result);
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
	return success;
}

static bool bc3_ztex_v2_workio_flush_expired(void)
{
	uint64_t now;
	bool expired;

	now = ztex_rb_now_us();
	pthread_mutex_lock(&bc3_ztex_v2_control_lock);
	expired = bc3_ztex_shutdown_expired(&bc3_ztex_v2_shutdown, now,
		BC3_ZTEX_V2_WORKIO_FLUSH_TIMEOUT_US);
	pthread_mutex_unlock(&bc3_ztex_v2_control_lock);
	return expired;
}

static inline void work_free(struct work *w)
{
	if (w->txs) free(w->txs);
	if (w->workid) free(w->workid);
	if (w->job_id) free(w->job_id);
	if (w->xnonce2) free(w->xnonce2);
	w->txs = NULL;
	w->workid = NULL;
	w->job_id = NULL;
	w->xnonce2 = NULL;
	w->xnonce2_len = 0;
	w->connection_generation = 0;
	w->job_epoch = 0;
}

#if defined(__GNUC__) || defined(__clang__)
#define WORK_MUST_CHECK __attribute__((warn_unused_result))
#else
#define WORK_MUST_CHECK
#endif

static inline WORK_MUST_CHECK bool work_copy(struct work *dest,
		const struct work *src)
{
	bool copied = work_clone_checked(dest, src);

	if (!copied)
		applog(LOG_ERR, "work copy failed: invalid ownership or out of memory");
	return copied;
}

static inline WORK_MUST_CHECK bool work_replace(struct work *dest,
		const struct work *src)
{
	bool replaced = work_replace_checked(dest, src);

	if (!replaced)
		applog(LOG_ERR, "work replacement failed: prior work preserved");
	return replaced;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	int data_size = sizeof(work->data), target_size = sizeof(work->target);
	int adata_sz = ARRAY_SIZE(work->data), atarget_sz = ARRAY_SIZE(work->target);

	if (jsonrpc_2) {
		return rpc2_job_decode(val, work);
	}

	if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}

	for (i = 0; i < adata_sz; i++)
		work->data[i] = le32dec(work->data + i);

	for (i = 0; i < atarget_sz; i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

// good alternative for wallet mining, difficulty and net hashrate
static const char *info_req =
"{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work)
{
	if (have_stratum || !allow_mininginfo)
		return false;

	int curl_err = 0;
	json_t *val = json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

	if (!val && curl_err == -1) {
		allow_mininginfo = false;
		if (opt_debug) {
			applog(LOG_DEBUG, "getmininginfo not supported");
		}
		return false;
	}
	else {
		json_t *res = json_object_get(val, "result");
		// "blocks": 491493 (= current work height - 1)
		// "difficulty": 0.99607860999999998
		// "networkhashps": 56475980
		if (res) {
			json_t *key = json_object_get(res, "difficulty");
			if (key && json_is_real(key)) {
				net_diff = json_real_value(key);
			}
			key = json_object_get(res, "networkhashps");
			if (key && json_is_integer(key)) {
				net_hashrate = (double) json_integer_value(key);
			}
			key = json_object_get(res, "blocks");
			if (key && json_is_integer(key)) {
				net_blocks = json_integer_value(key);
			}
			if (!work->height) {
				// complete missing data from getwork
				work->height = (uint32_t) net_blocks + 1;
				if (work->height > g_work.height) {
					restart_threads();
					if (!opt_quiet) {
						char netinfo[64] = { 0 };
						char srate[32] = { 0 };
						sprintf(netinfo, "diff %.2f", net_diff);
						if (net_hashrate) {
							format_hashrate(net_hashrate, srate);
							strcat(netinfo, ", net ");
							strcat(netinfo, srate);
						}
						applog(LOG_BLUE, "%s block %d, %s",
							algo_names[opt_algo], work->height, netinfo);
					}
				}
			}
		}
	}
	json_decref(val);
	return true;
}

#define BLOCK_VERSION_CURRENT 3

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	uchar *cbtx = NULL;
	int tx_count, tx_size;
	uchar txc_vi[9];
	uchar(*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool version_force = false;
	bool version_reduce = false;
	json_t *tmp, *txa;
	bool rc = false;

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = (int) json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
			else if (!strcmp(s, "version/force"))
				version_force = true;
			else if (!strcmp(s, "version/reduce"))
				version_reduce = true;
		}
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = (int) json_integer_value(tmp);
	applog(LOG_BLUE, "Current block is %d", work->height);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = (uint32_t) json_integer_value(tmp);
	if ((version & 0xffU) > BLOCK_VERSION_CURRENT) {
		if (version_reduce) {
			version = (version & ~0xffU) | BLOCK_VERSION_CURRENT;
		} else if (have_gbt && allow_getwork && !version_force) {
			applog(LOG_DEBUG, "Switching to getwork, gbt version %d", version);
			have_gbt = false;
			goto out;
		} else if (!version_force) {
			applog(LOG_ERR, "Unrecognized block version: %u", version);
			goto out;
		}
	}

	if (!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = (uint32_t) json_integer_value(tmp);

	if (!jobj_binary(val, "bits", &bits, sizeof(bits))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = (int) json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += (int) (strlen(tx_hex) / 2);
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? (int) strlen(cbtx_hex) / 2 : 0;
		cbtx = (uchar*) malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = (int64_t) (json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp));
		cbtx = (uchar*) malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8)
			cbtx[cbtx_size++] = n & 0xff;
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = (uint8_t) pk_script_size; /* txout-script length */
		memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		cbtx_size += (int) pk_script_size;
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
			n = (int) strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? (int) (strlen(s) / 2) : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
			               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}

	n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = (char*) malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = (uchar(*)[32]) calloc(((1 + tx_count + 1) & ~1), 32);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? (int) (strlen(tx_hex) / 2) : 0;
		unsigned char *tx = (uchar*) malloc(tx_size);
		if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
			applog(LOG_ERR, "JSON invalid transactions");
			free(tx);
			goto out;
		}
		sha256d(merkle_tree[1 + i], tx, tx_size);
		if (!submit_coinbase)
			strcat(work->txs, tx_hex);
	}
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++)
			sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	rc = true;
out:
	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = json_is_string(tmp) ? strdup(json_string_value(tmp)) : rpc_url;
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}

	free(merkle_tree);
	free(cbtx);
	return rc;
}

static int share_result(int result, struct work *work, const char *reason)
{
	char s[345];
	const char *sres;
	double hashrate;
	double reduced_factor;
	uint32_t accepted_snapshot;
	uint32_t rejected_snapshot;

	pthread_mutex_lock(&stats_lock);
	hashrate = sum_hashrate_slots(thr_hashrates, thr_hashrates_count);
	result ? accepted_count++ : rejected_count++;
	accepted_snapshot = accepted_count;
	rejected_snapshot = rejected_count;
	pthread_mutex_unlock(&stats_lock);

	global_hashrate = (uint64_t) hashrate;

	if (use_colors)
		sres = (result ? CL_GRN "yes!" : CL_RED "nooooo");
	else
		sres = (result ? "(yes!!!)" : "(nooooo)");

	sprintf(s, "%.2f", hashrate / 1000000.0);
	applog(LOG_NOTICE, "accepted: %lu/%lu (%.2f%%), %s MH/s %s",
		(unsigned long)accepted_snapshot,
		(unsigned long)(accepted_snapshot + rejected_snapshot),
		100. * accepted_snapshot /
			(accepted_snapshot + rejected_snapshot), s, sres);

	if (reason) {
		applog(LOG_WARNING, "reject reason: %s", reason);
		if (strncmp(reason, "low difficulty share", 20) == 0) {
			pthread_mutex_lock(&stats_lock);
			opt_diff_factor = (opt_diff_factor * 2.0) / 3.0;
			reduced_factor = opt_diff_factor;
			pthread_mutex_unlock(&stats_lock);
			applog(LOG_WARNING, "factor reduced to : %0.2f",
				reduced_factor);
			return 0;
		}
	}
	return 1;
}

enum upstream_submit_result {
	UPSTREAM_SUBMIT_FAILED = -1,
	UPSTREAM_SUBMIT_COMPLETE = 1
};

static enum upstream_submit_result submit_upstream_work(CURL *curl,
	struct workio_cmd *wc)
{
	struct work *work;
	json_t *val, *res, *reason;
	char s[JSON_BUF_LEN];
	char *stratum_line = NULL;
	int i;
	enum upstream_submit_result rc = UPSTREAM_SUBMIT_FAILED;
	bool stale = false;
	bool share_current = false;
	bool prevhash_matches = true;
	unsigned submit_id;

	if (!wc || wc->cmd != WC_SUBMIT_WORK || !wc->u.work)
		return UPSTREAM_SUBMIT_FAILED;
	work = wc->u.work;
	submit_id = wc->submit_ticket.id;

	if (have_stratum) {
		share_current = stratum_is_share_current(&stratum,
			work->connection_generation, work->job_epoch);
	} else if (!submit_old) {
		pthread_mutex_lock(&g_work_lock);
		prevhash_matches =
			memcmp(&work->data[1], &g_work.data[1], 32) == 0;
		pthread_mutex_unlock(&g_work_lock);
	}
	stale = stratum_submission_is_stale(have_stratum, share_current,
		submit_old, prevhash_matches);
	if (stale) {
		if (opt_debug)
			applog(LOG_DEBUG, have_stratum ?
				"DEBUG: stale Stratum generation/job epoch, discarding share" :
				"DEBUG: stale work detected, discarding");
		return UPSTREAM_SUBMIT_COMPLETE;
	}

	if (!have_stratum && allow_mininginfo) {
		struct work wheight;
		get_mininginfo(curl, &wheight);
		if (work->height && work->height <= net_blocks) {
			if (opt_debug)
				applog(LOG_WARNING, "block %u was already solved", work->height);
			return UPSTREAM_SUBMIT_COMPLETE;
		}
	}

	if (have_stratum) {
		uint32_t ntime, nonce;
		char ntimestr[9], noncestr[9];

		if (jsonrpc_2) {
			uchar hash[32];
			char auth_id[sizeof(rpc2_id)];

			if (!rpc2_id_copy(auth_id, sizeof(auth_id)))
				return UPSTREAM_SUBMIT_FAILED;
			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
			char *hashhex = abin2hex(hash, 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}\r\n",
					auth_id, work->job_id, noncestr, hashhex);
			free(hashhex);
		} else {
			char *xnonce2str;
			json_t *request;
			json_t *params;

			le32enc(&ntime, work->data[17]);
			le32enc(&nonce, work->data[19]);

			bin2hex(ntimestr, (const unsigned char *)(&ntime), 4);
			bin2hex(noncestr, (const unsigned char *)(&nonce), 4);
			if (opt_algo == ALGO_ODO && opt_debug) {
				applog(LOG_DEBUG, "STRATUM_SUBMIT: job=%s nonce=%s ntime=%s data19=%08X",
					work->job_id, noncestr, ntimestr, work->data[19]);
			}
			xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			if (!xnonce2str || !rpc_user || !work->job_id) {
				applog(LOG_ERR,
					"submit_upstream_work invalid/OOM Stratum fields");
				free(xnonce2str);
				goto out;
			}
			if (!wc->submit_ticket.valid ||
			    wc->submit_ticket.connection_generation !=
				work->connection_generation ||
			    submit_id < STRATUM_SUBMIT_ID_FIRST ||
			    submit_id > (unsigned)INT_MAX) {
				free(xnonce2str);
				applog(LOG_ERR,
					"Stratum submit command has no valid admission ticket");
				stratum_request_reconnect(&stratum,
					work->connection_generation);
				rc = UPSTREAM_SUBMIT_COMPLETE;
				goto out;
			}
			request = json_object();
			params = json_array();
			if (!request || !params ||
			    json_array_append_new(params, json_string(rpc_user)) ||
			    json_array_append_new(params, json_string(work->job_id)) ||
			    json_array_append_new(params, json_string(xnonce2str)) ||
			    json_array_append_new(params, json_string(ntimestr)) ||
			    json_array_append_new(params, json_string(noncestr)) ||
			    json_object_set_new(request, "method",
				    json_string("mining.submit")) ||
			    json_object_set(request, "params", params) ||
			    json_object_set_new(request, "id",
				    json_integer((int)submit_id))) {
				json_decref(request);
				json_decref(params);
				free(xnonce2str);
				applog(LOG_ERR,
					"submit_upstream_work failed to construct Stratum request");
				goto out;
			}
			/* request retained params; release the local reference. */
			json_decref(params);
			params = NULL;
			free(xnonce2str);
			stratum_line = json_dumps(request, JSON_COMPACT);
			json_decref(request);
			if (!stratum_line) {
				applog(LOG_ERR,
					"submit_upstream_work failed to encode Stratum request");
				goto out;
			}
		}

		if (!jsonrpc_2) {
			enum stratum_submit_mark_result marked =
				STRATUM_SUBMIT_MARK_INVALID;
			bool sent;

			/* Serialize the complete write plus state transition against the
			 * receive thread's exact response lookup. */
			pthread_mutex_lock(&g_submit_dispatch_lock);
			sent = stratum_send_line(&stratum, stratum_line,
				work->connection_generation, work->job_epoch);
			if (sent) {
				pthread_mutex_lock(&g_submit_map_lock);
				marked = stratum_submit_map_mark_sent(&g_submit_map,
					&wc->submit_ticket);
				pthread_mutex_unlock(&g_submit_map_lock);
			}
			pthread_mutex_unlock(&g_submit_dispatch_lock);

			if (!sent) {
				/* A failed write may have been partial. The transport helper
				 * poisons that socket; never retry an ambiguous request ID. */
				applog(LOG_ERR,
					"submit_upstream_work Stratum send failed; request will not be retried");
				rc = UPSTREAM_SUBMIT_COMPLETE;
				goto out;
			}
			if (marked == STRATUM_SUBMIT_MARK_INVALID) {
				applog(LOG_ERR,
					"Stratum submit ledger rejected a completed wire request; reconnecting");
				stratum_request_reconnect(&stratum,
					work->connection_generation);
				rc = UPSTREAM_SUBMIT_COMPLETE;
				goto out;
			}
			if (marked == STRATUM_SUBMIT_MARK_RETIRED) {
				if (opt_debug)
					applog(LOG_DEBUG,
						"DEBUG: completed submit belonged to a retired Stratum generation");
				rc = UPSTREAM_SUBMIT_COMPLETE;
				goto out;
			}
		} else if (unlikely(!stratum_send_line(&stratum, s,
			   work->connection_generation, work->job_epoch))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			if (!stratum_is_share_current(&stratum,
			    work->connection_generation, work->job_epoch)) {
				rc = UPSTREAM_SUBMIT_COMPLETE;
				goto out;
			}
			goto out;
		}
		free(stratum_line);
		stratum_line = NULL;

	} else if (work->txs) {

		char data_str[2 * sizeof(work->data) + 1];
		char *req;

		for (i = 0; i < ARRAY_SIZE(work->data); i++)
			be32enc(work->data + i, work->data[i]);
		bin2hex(data_str, (unsigned char *)work->data, 80);
		if (work->workid) {
			char *params;
			val = json_object();
			json_object_set_new(val, "workid", json_string(work->workid));
			params = json_dumps(val, 0);
			json_decref(val);
			req = (char*) malloc(128 + 2 * 80 + strlen(work->txs) + strlen(params));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":4}\r\n",
				data_str, work->txs, params);
			free(params);
		} else {
			req = (char*) malloc(128 + 2 * 80 + strlen(work->txs));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
				data_str, work->txs);
		}

		val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
		free(req);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}

		res = json_object_get(val, "result");
		if (json_is_object(res)) {
			char *res_str;
			bool sumres = false;
			void *iter = json_object_iter(res);
			while (iter) {
				if (json_is_null(json_object_iter_value(iter))) {
					sumres = true;
					break;
				}
				iter = json_object_iter_next(res, iter);
			}
			res_str = json_dumps(res, 0);
			share_result(sumres, work, res_str);
			free(res_str);
		} else
			share_result(json_is_null(res), work, json_string_value(res));

		json_decref(val);

	} else {

		char* gw_str = NULL;
		int data_size = 128;
		int adata_sz;

		if (jsonrpc_2) {
			char noncestr[9];
			char auth_id[sizeof(rpc2_id)];
			uchar hash[32];
			char *hashhex;

			if (!rpc2_id_copy(auth_id, sizeof(auth_id)))
				goto out;
			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
			hashhex = abin2hex(&hash[0], 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": "
						"{\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"},"
					"\"id\":4}\r\n",
					auth_id, work->job_id, noncestr, hashhex);
			free(hashhex);

			/* issue JSON-RPC request */
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
			if (unlikely(!val)) {
				applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
				goto out;
			}
			res = json_object_get(val, "result");
			json_t *status = json_object_get(res, "status");
			bool valid = !strcmp(status ? json_string_value(status) : "", "OK");
			if (valid)
				share_result(valid, work, NULL);
			else {
				json_t *err = json_object_get(res, "error");
				const char *sreason = json_string_value(json_object_get(err, "message"));
					share_result(valid, work, sreason);
					if (sreason && !strcasecmp("Invalid job id", sreason)) {
						/* work is the private queue-owned submission copy and is
						 * released immediately after this call.  Do not clone shared
						 * g_work into it; only invalidate the publication timestamp. */
						pthread_mutex_lock(&g_work_lock);
						g_work_time = 0;
						pthread_mutex_unlock(&g_work_lock);
						restart_threads();
					}
			}
			json_decref(val);
			return UPSTREAM_SUBMIT_COMPLETE;

		}

		adata_sz = data_size / sizeof(uint32_t);

		/* build hex string */
		for (i = 0; i < adata_sz; i++)
			le32enc(&work->data[i], work->data[i]);

		gw_str = abin2hex((uchar*)work->data, data_size);

		if (unlikely(!gw_str)) {
			applog(LOG_ERR, "submit_upstream_work OOM");
			return UPSTREAM_SUBMIT_FAILED;
		}

		/* build JSON-RPC request */
		snprintf(s, JSON_BUF_LEN,
			"{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n", gw_str);
		free(gw_str);

		/* issue JSON-RPC request */
		val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}
		res = json_object_get(val, "result");
		reason = json_object_get(val, "reject-reason");
		share_result(json_is_true(res), work, reason ? json_string_value(reason) : NULL);

		json_decref(val);
	}

	rc = UPSTREAM_SUBMIT_COMPLETE;

out:
	free(stratum_line);
	return rc;
}

static const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

static const char *gbt_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES "}], \"id\":0}\r\n";
static const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	int err;
	bool rc;
	struct timeval tv_start, tv_end, diff;

start:
	gettimeofday(&tv_start, NULL);

	if (jsonrpc_2) {
		char s[128];
		char auth_id[sizeof(rpc2_id)];
		if (!rpc2_id_copy(auth_id, sizeof(auth_id)))
			return false;
		snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", auth_id);
		val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	} else {
		val = json_rpc_call(curl, rpc_url, rpc_userpass,
		                    have_gbt ? gbt_req : getwork_req,
		                    &err, have_gbt ? JSON_RPC_QUIET_404 : 0);
	}
	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!have_gbt && !allow_getwork) {
		applog(LOG_ERR, "No usable protocol");
		if (val)
			json_decref(val);
		return false;
	}

	if (have_gbt && allow_getwork && !val && err == CURLE_OK) {
		applog(LOG_NOTICE, "getblocktemplate failed, falling back to getwork");
		have_gbt = false;
		goto start;
	}

	if (!val)
		return false;

	if (have_gbt) {
		rc = gbt_work_decode(json_object_get(val, "result"), work);
		if (!have_gbt) {
			json_decref(val);
			goto start;
		}
	} else {
		rc = work_decode(json_object_get(val, "result"), work);
	}

	if (opt_protocol && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "got new work in %.2f ms",
		       (1000.0 * diff.tv_sec) + (0.001 * diff.tv_usec));
	}

	json_decref(val);

	// store work height in solo
	get_mininginfo(curl, work);

	return rc;
}

static void stratum_submit_cancel_ticket(
	struct stratum_submit_ticket *ticket)
{
	bool cancelled;

	if (!ticket || !ticket->valid)
		return;
	pthread_mutex_lock(&g_submit_map_lock);
	cancelled = stratum_submit_map_cancel(&g_submit_map, ticket);
	pthread_mutex_unlock(&g_submit_map_lock);
	if (!cancelled)
		applog(LOG_ERR,
			"Stratum submit ledger could not cancel queued command");
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	/* A valid ticket is still QUEUED and belongs to this physical command.
	 * Successful wire dispatch moves ownership into the SENT ledger and
	 * invalidates the ticket before the command is freed. */
	stratum_submit_cancel_ticket(&wc->submit_ticket);

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		if (wc->u.work) {
			work_free(wc->u.work);
			free(wc->u.work);
		}
		break;
	case WC_STOP:
		/* Process-lifetime singleton; the queue owns only its pointer. */
		return;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc)); /* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
	struct work *ret_work;
	int failures = 0;

	ret_work = (struct work*) calloc(1, sizeof(*ret_work));
	if (!ret_work)
		return false;

	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(curl, ret_work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

static bool bc3_ztex_v2_workio_retry_pause(void)
{
	uint64_t remaining_ms = opt_fail_pause > 0 ?
		(uint64_t)opt_fail_pause * UINT64_C(1000) : 0;

	while (remaining_ms != 0) {
		unsigned slice_ms = remaining_ms > 100 ? 100u :
			(unsigned)remaining_ms;

		if (bc3_ztex_v2_workio_flush_expired())
			return false;
		nmsleep(slice_ms);
		remaining_ms -= slice_ms;
	}
	return !bc3_ztex_v2_workio_flush_expired();
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution via JSON-RPC */
	while (1) {
		enum upstream_submit_result submit_result =
			submit_upstream_work(curl, wc);

		if (submit_result == UPSTREAM_SUBMIT_COMPLETE)
			break;
		if (bc3_ztex_v2_active &&
		    bc3_ztex_v2_workio_flush_expired()) {
			applog(LOG_ERR,
				"typed shutdown share flush timed out after %d seconds; abandoning queued submission and requiring rollback",
				BC3_ZTEX_V2_WORKIO_FLUSH_TIMEOUT_SEC);
			return false;
		}
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		if (bc3_ztex_v2_active) {
			if (!bc3_ztex_v2_workio_retry_pause()) {
				applog(LOG_ERR,
					"typed shutdown share flush deadline reached during retry pause");
				return false;
			}
		} else {
			sleep(opt_fail_pause);
		}
	}

	return true;
}

bool rpc2_login(CURL *curl)
{
	json_t *val;
	bool rc = false;
	struct timeval tv_start, tv_end, diff;
	char s[JSON_BUF_LEN];

	if (!jsonrpc_2)
		return false;

	snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {"
		"\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
		rpc_user, rpc_pass, USER_AGENT);

	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	gettimeofday(&tv_end, NULL);

	if (!val)
		goto end;

//	applog(LOG_DEBUG, "JSON value: %s", json_dumps(val, 0));

	rc = rpc2_login_decode(val);
	if (!rc)
		goto end;

	json_t *result = json_object_get(val, "result");

	if (!result) {
		rc = false;
		goto end;
	}

	json_t *job = json_object_get(result, "job");
	/* Seed the RPC2 cached blob/job state, then let the normal getjob path
	 * publish an owned work item.  Publishing g_work from inside login would
	 * deadlock when a miner is already waiting for work under g_work_lock. */
	if (!rpc2_job_decode(job, NULL)) {
		rc = false;
		goto end;
	}

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
				diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

end:
	if (val)
		json_decref(val);
	return rc;
}

bool rpc2_workio_login(CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	pthread_mutex_lock(&rpc2_login_lock);
	while (!rpc2_login(curl)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			pthread_mutex_unlock(&rpc2_login_lock);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		sleep(opt_fail_pause);
		pthread_mutex_unlock(&rpc2_login_lock);
		pthread_mutex_lock(&rpc2_login_lock);
	}
	pthread_mutex_unlock(&rpc2_login_lock);

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	if(jsonrpc_2 && !have_stratum) {
		ok = rpc2_workio_login(curl);
	}

	while (ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}
		if (bc3_ztex_v2_active &&
		    bc3_ztex_v2_workio_flush_expired()) {
			applog(LOG_ERR,
				"typed shutdown workio flush deadline reached before command dispatch");
			workio_cmd_free(wc);
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_GET_WORK:
			ok = workio_get_work(wc, curl);
			break;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			if (ok && bc3_ztex_v2_active &&
			    bc3_ztex_v2_workio_flush_expired()) {
				applog(LOG_ERR,
					"typed shutdown share flush deadline reached after queued submission");
				ok = false;
			}
			break;
		case WC_STOP:
			if (bc3_ztex_v2_active &&
			    wc == &bc3_ztex_v2_workio_stop_command) {
				if (!bc3_ztex_v2_mark_workio_stop_consumed())
					applog(LOG_ERR,
						"typed shutdown token state transition rejected");
				ok = false;
			} else {
				ok = false;
			}
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
	work_heap = (struct work*) tq_pop(thr->q, NULL);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

/* Atomically prove that this share still belongs to the authenticated socket
 * and live job window, then charge one end-to-end workio/response credit.
 * Lock order matches the transport code: socket -> Stratum work -> ledger. */
static enum stratum_submit_admit_result stratum_submit_admit_current(
	const struct work *work, struct stratum_submit_ticket *ticket,
	bool *stale)
{
	enum stratum_submit_admit_result result =
		STRATUM_SUBMIT_ADMIT_INVALID;

	if (stale)
		*stale = false;
	if (!work || !ticket || !stale)
		return result;
	stratum_submit_ticket_init(ticket);

	pthread_mutex_lock(&stratum.sock_lock);
	if (!stratum.curl || stratum.sock == CURL_SOCKET_BAD ||
	    !stratum_transport_job_usable(&stratum.transport,
		work->connection_generation)) {
		*stale = true;
		goto unlock_socket;
	}
	pthread_mutex_lock(&stratum.work_lock);
	if (!work->job_epoch || !stratum.minimum_valid_job_epoch ||
	    work->job_epoch < stratum.minimum_valid_job_epoch ||
	    work->job_epoch > stratum.job_epoch_counter) {
		*stale = true;
		goto unlock_work;
	}
	pthread_mutex_lock(&g_submit_map_lock);
	result = stratum_submit_map_admit(&g_submit_map,
		work->connection_generation, work->dev_board, work->dev_fpga,
		ticket);
	pthread_mutex_unlock(&g_submit_map_lock);

unlock_work:
	pthread_mutex_unlock(&stratum.work_lock);
unlock_socket:
	pthread_mutex_unlock(&stratum.sock_lock);
	return result;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	struct stratum_submit_ticket ticket;
	bool stale = false;
	bool standard_stratum = have_stratum && !jsonrpc_2;

	stratum_submit_ticket_init(&ticket);
	if (standard_stratum) {
		enum stratum_submit_admit_result admitted =
			stratum_submit_admit_current(work_in, &ticket, &stale);

		if (stale) {
			if (opt_debug)
				applog(LOG_DEBUG,
					"DEBUG: stale Stratum generation/job epoch, discarding share before workio");
			return true;
		}
		if (admitted == STRATUM_SUBMIT_ADMIT_FULL)
			return false;
		if (admitted == STRATUM_SUBMIT_ADMIT_EXHAUSTED) {
			applog(LOG_WARNING,
				"Stratum submit ID space exhausted; reconnecting before accepting more shares");
			stratum_request_reconnect(&stratum,
				work_in->connection_generation);
			return false;
		}
		if (admitted != STRATUM_SUBMIT_ADMIT_READY) {
			applog(LOG_ERR, "Stratum submit admission rejected");
			stratum_request_reconnect(&stratum,
				work_in ? work_in->connection_generation : 0);
			return false;
		}
	}

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc) {
		stratum_submit_cancel_ticket(&ticket);
		return false;
	}
	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	wc->submit_ticket = ticket;
	stratum_submit_ticket_init(&ticket);

	wc->u.work = (struct work*) calloc(1, sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	if (!work_copy(wc->u.work, work_in))
		goto err_out;

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void work_publish_release_work(void *opaque)
{
	work_free((struct work *)opaque);
}

static bool work_publish_submit_work(void *opaque, const void *candidate)
{
	return submit_work((struct thr_info *)opaque,
		(const struct work *)candidate);
}

static void work_publish_retry_pause(void *opaque, unsigned failed_attempt)
{
	(void)opaque;
	(void)failed_attempt;
	nmsleep(10);
}

enum stratum_gen_result {
	STRATUM_GEN_FATAL = -1,
	STRATUM_GEN_WAIT = 0,
	STRATUM_GEN_READY = 1
};

static WORK_MUST_CHECK enum stratum_gen_result stratum_gen_work_result(
		struct stratum_ctx *sctx, struct work *work)
{
	unsigned char merkle_root[64];
	unsigned char *job_xnonce2;
	char *new_job_id = NULL;
	uchar *new_xnonce2 = NULL;
	double diff_factor_snapshot;
	double share_diff;
	double new_net_diff;
	uint32_t share_target[8];
	uint32_t block_target[8];
	uint64_t connection_generation;
	size_t i, t;

	if (!sctx || !work)
		return STRATUM_GEN_FATAL;
	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_share(&sctx->transport) ||
	    sctx->sock == CURL_SOCKET_BAD) {
		pthread_mutex_unlock(&sctx->sock_lock);
		return STRATUM_GEN_WAIT;
	}
	connection_generation = sctx->transport.generation;
	pthread_mutex_lock(&sctx->work_lock);

	if (jsonrpc_2) {
		enum stratum_gen_result result;

		if (sctx->work.connection_generation == 0 &&
		    sctx->work.job_epoch == 0) {
			result = STRATUM_GEN_WAIT;
		} else if (sctx->work.connection_generation !=
			   sctx->transport.generation ||
			   sctx->work.job_epoch == 0 ||
			   sctx->minimum_valid_job_epoch == 0 ||
			   sctx->work.job_epoch < sctx->minimum_valid_job_epoch ||
			   sctx->work.job_epoch > sctx->job_epoch_counter) {
			result = STRATUM_GEN_FATAL;
		} else {
			result = work_replace(work, &sctx->work) ?
				STRATUM_GEN_READY : STRATUM_GEN_FATAL;
		}
		pthread_mutex_unlock(&sctx->work_lock);
		pthread_mutex_unlock(&sctx->sock_lock);
		if (result == STRATUM_GEN_FATAL) {
			applog(LOG_ERR,
				"RPC2 work generation failed: invalid ownership or out of memory");
			stratum_request_reconnect(sctx, connection_generation);
		}
		return result;
	} else {
		if (!sctx->job.job_id && !sctx->job.coinbase &&
		    sctx->job.connection_generation == 0 &&
		    sctx->job.job_epoch == 0)
			goto waiting_for_job;
		if (!stratum_transport_job_usable(&sctx->transport,
			sctx->job.connection_generation) ||
		    sctx->job.job_epoch == 0 ||
		    sctx->minimum_valid_job_epoch == 0 ||
		    sctx->job.job_epoch < sctx->minimum_valid_job_epoch ||
		    sctx->job.job_epoch > sctx->job_epoch_counter ||
		    !sctx->job.job_id || !sctx->job.coinbase ||
		    sctx->job.xnonce2_size != sctx->xnonce2_size ||
		    !stratum_xnonce_layout_valid(sctx->job.coinbase_size,
			sctx->job.xnonce2_offset, sctx->job.xnonce2_size) ||
		    !isfinite(sctx->job.diff) || sctx->job.diff <= 0.0 ||
		    (sctx->job.merkle_count != 0 && !sctx->job.merkle) ||
		    (opt_algo == ALGO_BLAKE3 && sctx->job.coinbase_size < 144))
			goto allocation_failed;
		for (i = 0; i < sctx->job.merkle_count; ++i)
			if (!sctx->job.merkle[i])
				goto allocation_failed;
		pthread_mutex_lock(&stats_lock);
		diff_factor_snapshot = opt_diff_factor;
		pthread_mutex_unlock(&stats_lock);
		if (!isfinite(diff_factor_snapshot) || diff_factor_snapshot <= 0.0)
			goto allocation_failed;
		share_diff = sctx->job.diff / diff_factor_snapshot;
		if (opt_algo == ALGO_DMD_GR || opt_algo == ALGO_GROESTL)
			share_diff /= 256.0;
		new_net_diff = ConvertBitsToDouble(
			swab32(le32dec(sctx->job.nbits)));
		if (!diff_to_target_checked(share_target, share_diff) ||
		    !diff_to_target_checked(block_target, new_net_diff))
			goto allocation_failed;
		job_xnonce2 = sctx->job.coinbase + sctx->job.xnonce2_offset;
		new_job_id = strdup(sctx->job.job_id);
		if (!new_job_id)
			goto allocation_failed;
		if (sctx->job.xnonce2_size != 0) {
			new_xnonce2 = (uchar *)malloc(sctx->job.xnonce2_size);
			if (!new_xnonce2)
				goto allocation_failed;
			memcpy(new_xnonce2, job_xnonce2,
				sctx->job.xnonce2_size);
		}

		/* Commit both owned fields together only after every allocation has
		 * succeeded.  Failure above leaves the caller's prior work intact. */
		free(work->job_id);
		free(work->xnonce2);
		work->job_id = new_job_id;
		work->xnonce2 = new_xnonce2;
		work->xnonce2_len = sctx->job.xnonce2_size;
		work->connection_generation = sctx->job.connection_generation;
		work->job_epoch = sctx->job.job_epoch;
		new_job_id = NULL;
		new_xnonce2 = NULL;

		/* Generate merkle root */
		switch (opt_algo) {
			case ALGO_GROESTL:
			case ALGO_BLAKECOIN:
				sha256(sctx->job.coinbase, (int) sctx->job.coinbase_size, merkle_root);
				break;
			default:
				/* DigiByte (OdoCrypt) and most coins use SHA256d for coinbase */
				sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
		}

		for (i = 0; i < sctx->job.merkle_count; i++) {
			memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
			sha256d(merkle_root, merkle_root, 64);
		}

		/* Increment extranonce2 */
		for (t = 0; t < sctx->job.xnonce2_size &&
		    !(++job_xnonce2[t]); ++t)
			;

		/* Assemble block header */
		if (opt_algo == ALGO_BLAKE3) {
			/*
			 * Decred stratum header reconstruction:
			 *
			 * Pool sends via mining.notify:
			 *   version  (4 bytes from param[5])
			 *   prevBlock (32 bytes from param[1])
			 *   genTx1   (144 bytes from param[2]) = header[36:180]
			 *   nTime    (4 bytes from param[7])
			 *   nBits    (4 bytes from param[6])
			 *
			 * The coinbase buffer = coinb1 + xnonce1 + xnonce2 + coinb2
			 * For Decred: coinb1 = genTx1 (144 bytes = header[36:180])
			 *
			 * Reconstructed 180-byte header layout:
			 *   [0:4]     = version
			 *   [4:36]    = prevBlock
			 *   [36:144]  = genTx1[0:108] (merkleRoot through nonce)
			 *   [144:148] = extraNonce1 (from xnonce1)
			 *   [148:152] = extraNonce2 (from xnonce2)
			 *   [152:180] = genTx1[116:144] (remaining ExtraData + StakeVersion)
			 *
			 * But actually, the coinbase already has xnonce1+xnonce2 spliced in
			 * by stratum_notify, so coinbase = genTx1[0:108] + xnonce1 + xnonce2 + coinb2
			 * = full header[36:180] with extranonces filled in.
			 */
			unsigned char hdr[180];
			memset(hdr, 0, 180);

			/* Bytes 0-3: version */
			memcpy(hdr, sctx->job.version, 4);

			/* Bytes 4-35: prevhash */
			memcpy(hdr + 4, sctx->job.prevhash, 32);

			/* Bytes 36-179: from coinbase (which is genTx1 + xnonce1 + xnonce2 + coinb2) */
			memcpy(hdr + 36, sctx->job.coinbase, 144);

			/* Overwrite nTime at offset 136 with the notify value */
			memcpy(hdr + 136, sctx->job.ntime, 4);

			/* Clear nonce at offset 140 - FPGA will scan it */
			memset(hdr + 140, 0, 4);

			/* Load into work.data as LE uint32 words */
			memset(work->data, 0, 192);
			for (i = 0; i < 45; i++)
				work->data[i] = le32dec(hdr + i * 4);

			work->height = work->data[32];  /* height at offset 128 = word 32 */
		} else {
			/* Standard path (groestl, OdoCrypt, etc.):
			 * Same work.data format as groestl — proven to work with stratum. */
			memset(work->data, 0, 128);
			work->data[0] = le32dec(sctx->job.version);
			for (i = 0; i < 8; i++)
				work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
			for (i = 0; i < 8; i++)
				work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);
			work->data[17] = le32dec(sctx->job.ntime);
			work->data[18] = le32dec(sctx->job.nbits);
			work->data[20] = 0x80000000;
			work->data[31] = 0x00000280;
		}

		memcpy(work->target, share_target, sizeof(work->target));
		memcpy(work->block_target, block_target,
			sizeof(work->block_target));
		pthread_mutex_unlock(&sctx->work_lock);
		pthread_mutex_unlock(&sctx->sock_lock);

		pthread_mutex_lock(&stats_lock);
		g_net_diff = new_net_diff;
		pthread_mutex_unlock(&stats_lock);

		if (opt_debug) {
			char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
					work->job_id, xnonce2str ? xnonce2str : "<oom>",
					swab32(work->data[17]));
			free(xnonce2str);
		}
		return STRATUM_GEN_READY;
	}

allocation_failed:
	free(new_job_id);
	free(new_xnonce2);
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);
	applog(LOG_ERR, "stratum work generation failed: invalid job ownership or out of memory");
	stratum_request_reconnect(sctx, connection_generation);
	return STRATUM_GEN_FATAL;

waiting_for_job:
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);
	return STRATUM_GEN_WAIT;
}

bool rpc2_stratum_job(struct stratum_ctx *sctx, json_t *params)
{
	bool ret = false;
	/* Lock order is global work -> socket generation -> Stratum work. */
	pthread_mutex_lock(&g_work_lock);
	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_share(&sctx->transport) ||
	    sctx->sock == CURL_SOCKET_BAD)
		goto unlock_socket;
	pthread_mutex_lock(&sctx->work_lock);
	ret = rpc2_job_decode(params, &sctx->work);

	if (ret) {
		sctx->work.connection_generation = sctx->transport.generation;
		sctx->job_epoch_counter++;
		if (sctx->job_epoch_counter == 0) {
			sctx->job_epoch_counter = 1;
			sctx->minimum_valid_job_epoch = 1;
		}
		sctx->work.job_epoch = sctx->job_epoch_counter;
		sctx->minimum_valid_job_epoch = sctx->work.job_epoch;
		ret = work_replace(&g_work, &sctx->work);
		if (ret)
			g_work_time = 0;
	}

	pthread_mutex_unlock(&sctx->work_lock);
unlock_socket:
	pthread_mutex_unlock(&sctx->sock_lock);
	pthread_mutex_unlock(&g_work_lock);

	return ret;
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	int thr_id = mythr->id;
	struct work work;
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	time_t firstwork_time = 0;
	unsigned char *scratchbuf = NULL;
	char s[16];
	int i;

	memset(&work, 0, sizeof(work));

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	if (opt_priority == 0) {
		setpriority(PRIO_PROCESS, 0, 19);
		drop_policy();
	} else {
		int prio = 0;
#ifndef WIN32
		prio = 18;
		// note: different behavior on linux (-19 to 19)
		switch (opt_priority) {
			case 1:
				prio = 5;
				break;
			case 2:
				prio = 0;
				break;
			case 3:
				prio = -5;
				break;
			case 4:
				prio = -10;
				break;
			case 5:
				prio = -15;
		}
		if (opt_debug)
			applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
				thr_id,	opt_priority, prio);
#endif
		setpriority(PRIO_PROCESS, 0, prio);
		if (opt_priority == 0) {
			drop_policy();
		}
	}

	/* Cpu thread affinity */
	if (num_cpus > 1) {
		if (opt_affinity == -1 && opt_n_threads > 1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)", thr_id,
						thr_id % num_cpus, (1 << (thr_id % num_cpus)));
			affine_to_cpu_mask(thr_id, 1 << (thr_id % num_cpus));
		} else if (opt_affinity != -1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu mask %x", thr_id,
						opt_affinity);
			affine_to_cpu_mask(thr_id, opt_affinity);
		}
	}

	while (1) {
		uint64_t hashes_done;
		struct timeval tv_start, tv_end, diff;
		int64_t max64;
		int wkcmp_offset = 0;
		int nonce_oft = 19*sizeof(uint32_t); // 76
		int wkcmp_sz = nonce_oft;
		int rc = 0;

		if (jsonrpc_2) {
			wkcmp_sz = nonce_oft = 39;
		}

		uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);

		if (have_stratum) {
			while (!jsonrpc_2 && time(NULL) >= current_work_time() + 120)
				sleep(1);

			pthread_mutex_lock(&g_work_lock);

			if ( (*nonceptr) >= end_nonce
				&& !( memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
				 jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0))
			{
				enum stratum_gen_result generated =
					stratum_gen_work_result(&stratum, &g_work);

				if (generated != STRATUM_GEN_READY) {
					if (generated == STRATUM_GEN_FATAL)
						applog(LOG_ERR,
							"failed to roll Stratum extranonce work");
					pthread_mutex_unlock(&g_work_lock);
					nmsleep(100);
					continue;
				}
			}

		} else {

			int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
			/* obtain new work from internal workio thread */
			pthread_mutex_lock(&g_work_lock);
			if (!have_stratum &&
			    (time(NULL) - g_work_time >= min_scantime ||
			     work.data[19] >= end_nonce)) {
				if (unlikely(!get_work(mythr, &g_work))) {
					applog(LOG_ERR, "work retrieval failed, exiting "
						"mining thread %d", mythr->id);
					pthread_mutex_unlock(&g_work_lock);
					goto out;
				}
				g_work_time = have_stratum ? 0 : time(NULL);
			}
			if (have_stratum) {
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}
		if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
			jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0)
		{
			if (!work_replace(&work, &g_work)) {
				pthread_mutex_unlock(&g_work_lock);
				nmsleep(100);
				continue;
			}
			nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);
			*nonceptr = 0xffffffffU / opt_n_threads * thr_id;
		} else
			++(*nonceptr);
		pthread_mutex_unlock(&g_work_lock);
		work_restart[thr_id].restart = 0;

		/* prevent scans before a job is received */
		if (have_stratum && !work.data[0]) {
			sleep(1);
			continue;
		}

		/* adjust max_nonce to meet target scan time */
		if (have_stratum)
			max64 = LP_SCANTIME;
		else
			max64 = current_work_time() + (have_longpoll ? LP_SCANTIME : opt_scantime)
					- time(NULL);

		max64 *= (int64_t) thr_hashrates[thr_id];

		if (max64 <= 0) {
			switch (opt_algo) {
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
			case ALGO_MYR_GR:
				max64 = 0x3ffff;
				break;
			case ALGO_BLAKECOIN:
			case ALGO_VCASH:
				max64 = 0x7ffffLL;
				break;
			default:
				max64 = 0x1fffffLL;
				break;
			}
		}
		if ((*nonceptr) + max64 > end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = (*nonceptr) + (uint32_t) max64;

		hashes_done = 0;
		gettimeofday((struct timeval *) &tv_start, NULL);

		if (firstwork_time == 0)
			firstwork_time = time(NULL);

		/* scan nonces for a proof-of-work hash */
		switch (opt_algo) {
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
			rc = scanhash_groestl(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_MYR_GR:
			rc = scanhash_myriad(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			rc = scanhash_blakecoin(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_SHA3T:
			rc = scanhash_sha3t(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		default:
			/* should never happen */
			goto out;
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet) {
			sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
					thr_hashrates[thr_id] / 1e3);
			applog(LOG_INFO, "CPU #%d: %s kH/s", thr_id, s);
		}

		/* if nonce found, submit work */
		if (rc) {
			if (!submit_work(mythr, &work))
				break;
			// prevent stale work in solo
			// we can't submit twice a block!
			if (!have_stratum && !have_longpoll) {
				pthread_mutex_lock(&g_work_lock);
				// will force getwork
				g_work_time = 0;
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}

	}

out:
	tq_freeze(mythr->q);

	return NULL;
}

void restart_threads(void)
{
	size_t i;

	/* Device workers live after the four service slots, outside the old
	 * [0,g_miner_count) loop.  Signal the complete allocation and advance a
	 * locked generation so the R34 controller cannot lose an event by clearing
	 * its legacy byte concurrently with this broadcast. */
	pthread_mutex_lock(&work_generation_lock);
	work_generation++;
	if (work_generation == 0)
		work_generation = 1;
	if (work_restart)
		for (i = 0; i < thr_hashrates_count; ++i)
			work_restart[i].restart = 1;
	pthread_mutex_unlock(&work_generation_lock);
}

static uint64_t current_work_generation(void)
{
	uint64_t generation;

	pthread_mutex_lock(&work_generation_lock);
	generation = work_generation;
	pthread_mutex_unlock(&work_generation_lock);
	return generation;
}

static void *longpoll_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info*) userdata;
	CURL *curl = NULL;
	char *copy_start, *hdr_path = NULL, *lp_url = NULL;
	bool need_slash = false;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL init failed");
		goto out;
	}

start:
	hdr_path = (char*) tq_pop(mythr->q, NULL);
	if (!hdr_path)
		goto out;

	/* full URL */
	if (strstr(hdr_path, "://")) {
		lp_url = hdr_path;
		hdr_path = NULL;
	}

	/* absolute path, on current server */
	else {
		copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
		if (rpc_url[strlen(rpc_url) - 1] != '/')
			need_slash = true;

		lp_url = (char*) malloc(strlen(rpc_url) + strlen(copy_start) + 2);
		if (!lp_url)
			goto out;

		sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
	}

	if (!opt_quiet)
		applog(LOG_INFO, "Longpoll enabled for %s", lp_url);

	while (1) {
		json_t *val;
		char *req = NULL;
		int err;

		if (jsonrpc_2) {
			char s[128];
			char auth_id[sizeof(rpc2_id)];
			if (!rpc2_id_copy(auth_id, sizeof(auth_id))) {
				sleep(1);
				continue;
			}
			snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", auth_id);
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, &err, JSON_RPC_LONGPOLL);
		} else {
			if (have_gbt) {
				req = (char*) malloc(strlen(gbt_lp_req) + strlen(lp_id) + 1);
				sprintf(req, gbt_lp_req, lp_id);
			}
			val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, JSON_RPC_LONGPOLL);
			val = json_rpc_call(curl, lp_url, rpc_userpass,
					    req ? req : getwork_req, &err,
					    JSON_RPC_LONGPOLL);
			free(req);
		}

		if (have_stratum) {
			if (val)
				json_decref(val);
			goto out;
		}
		if (likely(val)) {
			bool rc;
			char *start_job_id;
			json_t *res, *soval;
			res = json_object_get(val, "result");
			if (!jsonrpc_2) {
				soval = json_object_get(res, "submitold");
				submit_old = soval ? json_is_true(soval) : false;
			}
			pthread_mutex_lock(&g_work_lock);
			start_job_id = g_work.job_id ? strdup(g_work.job_id) : NULL;
			if (have_gbt)
				rc = gbt_work_decode(res, &g_work);
			else
				rc = work_decode(res, &g_work);
			if (rc) {
				if (g_work.job_id && (!start_job_id ||
				    strcmp(start_job_id, g_work.job_id))) {
					if (opt_debug)
						applog(LOG_BLUE, "Longpoll pushed new work");
					time(&g_work_time);
					restart_threads();
				}
			}
			free(start_job_id);
			pthread_mutex_unlock(&g_work_lock);
			json_decref(val);
		} else {
			pthread_mutex_lock(&g_work_lock);
			g_work_time -= LP_SCANTIME;
			pthread_mutex_unlock(&g_work_lock);
			if (err == CURLE_OPERATION_TIMEDOUT) {
				restart_threads();
			} else {
				have_longpoll = false;
				restart_threads();
				free(hdr_path);
				free(lp_url);
				lp_url = NULL;
				sleep(opt_fail_pause);
				goto start;
			}
		}
	}

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static bool stratum_handle_response(char *buf,
	uint64_t received_generation)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;
	bool valid = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val))
		goto out;

	if (jsonrpc_2)
	{
		const char *status_text = NULL;
		if (!res_val && !err_val)
			goto out;

		if (!json_is_object(res_val))
			goto out;
		{
			json_t *status = json_object_get(res_val, "status");
			if (!json_is_string(status))
				goto out;
			status_text = json_string_value(status);
		}
		valid = status_text && !strcmp(status_text, "OK") &&
			(!err_val || json_is_null(err_val));
		share_result(valid, NULL, err_val ? json_string_value(err_val) : NULL);

	} else {
		struct stratum_submit_entry entry;
		const char *reject_reason = NULL;
		int sid;
		int64_t sid_wide;
		bool matched = false;

		if (!json_is_integer(id_val))
			goto out;
		sid_wide = (int64_t)json_integer_value(id_val);
		if (sid_wide >= 1 && sid_wide <= 3) {
			ret = true;
			goto out;
		}
		if (sid_wide < 4 || sid_wide > INT_MAX)
			goto out;
		sid = (int)sid_wide;
		memset(&entry, 0, sizeof(entry));
		pthread_mutex_lock(&g_submit_dispatch_lock);
		pthread_mutex_lock(&g_submit_map_lock);
		matched = stratum_submit_map_take(&g_submit_map,
			received_generation, (unsigned)sid, &entry);
		pthread_mutex_unlock(&g_submit_map_lock);
		pthread_mutex_unlock(&g_submit_dispatch_lock);
		if (!matched) {
			applog(LOG_WARNING,
				"Ignoring unknown or duplicate Stratum submit response id %d",
				sid);
			ret = true;
			goto out;
		}
		/* Exact (received_generation, id) matching is the linearization
		 * point. A disconnect after the line was removed from that socket
		 * must not erase an otherwise terminal accepted/rejected response. */
		if (!json_is_boolean(res_val))
			goto out;
		valid = json_is_true(res_val) &&
			(!err_val || json_is_null(err_val));
		if (json_is_array(err_val))
			reject_reason = json_string_value(json_array_get(err_val, 1));
		else if (json_is_string(err_val))
			reject_reason = json_string_value(err_val);
		else if (json_is_object(err_val))
			reject_reason = json_string_value(
				json_object_get(err_val, "message"));
		share_result(valid, NULL, reject_reason);
		if (entry.board >= 0) {
			const char *bn = tui_board_name(entry.board);
			tui_record_share(entry.board, entry.fpga, valid);
			applog(LOG_NOTICE, "Share from %s FPGA %d %s",
				bn ? bn : "?", entry.fpga,
				valid ? "ACCEPTED" : "REJECTED");
		}
	}

	ret = true;

out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	char *s;
	uint64_t received_generation = 0;

	stratum.url = (char*) tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

	while (1) {
		int failures = 0;

		if (stratum_need_reset) {
			stratum_need_reset = false;
			stratum_disconnect(&stratum);
			if (strcmp(stratum.url, rpc_url)) {
				free(stratum.url);
				stratum.url = strdup(rpc_url);
				applog(LOG_BLUE, "Connection changed to %s", short_url);
			} else if (!opt_quiet) {
				applog(LOG_DEBUG, "Stratum connection reset");
			}
		}

		while (!stratum_is_authenticated(&stratum)) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url)
					|| !stratum_subscribe(&stratum)
					|| !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
				continue;
			}

			if (jsonrpc_2) {
				enum stratum_gen_result installed;
				pthread_mutex_lock(&g_work_lock);
				installed = stratum_gen_work_result(&stratum, &g_work);
				if (installed == STRATUM_GEN_READY)
					g_work_time = 0;
				pthread_mutex_unlock(&g_work_lock);
				if (installed != STRATUM_GEN_READY) {
					applog(LOG_ERR,
						"authenticated RPC2 work is %s",
						installed == STRATUM_GEN_WAIT ?
						"not available" : "invalid");
					stratum_disconnect(&stratum);
					continue;
				}
			}
		}

		{
			enum stratum_gen_result generated = STRATUM_GEN_WAIT;
			bool needs_generation = false;

			pthread_mutex_lock(&g_work_lock);
			if (stratum.job.job_id &&
			    (!g_work_time || !g_work.job_id ||
			     strcmp(stratum.job.job_id, g_work.job_id))) {
				needs_generation = true;
				generated = stratum_gen_work_result(&stratum, &g_work);
				if (generated == STRATUM_GEN_READY)
					time(&g_work_time);
			}
			pthread_mutex_unlock(&g_work_lock);

			if (needs_generation) {
				if (generated != STRATUM_GEN_READY) {
					if (generated == STRATUM_GEN_FATAL) {
						applog(LOG_ERR,
							"invalid authenticated Stratum work; reconnecting");
						stratum_disconnect(&stratum);
					}
					continue;
				}

				if (stratum.job.clean || jsonrpc_2) {
					if (!opt_quiet)
						applog(LOG_BLUE, "%s %s block %" PRIu32, short_url,
							algo_names[opt_algo], stratum.bloc_height);
					restart_threads();
				} else if (opt_debug && !opt_quiet) {
					applog(LOG_BLUE, "%s asks job %s for block %" PRIu32, short_url,
						stratum.job.job_id,
						stratum.bloc_height);
				}
			}
		}

		if (!stratum_socket_full(&stratum, opt_timeout)) {
			applog(LOG_ERR, "Stratum connection timeout");
			s = NULL;
		} else {
			received_generation = 0;
			s = stratum_recv_line(&stratum, &received_generation);
		}
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		{
			enum stratum_method_result method_result =
				stratum_handle_method(&stratum, s);

			if (method_result == STRATUM_METHOD_FATAL) {
				free(s);
				stratum_disconnect(&stratum);
				applog(LOG_ERR,
					"fatal Stratum method/input error; reconnecting");
				continue;
			}
			if (method_result == STRATUM_METHOD_UNHANDLED &&
			    !stratum_handle_response(s, received_generation)) {
				free(s);
				stratum_disconnect(&stratum);
				applog(LOG_ERR,
					"malformed or unmatched Stratum response; reconnecting");
				continue;
			}
		}
		free(s);
	}
out:
	return NULL;
}

static void show_version_and_exit(void)
{
	printf("\n built on " __DATE__
#ifdef _MSC_VER
	 " with VC++ 2013\n");
#elif defined(__GNUC__)
	 " with GCC");
	printf(" %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

	printf(" features:"
#if defined(USE_ASM) && defined(__i386__)
		" i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
		" x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
		" SSE2"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
		" AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
		" AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
		" XOP"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
		" ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
		" ARMv5E"
#endif
#if defined(__ARM_NEON__)
		" NEON"
#endif
#endif
		"\n\n");

	/* dependencies versions */
	printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
	printf("jansson/%s ", JANSSON_VERSION);
#endif
#ifdef PTW32_VERSION
	printf("pthreads/%d.%d.%d.%d ", PTW32_VERSION);
#endif
	printf("\n");
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

static bool get_serial_fpga_list(char *arg)
{
	char *token = strtok(arg, ", \n\r");
	int i;

	for (i = 0; i < g_serial_device_count && i < MAX_SERIAL_DEVICES; ++i) {
		free(serial_fpga_list[i]);
		serial_fpga_list[i] = NULL;
	}
	g_serial_device_count = 0;

	while (token != NULL) {
		char *device;

		if (g_serial_device_count >= MAX_SERIAL_DEVICES) {
			fprintf(stderr,
				"ERROR: --scan-serial accepts at most %d devices\n",
				MAX_SERIAL_DEVICES);
			goto failed;
		}
		device = strdup(token);
		if (!device) {
			fprintf(stderr,
				"ERROR: Unable to allocate --scan-serial device\n");
			goto failed;
		}
		serial_fpga_list[g_serial_device_count++] = device;
		token = strtok(NULL, ", \n\r");
	}
	
	if (g_serial_device_count == 0) {
		fprintf(stderr, "ERROR: Unable to parse --scan-serial parameter\n");
		return false;
	}

	return true;

failed:
	for (i = 0; i < g_serial_device_count; ++i) {
		free(serial_fpga_list[i]);
		serial_fpga_list[i] = NULL;
	}
	g_serial_device_count = 0;
	return false;
}

static bool parse_vu9p_hex32(const char *arg, uint32_t *value)
{
	uint32_t parsed = 0;
	int i;

	if (!arg || !value || strlen(arg) != 8)
		return false;
	for (i = 0; i < 8; i++) {
		unsigned int digit;
		unsigned char c = (unsigned char)arg[i];

		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = (unsigned int)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			digit = (unsigned int)(c - 'A' + 10);
		else
			return false;
		parsed = (parsed << 4) | digit;
	}
	*value = parsed;
	return true;
}

static bool parse_vu9p_u64(const char *arg, uint64_t maximum,
		uint64_t *value)
{
	unsigned long long parsed;
	char *end;

	if (!arg || !value || arg[0] < '0' || arg[0] > '9')
		return false;
	errno = 0;
	parsed = strtoull(arg, &end, 10);
	if (errno == ERANGE || end == arg || *end != '\0' ||
	    (uint64_t)parsed > maximum)
		return false;
	*value = (uint64_t)parsed;
	return true;
}

void parse_arg(int key, char *arg)
{
	uint64_t vu9p_value;
	char *p;
	int v, i;
	double d;

	switch(key) {
	case 'a':
		for (i = 0; i < ALGO_COUNT; i++) {
			v = (int) strlen(algo_names[i]);
			if (!strncmp(arg, algo_names[i], v)) {
				if (arg[v] == '\0') {
					opt_algo = (enum algos) i;
					break;
				}
			}
		}
		if (i == ALGO_COUNT) {
			applog(LOG_ERR, "Unknown algo parameter '%s'", arg);
			show_usage_and_exit(1);
		}
		break;
	case 'b':
		p = strstr(arg, ":");
		if (p) {
			/* ip:port */
			if (p - arg > 0) {
				free(opt_api_allow);
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if (arg && strstr(arg, ".")) {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
		}
		else if (arg) {
			/* port or 0 to disable */
			opt_api_listen = atoi(arg);
		}
		break;
	case 1030: /* --api-remote */
		opt_api_remote = 1;
		break;
	case 'c': {
		json_error_t err;
		json_t *config = JSON_LOAD_FILE(arg, &err);
		if (!json_is_object(config)) {
			if (err.line < 0)
				fprintf(stderr, "%s\n", err.text);
			else
				fprintf(stderr, "%s:%d: %s\n",
					arg, err.line, err.text);
		} else {
			parse_config(config, arg);
			json_decref(config);
		}
		break;
	}
	case 'C':
		opt_use_cpu = true;
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'S':
		if (!get_serial_fpga_list(arg))
			show_usage_and_exit(1);
		opt_use_serial = true;
		break;
	case 1050:  /* --vu9p host:port[,host:port...] (vu9p_bridge endpoints) */
		if (vu9p_parse_spec(arg) <= 0) {
			fprintf(stderr, "ERROR: Unable to parse --vu9p parameter\n");
			show_usage_and_exit(1);
		}
		opt_use_vu9p = true;
		break;
	case 1051:
		opt_vu9p_options_seen = true;
		if (!parse_vu9p_hex32(arg, &opt_vu9p_build_id)) {
			fprintf(stderr, "ERROR: --vu9p-build-id requires exactly eight hex digits\n");
			show_usage_and_exit(1);
		}
		opt_vu9p_build_id_set = true;
		break;
	case 1052:
		opt_vu9p_options_seen = true;
		if (!parse_vu9p_u64(arg, UINT32_MAX, &vu9p_value) ||
		    !vu9p_active_lanes_valid((uint32_t)vu9p_value)) {
			fprintf(stderr, "ERROR: --vu9p-active-lanes must be 1 for BS1\n");
			show_usage_and_exit(1);
		}
		opt_vu9p_active_lanes = (uint32_t)vu9p_value;
		break;
	case 1053:
		opt_vu9p_options_seen = true;
		if (!parse_vu9p_u64(arg, UINT64_MAX, &vu9p_value) ||
		    vu9p_value == 0) {
			fprintf(stderr, "ERROR: --vu9p-rate-hps requires a positive integer\n");
			show_usage_and_exit(1);
		}
		opt_vu9p_rate_hps = vu9p_value;
		break;
	case 1054:
		opt_vu9p_options_seen = true;
		if (!parse_vu9p_u64(arg, UINT32_MAX, &vu9p_value) ||
		    vu9p_transaction_timeout_ms((uint32_t)vu9p_value) == 0) {
			fprintf(stderr,
			        "ERROR: --vu9p-poll-work-ms must leave a positive deadline for both POLL and STOP (minimum %u)\n",
			        (unsigned int)VU9P_POLL_INTERVAL_MS + 2U);
			show_usage_and_exit(1);
		}
		opt_vu9p_poll_work_ms = (uint32_t)vu9p_value;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999) /* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = (char*) calloc(p - ap + 1, 1);
				strncpy(rpc_user, ap, p - ap);
				free(rpc_pass);
				rpc_pass = strdup(++p);
				if (*p) *p++ = 'x';
				v = (int) strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "http://", 7) &&
			    strncasecmp(arg, "https://", 8) &&
			    strncasecmp(arg, "stratum+tcp://", 14)) {
				fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
			short_url = &rpc_url[ap - arg];
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "invalid URL -- '%s'\n",
					arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = (char*) malloc(strlen(hp) + 8);
			sprintf(rpc_url, "http://%s", hp);
			short_url = &rpc_url[sizeof("http://")-1];
		}
		have_stratum = !strncasecmp(rpc_url, "stratum", 7);
		break;
	}
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = (char*) calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(++p);
		strhide(p);
		break;
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 'z':
		v = atoi(arg);
		if (v < 25 || v > 250) {
			applog(LOG_ERR, "ZTEX frequency must be between 25 Mhz and 250 Mhz");
			show_usage_and_exit(1);
		}
		opt_use_ztex = true;
		g_ztex_freq = (int)((v/4)-1);
		opt_ztex_frequency_explicit = true;
		opt_ztex_frequency_exact_96 = strcmp(arg, "96") == 0;
		break;
	case 'F':
		opt_firmware = true;
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:
		use_colors = false;
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1004:
		opt_auto_freq = true;
		break;
	case 1008:
		opt_watts_per_fpga = atof(arg);
		if (opt_watts_per_fpga <= 0) opt_watts_per_fpga = 7.5;
		break;
	case 1040:			/* --tui */
		opt_tui = true;
		break;
	case 1041:			/* --log-file PATH */
		free(opt_log_file);
		opt_log_file = strdup(arg);
		break;
	case 1042:			/* --hash-clock MHZ (display only) */
		g_hash_clock_mhz = atof(arg);
		if (g_hash_clock_mhz <= 0) g_hash_clock_mhz = 90.0;
		opt_hash_clock_explicit = true;
		opt_hash_clock_exact_96 = strcmp(arg, "96") == 0;
		break;
	case 1043: {			/* --heartbeat-interval 20 (scoped canary only) */
		enum bc3_ztex_heartbeat_policy_result result =
			bc3_ztex_heartbeat_option_apply(arg,
				&opt_heartbeat_interval_seen,
				&g_ztex_heartbeat_interval_seconds);

		if (result != BC3_ZTEX_HEARTBEAT_POLICY_OK) {
			applog(LOG_ERR, "--heartbeat-interval rejected: %s",
				bc3_ztex_heartbeat_policy_result_text(result));
			show_usage_and_exit(1);
		}
		break;
	}
	case 1007:
		want_stratum = false;
		opt_extranonce = false;
		break;
	case 1009:
		opt_redirect = false;
		break;
	case 1010:
		allow_getwork = false;
		break;
	case 1011:
		have_gbt = false;
		break;
	case 1012:
		opt_extranonce = false;
		break;
	case 1013:			/* --coinbase-addr */
		pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
		if (!pk_script_size) {
			fprintf(stderr, "invalid address -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		break;
	case 1015:			/* --coinbase-sig */
		if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
			fprintf(stderr, "coinbase signature too long\n");
			show_usage_and_exit(1);
		}
		strcpy(coinbase_sig, arg);
		break;
	case 'f':
		d = atof(arg);
		if (d == 0.)	/* --diff-factor */
			show_usage_and_exit(1);
		opt_diff_factor = d;
		break;
	case 'm':
		d = atof(arg);
		if (d == 0.)	/* --diff-multiplier */
			show_usage_and_exit(1);
		opt_diff_factor = 1.0/d;
		break;
	case 1020:
		v = atoi(arg);
		if (v < -1)
			v = -1;
		if (v > (1<<num_cpus)-1)
			v = -1;
		opt_affinity = v;
		break;
	case 1021:
		v = atoi(arg);
		if (v < 0 || v > 5)	/* sanity check */
			show_usage_and_exit(1);
		opt_priority = v;
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

void parse_config(json_t *config, char *ref)
{
	int i;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;
		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int)json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
			options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
		key = getopt_long(argc, argv, short_options, options, NULL);

		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
	case SIGQUIT:
	case SIGINT:
	case SIGTERM:
		if (bc3_ztex_v2_signal_drain_mode) {
			if (bc3_ztex_v2_stop_signal == 0)
				bc3_ztex_v2_stop_signal = sig;
			bc3_ztex_v2_signal_stop_requested = 1;
			break;
		}
		/* Historically only SIGINT was installed. Leave a non-candidate
		 * SIGHUP inert if a caller explicitly routes it here. */
		if (sig == SIGHUP)
			break;
		/* Preserve the legacy miner's existing exit/atexit behavior.  The v2
		 * path above is the signal-safe, protocol-coordinated canary path. */
		proper_exit(EXIT_SUCCESS);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		if (bc3_ztex_v2_signal_drain_mode) {
			bc3_ztex_v2_signal_stop_requested = 1;
			break;
		}
		proper_exit(0);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int thread_create(struct thr_info *thr, void* func)
{
	int err = 0;
	pthread_attr_init(&thr->attr);
	err = pthread_create(&thr->pth, &thr->attr, func, thr);
	pthread_attr_destroy(&thr->attr);
	return err;
}

static void show_credits()
{
	printf("** " PACKAGE_NAME " " PACKAGE_VERSION " (based on cpuminer 2.4.5) **\n");
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

static bool bc3_ztex_select_lane(void *opaque, int lane)
{
	return libztex_selectFpga((struct libztex_device *)opaque, lane);
}

static int bc3_ztex_send_exact(void *opaque, const uint8_t *frame,
	int length, unsigned timeout_ms)
{
	return libztex_sendFrameExact((struct libztex_device *)opaque, frame,
		length, timeout_ms);
}

static int bc3_ztex_read_exact(void *opaque, uint8_t *frame, int length,
	unsigned timeout_ms)
{
	return libztex_readFrameExact((struct libztex_device *)opaque, frame,
		length, timeout_ms);
}

static struct bc3_ztex_io_ops bc3_ztex_make_io_ops(
	struct libztex_device *ztex)
{
	struct bc3_ztex_io_ops ops;

	ops.opaque = ztex;
	ops.select_lane = bc3_ztex_select_lane;
	ops.send_exact = bc3_ztex_send_exact;
	ops.read_exact = bc3_ztex_read_exact;
	return ops;
}

/* A candidate must prove its exact ABI/build identity and reset state before
 * a mining thread may give it work.  Every retry reselects the lane through
 * bc3_ztex_io_read_selected(); positive shorts are never stitched. */
static bool bc3_ztex_v2_probe_lane(struct libztex_device *ztex, int lane,
	bool *protocol_compatible)
{
	struct bc3_ztex_io_ops ops = bc3_ztex_make_io_ops(ztex);
	struct bc3_ztex_status status;
	uint8_t frame[BC3_ZTEX_STATUS_FRAME_SIZE];
	int last_rc = BC3_ZTEX_IO_INVALID_ERROR;
	unsigned attempt;

	if (protocol_compatible)
		*protocol_compatible = false;

	for (attempt = 0; attempt < 20; ++attempt) {
		last_rc = bc3_ztex_io_read_selected(&ops, lane, frame,
			(int)sizeof(frame), 500);
		if (last_rc == (int)sizeof(frame) &&
		    bc3_ztex_decode_status(&status, frame, sizeof(frame))) {
			if (!bc3_ztex_status_compatible(&status,
				    bc3_ztex_v2_build_id)) {
				applog(LOG_ERR,
					"%s-%d: typed ABI/build/state mismatch: got BUILD_ID %08" PRIx32
					" expected %08" PRIx32,
					ztex->repr, lane, status.build_id,
					bc3_ztex_v2_build_id);
				return false;
			}
			if (protocol_compatible)
				*protocol_compatible = true;
			if (!bc3_ztex_startup_status_ok(&status,
				    bc3_ztex_v2_build_id)) {
				applog(LOG_ERR,
					"%s-%d: R34 startup status is not pristine/healthy",
					ztex->repr, lane);
				return false;
			}
			applog(LOG_WARNING,
				"%s-%d: R34 ABI/build startup probe passed",
				ztex->repr, lane);
			return true;
		}
		nmsleep(10);
	}
	applog(LOG_ERR,
		"%s-%d: R34 startup status probe failed after %u exact reads (last rc=%d)",
		ztex->repr, lane, attempt, last_rc);
	return false;
}

static bool detect_fpga()
{
	int i, j, fd;
	int ztex_scan_count = 0;
	int ztex_selected_scan_index = -1;
	const char *ztex_serial_only = NULL;

	char *bitstream;

	g_fpga_count = 0;
	g_serial_fpga_count = 0;
	g_ztex_fpga_count = 0;
	sha3_bitstream_override_active = false;
	sha3_bitstream_override[0] = '\0';
	memset(vg_avail, 0, sizeof(vg_avail));
	vg_enabled = false;
	ztex_rb_mode = ZTEX_RB_TEST_OFF;
	ztex_lane_policies = NULL;
	bc3_ztex_v2_compatible_lane_mask = 0;
	bc3_ztex_v2_configured_lane_mask = 0;
	bc3_ztex_v2_attempted_lane_mask = 0;

	/* Reject malformed selectors/test modes before even enumerating USB. */
	if (opt_use_ztex && !ztex_get_readback_test())
		return false;
	if (opt_use_ztex && !ztex_get_serial_only(&ztex_serial_only))
		return false;

	/* Validate the candidate before scanning or touching any USB device.  The
	 * environment variable has no effect for algorithms other than SHA3T. */
	if (opt_use_ztex && opt_algo == ALGO_SHA3T) {
		const char *override = getenv("SHA3_BITSTREAM");
		if (override) {
			if (opt_auto_freq) {
				applog(LOG_ERR,
					"--auto-freq rejected: SHA3_BITSTREAM exact override and fixed-image governor are mutually exclusive");
				return false;
			}
			if (!sha3_activate_bitstream_override(override))
				return false;
		} else if (opt_auto_freq) {
			int available = vg_discover();
			if (sha3_variant_activation_decide(true, false,
					(size_t)available) != SHA3_VARIANT_READY) {
				applog(LOG_ERR,
					"--auto-freq rejected: SHA3T requires at least two separately qualified fixed bitstreams");
				return false;
			}
		}
	}
	{
		const char *build_text = getenv("SHA3_PROTOCOL_V2_BUILD_ID");
			if (build_text) {
				if (!opt_use_ztex || opt_use_cpu || opt_use_serial ||
				    opt_algo != ALGO_SHA3T ||
				    !want_stratum || !have_stratum ||
				    !sha3_bitstream_override_active ||
				    !ztex_serial_only ||
				    opt_api_listen != 0 ||
				    opt_retries != -1 ||
				    ztex_rb_enabled(ztex_rb_mode) ||
			    !bc3_ztex_parse_build_id(build_text,
				    &bc3_ztex_v2_build_id) ||
				    !bc3_ztex_build_id_supported(
					bc3_ztex_v2_build_id)) {
				applog(LOG_ERR,
						"SHA3_PROTOCOL_V2_BUILD_ID rejected: requires ZTEX-only sha3t over active Stratum, an explicit SHA3_BITSTREAM override, an exact ZTEX_SERIAL_ONLY canary, --api-bind 0, infinite retries, no ZTEX_RB_TEST, and supported BUILD_ID 00000034");
				return false;
			}
			bc3_ztex_v2_active = true;
			bc3_ztex_v2_signal_drain_mode = 1;
			applog(LOG_WARNING,
				"R34 typed ZTEX protocol enabled with BUILD_ID=%08" PRIx32
				" (legacy nonce-zero/readback paths bypassed)",
				bc3_ztex_v2_build_id);
		}
	}
	if (bc3_ztex_v2_active && bc3_ztex_v2_signal_stop_requested) {
		applog(LOG_WARNING,
			"typed shutdown signal observed before USB configuration");
		return false;
	}

	struct libztex_dev_list **ztex_devices;

	if (opt_use_serial) {

		applog(LOG_DEBUG, "Detect Serial FPGAs...");

		for (i = 0; i < g_serial_device_count; i++) {

			fd = serial_open(serial_fpga_list[i], SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, true);
			if (fd == -1) {
				applog(LOG_ERR, "ERROR: Unable to find Serial FPGA on Port: %s", serial_fpga_list[i]);
			}
			else {
				g_fpga_count++;
				g_serial_fpga_count++;

				applog(LOG_WARNING, "Detected Serial FPGA on Port: %s", serial_fpga_list[i]);
			}
			close(fd);
		}
	}	

	if (opt_use_ztex) {

		applog(LOG_DEBUG, "Detect ZTEX FPGAs...");

		ztex_scan_count = libztex_scanDevices(&ztex_devices, opt_firmware);
		if (ztex_scan_count <= 0) {
			if (ztex_serial_only)
				applog(LOG_ERR, "ZTEX_SERIAL_ONLY=%s not found: no ZTEX boards were detected; refusing to configure any FPGA",
					ztex_serial_only);
			applog(LOG_ERR, "ERROR: No ZTEX FGPA Boards Found");
			return false;
		}

		applog(LOG_INFO, "Found %d ZTEX FPGA Boards", ztex_scan_count);
		if (bc3_ztex_v2_active && bc3_ztex_v2_signal_stop_requested) {
			applog(LOG_WARNING,
				"typed shutdown signal observed after USB enumeration");
			for (i = 0; i < ztex_scan_count; ++i) {
				libztex_destroy_device(ztex_devices[i]->dev);
				ztex_devices[i]->dev = NULL;
			}
			libztex_freeDevList(ztex_devices);
			return false;
		}

		/* Resolve the complete scan first.  This makes a missing or duplicated
		 * requested serial fail before the configuration loop can upload even one
		 * bitstream.  It also prevents FPGA_ONLY=0 from selecting FPGA 0 on every
		 * visible board during a single-FPGA canary. */
		if (ztex_serial_only) {
			int matches = 0;
			for (i = 0; i < ztex_scan_count; i++) {
				if (strcmp((const char *)ztex_devices[i]->dev->snString,
				           ztex_serial_only) == 0) {
					ztex_selected_scan_index = i;
					matches++;
				}
			}

			if (matches != 1) {
				applog(LOG_ERR, "ZTEX_SERIAL_ONLY=%s matched %d of %d boards; refusing to configure any FPGA",
					ztex_serial_only, matches, ztex_scan_count);
				for (i = 0; i < ztex_scan_count; i++) {
					applog(LOG_WARNING, "%s: skipped (ZTEX_SERIAL_ONLY=%s)",
						ztex_devices[i]->dev->repr, ztex_serial_only);
					libztex_destroy_device(ztex_devices[i]->dev);
					ztex_devices[i]->dev = NULL;
				}
				libztex_freeDevList(ztex_devices);
				return false;
			}

			for (i = 0; i < ztex_scan_count; i++) {
				if (i == ztex_selected_scan_index) {
					applog(LOG_WARNING, "%s: selected exclusively (1 of %d boards)",
						ztex_devices[i]->dev->repr, ztex_scan_count);
					continue;
				}
				applog(LOG_WARNING, "%s: skipped (ZTEX_SERIAL_ONLY=%s)",
					ztex_devices[i]->dev->repr, ztex_serial_only);
				/* Scanning opens every board.  Close non-selected handles so the
				 * canary process neither owns nor communicates with those boards. */
				libztex_destroy_device(ztex_devices[i]->dev);
				ztex_devices[i]->dev = NULL;
			}
			g_ztex_fpga_count = 1;
		} else {
			g_ztex_fpga_count = ztex_scan_count;
		}

		ztex_info = (struct libztex_device*) calloc(g_ztex_fpga_count, sizeof(struct libztex_device));
		if(!ztex_info) {
			applog(LOG_ERR, "ERROR: Unable To Allocate ZTEX Info");
			return false;
		}
		ztex_lane_policies = calloc((size_t)g_ztex_fpga_count,
			sizeof(*ztex_lane_policies));
		if (!ztex_lane_policies) {
			applog(LOG_ERR, "ERROR: Unable To Allocate ZTEX Lane Policies");
			return false;
		}

		switch (opt_algo) {
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
				bitstream = "ztex_groestl.bit";
				break;
			case ALGO_MYR_GR:
				bitstream = "ztex_myr_groestl.bit";
				break;
			case ALGO_BLAKECOIN:
			case ALGO_VCASH:
				bitstream = "ztex_blake256_8.bit";
				break;
			case ALGO_BLAKE3:
				bitstream = "blake3_dcr.bit";
				break;
			case ALGO_ODO:
				bitstream = "odo_dgb.bit";
				break;
			case ALGO_SHA3T:
				if (sha3_bitstream_override_active) {
					bitstream = sha3_bitstream_override;
				} else {
					bitstream = "ztex_sha3.bit";
				}
				break;
			default:
				bitstream = "ztex_groestl.bit";
				break;
		}
		
		/* Resolve and validate every board's lane count/selection/order before
		 * configuring the first FPGA.  The same stored policy later initializes
		 * the runtime enable flags, so configuration and mining cannot disagree. */
		for (i = 0; i < g_ztex_fpga_count; i++) {
			int scan_index = ztex_serial_only ? ztex_selected_scan_index : i;

			memcpy(&ztex_info[i], ztex_devices[scan_index]->dev, sizeof(struct libztex_device));

			ztex_info[i].numberOfFpgas = libztex_numberOfFpgas(&ztex_info[i]);
			ztex_info[i].selectedFpga = -1;
			if (bc3_ztex_v2_active &&
			    ztex_info[i].numberOfFpgas != 4) {
				applog(LOG_ERR,
					"%s: R34 requires the exact ZTEX 1.15y four-lane topology (reported %d); refusing to configure any FPGA",
					ztex_info[i].repr,
					ztex_info[i].numberOfFpgas);
				return false;
			}
			if (!bc3_ztex_lane_policy_parse(
				    (unsigned)ztex_info[i].numberOfFpgas,
				    getenv("FPGA_ONLY"), getenv("FPGA_ORDER"),
				    &ztex_lane_policies[i])) {
				applog(LOG_ERR,
					"%s: invalid FPGA_ONLY/FPGA_ORDER for %d lanes; refusing to configure any FPGA",
					ztex_info[i].repr, ztex_info[i].numberOfFpgas);
				return false;
			}

			g_fpga_count++;

			applog(LOG_WARNING,"%s: Found Ztex Board (fpga count = %d), ID #%d", ztex_info[i].repr, ztex_info[i].numberOfFpgas, i);
		}

		for (i = 0; i < g_ztex_fpga_count; i++) {
			/* Configure all FPGAs directly.
			 * With UnusedPin:PullNone in bitgen, all 4 configure reliably. */
			{
				struct bc3_ztex_lane_policy *policy =
					&ztex_lane_policies[i];
				int num_ok = 0;
				const char *only = getenv("FPGA_ONLY");
				int oi;
				for (oi = 0; oi < (int)policy->lane_count; oi++) {
					j = (int)policy->order[oi];
					if (bc3_ztex_v2_active &&
					    bc3_ztex_v2_signal_stop_requested) {
						applog(LOG_WARNING,
							"typed shutdown signal observed during configuration");
						return false;
					}
					if ((policy->selection_mask &
					     (uint8_t)(UINT32_C(1) << (unsigned)j)) == 0) {
						applog(LOG_WARNING,
							"%s-%d: skipped%s%s%s", ztex_info[i].repr,
							j, only ? " (FPGA_ONLY=" : "",
							only ? only : "", only ? ")" : "");
						continue;
					}
						if(!libztex_selectFpga(&ztex_info[i], j)) return false;
						{
						const char *bf = bitstream;
					if (opt_algo == ALGO_SHA3T && !sha3_bitstream_override_active &&
					    vg_enabled && i < 64) {
							vg_rung_tbl[i][j] = vg_load_rung(ztex_info[i].repr, j);
							if (vg_rung_tbl[i][j] < 0 ||
							    !vg_verify_rung_file(vg_rung_tbl[i][j], true)) {
								applog(LOG_ERR,
									"%s-%d: no authenticated startup variant; refusing configuration",
									ztex_info[i].repr, j);
								return false;
							}
							bf = vg_bitfile(vg_rung_tbl[i][j]);
							applog(LOG_WARNING,
								"%s-%d: variant %s %.6f MHz %.6f MH/s (%s)",
								ztex_info[i].repr, j,
								vg_spec(vg_rung_tbl[i][j])->state_id,
								sha3_variant_clock_mhz(vg_spec(vg_rung_tbl[i][j])),
								vg_spec(vg_rung_tbl[i][j])->expected_rate_hps_floor /
									1000000.0, bf);
						}
						if (bc3_ztex_v2_active)
							bc3_ztex_v2_attempted_lane_mask |=
								(uint8_t)(UINT32_C(1) << (unsigned)j);
						if(!libztex_configureFpga(&ztex_info[i], bf)) {
							applog(LOG_ERR, "%s-%d: Configuration failed, skipping", ztex_info[i].repr, j);
							if (bc3_ztex_v2_active)
								return false;
							policy->selection_mask &=
								(uint8_t)~(UINT32_C(1) << (unsigned)j);
							policy->selected_count--;
							continue;
						}
						if (bc3_ztex_v2_active)
							bc3_ztex_v2_configured_lane_mask |=
								(uint8_t)(UINT32_C(1) << (unsigned)j);
						if (bc3_ztex_v2_active &&
						    bc3_ztex_v2_signal_stop_requested)
							return false;
					}
					if(!libztex_setFreq(&ztex_info[i], g_ztex_freq)) return false;
					if (bc3_ztex_v2_active) {
						bool protocol_compatible = false;

						nmsleep(20);
						if (!bc3_ztex_v2_probe_lane(&ztex_info[i], j,
							    &protocol_compatible)) {
							if (protocol_compatible)
								bc3_ztex_v2_compatible_lane_mask |=
									(uint8_t)(UINT32_C(1) << (unsigned)j);
							return false;
						}
						bc3_ztex_v2_compatible_lane_mask |=
							(uint8_t)(UINT32_C(1) << (unsigned)j);
					}
					applog(LOG_WARNING, "%s-%d: Successfully configured", ztex_info[i].repr, j);
					num_ok++;
					nmsleep(200);
				}
				applog(LOG_WARNING, "%s: %d of %d FPGAs running",
					ztex_info[i].repr, num_ok, ztex_info[i].numberOfFpgas);
				if (bc3_ztex_v2_active &&
				    num_ok != (int)policy->selected_count) {
					applog(LOG_ERR,
						"%s: R34 requested-lane configuration mismatch",
						ztex_info[i].repr);
					return false;
				}
			}			
		}

		libztex_freeDevList(ztex_devices);
	}

	if (g_fpga_count == 0) {
		applog(LOG_ERR, "ERROR: No FPGAs Found!");
		return false;
	}

	return true;
}

static bool initialize_serial_miner(void *thr, int serial_fpga_num)
{
	struct thr_info *mythr = thr;
	struct fpga_info *fpga = mythr->fpga;
	int name_length;

	if (serial_fpga_num < 0 || serial_fpga_num >= MAX_SERIAL_DEVICES ||
	    !serial_fpga_list[serial_fpga_num])
		return false;
	
	memset(fpga->name, 0, sizeof(fpga->name));
	memset(fpga->short_name, 0, sizeof(fpga->short_name));
	memcpy(fpga->name, "SerialFPGA", sizeof("SerialFPGA"));
	name_length = snprintf(fpga->short_name, sizeof(fpga->short_name),
		"SRL%d", serial_fpga_num);
	if (name_length < 0 ||
	    (size_t)name_length >= sizeof(fpga->short_name))
		return false;
	fpga->type = FPGA_SERIAL;
	fpga->device_path = malloc(strlen(serial_fpga_list[serial_fpga_num]) + 1);
	if (!fpga->device_path)
		return false;
	strcpy(fpga->device_path, serial_fpga_list[serial_fpga_num]);
	fpga->device_fd = -1;
	fpga->timeout = opt_scantime;
	fpga->Hs = 0.000001;	// Default Hs(hashes/sec) to 1MH/s until share is found and hashrate can be calculated

	return true;
}

static bool initialize_ztex_miner(void *thr, int ztex_num)
{
	int i;
	int name_length;
	struct thr_info *mythr = thr;
	struct fpga_info *fpga = mythr->fpga;
	const struct bc3_ztex_lane_policy *policy;

	if (!ztex_lane_policies || ztex_num < 0 ||
	    ztex_num >= g_ztex_fpga_count)
		return false;
	policy = &ztex_lane_policies[ztex_num];

	memset(fpga->short_name, 0, 10);

	name_length = snprintf(fpga->short_name, sizeof(fpga->short_name),
		"ZTX%d", ztex_num);
	if (name_length < 0 ||
	    (size_t)name_length >= sizeof(fpga->short_name))
		return false;
	
	memcpy(fpga->name, ztex_info[ztex_num].repr, 20);
	fpga->board_idx = ztex_num;
	fpga->type = FPGA_ZTEX;
	fpga->timeout = opt_scantime;
	fpga->ztex_info = &ztex_info[ztex_num];

	fpga->ztex_stats = (struct ztex_stats *) calloc(ztex_info[ztex_num].numberOfFpgas, sizeof(struct ztex_stats));
	if (!fpga->ztex_stats)
		return false;

	/* Register with the TUI so the dashboard can read this board's stats. */
	tui_register_board(ztex_num, fpga);
	
	for(i=0; i<ztex_info[ztex_num].numberOfFpgas; i++) {
		int startup_fallback = -1;

		fpga->ztex_stats[i].enabled =
			(policy->selection_mask &
			 (uint8_t)(UINT32_C(1) << (unsigned)i)) != 0;
		fpga->ztex_stats[i].hashrate = 0.0;
		fpga->ztex_stats[i].vg_reconfig_fallback_rung = -1;
		if (opt_algo == ALGO_SHA3T && !sha3_bitstream_override_active &&
		    vg_enabled && ztex_num < 64) {
			/* Variant mode stores the exact catalog clock separately. */
			fpga->ztex_stats[i].gov_m = vg_rung_tbl[ztex_num][i];
			fpga->ztex_stats[i].freq = 0;
			fpga->ztex_stats[i].hash_clock_mhz =
				sha3_variant_clock_mhz(vg_spec(vg_rung_tbl[ztex_num][i]));
			startup_fallback = sha3_variant_initial_rung(vg_avail,
				VG_NRUNGS, SHA3_VARIANT_CATALOG_DEFAULT_RUNG);
			if (startup_fallback < 0)
				startup_fallback = vg_rung_tbl[ztex_num][i];
			if (fpga->ztex_stats[i].enabled)
				vg_arm_reconfig_guard(&fpga->ztex_stats[i],
					startup_fallback, false);
		} else {
			fpga->ztex_stats[i].freq = g_ztex_freq;
			fpga->ztex_stats[i].gov_m = g_ztex_freq;   /* legacy: --ztex M index */
			fpga->ztex_stats[i].hash_clock_mhz = g_hash_clock_mhz;
		}
		gettimeofday(&fpga->ztex_stats[i].freq_check_tv, NULL);
	}

	return true;
}

void calc_hash(unsigned char *data, unsigned char *hash)
{
	uint32_t endian_data[48];
	uint32_t *data32 = (uint32_t *)(data);

	switch (opt_algo) {
		case ALGO_BLAKE3:
			/* BLAKE3: work.data is already in LE format, hash directly
			 * (180 bytes = 45 words, no swap_endian needed for BLAKE3) */
			blake3_hash_180((void *)data32, (void *)hash);
			break;
		case ALGO_ODO:
		{
			/* OdoCrypt: full swap_endian (matches nonce_bswap in FPGA) */
			extern void odohash(void *output, const void *input, uint32_t odo_key);
			swap_endian(endian_data, data32, 80);
			uint32_t ntime = endian_data[17];
			uint32_t odo_key = ntime - ntime % 864000;
			odohash((void *)hash, (void *)endian_data, odo_key);
			break;
		}
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
			swap_endian(endian_data, data32, 80);
			groestlhash((void *)hash, (void *)endian_data);
			break;
		case ALGO_MYR_GR:
			swap_endian(endian_data, data32, 80);
			myriadhash((void *)hash, (void *)endian_data);
			break;
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			swap_endian(endian_data, data32, 80);
			blake256_8_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_SHA3T:
			swap_endian(endian_data, data32, 80);
			sha3256t_hash((void *)hash, (void *)endian_data);
			break;
		default:
			swap_endian(endian_data, data32, 80);
			break;
	}
}

void calc_midstate(unsigned char *data, unsigned char *midstate)
{
	uint32_t endian_data[20];
	uint32_t *data32 = (uint32_t *)(data);

	swap_endian(endian_data, data32, 80);

	switch (opt_algo) {
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			blake256_8_midstate((void *)midstate, (void *)endian_data);
			break;
		default:
			applog(LOG_ERR, "ERROR: Midstate option not supported for this algo");
	}
}
					
static void *serial_miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	struct fpga_info *fpga = mythr->fpga;
	int thr_id = mythr->id;
	struct work work = {{0}};
	int i, fd, ret;
	unsigned char data[184], midstate[32], send_buf[184], nonce_buf[SERIAL_READ_SIZE];
	uint32_t *target;
	bool display_summary = false;

	uint32_t nonce, hash[8];
	int64_t hash_count;
	struct timeval tv_start, tv_finish, elapsed, tv_end, diff;
	
	while (1) {
		unsigned long hashes_done;
		int rc;

		fd = fpga->device_fd;
		if (fd == -1) {
		
			applog(LOG_DEBUG, "Attemping to Reopen Serial FPGA on %s", fpga->device_path);
			fd = serial_open(fpga->device_path, SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, false);
			if (fd == -1) {
				applog(LOG_ERR, "Failed to open Serial FPGA on %s", fpga->device_path);
				nmsleep(5000);

				applog(LOG_DEBUG, "Attemping to Reopen Serial FPGA on %s", fpga->device_path);
				fd = serial_open(fpga->device_path, SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, false);
				if (fd == -1) {
					applog(LOG_ERR, "Failed to open Serial FPGA on %s", fpga->device_path);
					goto out;
				}
				else
				fpga->device_fd = fd;
			}
			else
				fpga->device_fd = fd;
		}

		if (have_stratum) {
			enum stratum_gen_result generated;

			while (!jsonrpc_2 && time(NULL) >= current_work_time() + 120)
				sleep(1);
			generated = stratum_gen_work_result(&stratum, &work);
			if (generated != STRATUM_GEN_READY) {
				nmsleep(100);
				continue;
			}
		}
		else {
			applog(LOG_ERR, "ERROR: Only Stratum Protocol Has Been Implemented");
			goto out;
		}
		work_restart[thr_id].restart = 0;

		target = (uint32_t *)(work.target);

		if ( g_fpga_use_midstate ) {
			calc_midstate((unsigned char *)work.data, (unsigned char *)midstate);
			memcpy(data, midstate, 32);
			memcpy(data + 32, (unsigned char*)work.data + 64, 12);
		}
		else if (opt_algo == ALGO_BLAKE3) {
			/* Same precompute as ZTEX path - see ztex_miner_thread */
			uint32_t iv[8] = {
				0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
				0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
			};
			uint32_t cv0[8], cv[8], bw[16];
			int w;
			for (w = 0; w < 16; w++) bw[w] = work.data[w];
			blake3_compress_host(iv, bw, 0, 64, 1, cv0);
			for (w = 0; w < 16; w++) bw[w] = work.data[16 + w];
			blake3_compress_host(cv0, bw, 0, 64, 0, cv);
			memcpy(data, (unsigned char *)cv, 32);
			memcpy(data + 32, (unsigned char *)&work.data[32], 12);
			memcpy(data + 44, (unsigned char *)&work.data[36], 36);
			memcpy(data + 80, (unsigned char *)work.target + 28, 4);
		}
		else {
			memcpy(data, (unsigned char*)work.data, 76);
			memcpy(data + 76, (unsigned char*)work.target + 28, 4);
		}

		// Prepare send buffer
		if (opt_algo == ALGO_BLAKE3) {
			int l;
			for (l = 0; l < g_fpga_work_len; l++)
				send_buf[l] = data[g_fpga_work_len - 1 - l];
		} else {
			swap_endian(send_buf, data, g_fpga_work_len);
		}

		// Send Data To FPGA
		ret = write(fd, send_buf, g_fpga_work_len);

		if (ret != g_fpga_work_len) {
			applog(LOG_ERR, "%s: Serial Send Error (ret=%d)", fpga->short_name, ret);
			close(fd);
			fpga->device_fd = -1;
			fpga->Hs = 1;
			continue;
		}

		hashes_done = 0;
		elapsed.tv_sec = 0;
		elapsed.tv_usec = 0;
		gettimeofday(&tv_start, NULL);

		applog(LOG_DEBUG, "%s: Begin Scan For Nonces", fpga->short_name);
		while (mythr && !work_restart[thr_id].restart) {

			memset(nonce_buf,0,4);
		
			// Check Serial Port For 1/10 Sec For Nonce  
			ret = read(fd, nonce_buf, SERIAL_READ_SIZE);

			// Calculate Elapsed Time
			gettimeofday(&tv_end, NULL);
			timeval_subtract(&elapsed, &tv_end, &tv_start);

			if (ret == 0) {		// No Nonce Found
				if (elapsed.tv_sec >= fpga->timeout) {
					applog(LOG_DEBUG, "%s: End Scan For Nonces - Time = %d sec", fpga->short_name, elapsed.tv_sec);
					break;
				}
				continue;
			}
			else if (ret < SERIAL_READ_SIZE) {
				applog(LOG_ERR, "%s: Serial Read Error (ret=%d)", fpga->short_name, ret);
				close(fd);
				fpga->device_fd = -1;
				fpga->Hs = 1;
				break;
			}

			memcpy((char *)&nonce, nonce_buf, SERIAL_READ_SIZE);
			nonce = swab32(nonce);

			// Calculate Hash Using Nonce By FPGA
			work.data[g_nonce_word_index] = nonce;
			calc_hash((unsigned char *)work.data, (unsigned char *)hash);

			// Check If Hash < Target Sent To FPGA
			if (swab32(hash[7]) > swab32(target[7])) {
				fpga->hw_errors++;
				applog(LOG_DEBUG, "%s: HW Error (Nonce: %08X, Hash: %08X, Target: %08X)", fpga->short_name, nonce, swab32(hash[7]), swab32(target[7]));
				continue;
			}

			// Update Hashrate
			fpga->Hs = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000)) / (double)nonce;
			if(fpga->Hs < 0.000000001)
				fpga->Hs = 0.000000001;

			// Check If Hash < Work Target
			if(fulltest(hash, work.target)) {
				if (work_publish_retry(mythr, &work, 3,
						work_publish_submit_work,
						work_publish_retry_pause)) {
					applog(LOG_DEBUG, "%s: Nonce Found - %08X (%5.1fMhz)", fpga->short_name, nonce, (double)(1/(fpga->Hs * 1000000)));
					fpga->submitted++;

					// Check If Block Was Found
					if(fulltest(hash, work.block_target)) {
						applog(LOG_NOTICE, "%s: %s***** BLOCK FOUND *****", fpga->short_name, CL_GRN);
						g_block_count++;
					}
				} else {
					applog(LOG_ERR, "%s: share queue failed after 3 attempts", fpga->short_name);
				}
			}
			else {
				applog(LOG_DEBUG, "%s: Share above target - %08X (%5.1fMhz)", fpga->short_name, nonce, (double)(1/(fpga->Hs * 1000000)));
			}
		}

		// Estimate Number Of Hashes
		hashes_done = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000)) / fpga->Hs;
		fpga->hashrate = hashes_done / (elapsed.tv_sec + elapsed.tv_usec * 1e-6);

		pthread_mutex_lock(&stats_lock);
		thr_hashrates[thr_id] = fpga->hashrate;
		pthread_mutex_unlock(&stats_lock);

		// Display FPGA Summary
		if (display_summary != opt_fpga_summary) {

			display_summary = opt_fpga_summary;

			applog(LOG_WARNING, "----------------- FPGA Summary for %s -------------------", fpga->device_path);
			applog(LOG_WARNING, "Hash: %-4.2fMh/s  Submitted: %u  HW: %u", fpga->hashrate / 1000000.0, fpga->submitted, fpga->hw_errors);
			applog(LOG_WARNING, "--------------------------------------------------------------------");
		}

	}

out:
	tq_freeze(mythr->q);

	pthread_mutex_lock(&stats_lock);
	thr_hashrates[thr_id] = 0;
	pthread_mutex_unlock(&stats_lock);

	return NULL;
}



static uint32_t ztex_checkNonce(unsigned char* data)
{
	uint32_t hash[8];

	calc_hash(data, (unsigned char *)hash);

	return hash[7];
}

/* Recompute, publish, and sanitize the board total as one operation.  In
 * particular, a lane disabled by a USB send/read failure must stop
 * contributing before the next accepted-share message, rather than waiting
 * for the next two-second nonce-rate window. */
static void ztex_publish_hashrate(struct fpga_info *fpga,
		struct ztex_stats *ztex_stats, int num_fpgas, int thr_id)
{
	double total = 0.0;
	int i;

	for (i = 0; i < num_fpgas; i++)
		total += active_lane_hashrate(ztex_stats[i].enabled,
			&ztex_stats[i].hashrate,
			&ztex_stats[i].hashrate_smooth);

	fpga->hashrate = total;
	pthread_mutex_lock(&stats_lock);
	if (thr_hashrates && thr_id >= 0 &&
	    (size_t)thr_id < thr_hashrates_count)
		thr_hashrates[thr_id] = total;
	pthread_mutex_unlock(&stats_lock);
}

static uint64_t ztex_rb_now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL +
		(uint64_t)ts.tv_nsec / 1000ULL;
}

static void vg_reset_lane_measurements(struct ztex_stats *stats)
{
	if (!stats)
		return;
	stats->hash_checks = 0;
	stats->hash_errors = 0;
	stats->vg_snap_checks = 0;
	stats->vg_snap_errors = 0;
	stats->last_checked_nonce = 0;
	stats->vg_clean_wins = 0;
	clear_lane_hashrate(&stats->hashrate, &stats->hashrate_smooth);
	memset(stats->hr_hist, 0, sizeof(stats->hr_hist));
	stats->hr_idx = 0;
	stats->hr_count = 0;
	gettimeofday(&stats->freq_check_tv, NULL);
}

static void vg_arm_reconfig_guard(struct ztex_stats *stats,
		int fallback_rung, bool recovery_attempted)
{
	vg_reset_lane_measurements(stats);
	stats->vg_reconfig_pending = true;
	stats->vg_reconfig_recovery_attempted = recovery_attempted;
	stats->vg_reconfig_fallback_rung = fallback_rung;
	/* The deadline begins only after the worker has delivered work to this
	 * image. Pool/network delay therefore cannot condemn a healthy image. */
	stats->vg_reconfig_started_us = 0;
}

static void vg_note_work_published(struct ztex_stats *stats)
{
	if (stats && stats->vg_reconfig_pending &&
	    stats->vg_reconfig_started_us == 0)
		stats->vg_reconfig_started_us = ztex_rb_now_us();
}

static bool vg_commit_reconfig(struct fpga_info *fpga,
		struct libztex_device *ztex, int lane)
{
	struct ztex_stats *stats = &fpga->ztex_stats[lane];
	int rung = stats->gov_m;

	if (!stats->vg_reconfig_pending || rung < 0 ||
	    rung >= (int)VG_NRUNGS || !vg_avail[rung])
		return false;
	stats->vg_reconfig_pending = false;
	stats->vg_reconfig_recovery_attempted = false;
	stats->vg_reconfig_fallback_rung = -1;
	stats->vg_reconfig_started_us = 0;
	stats->vg_snap_checks = stats->hash_checks;
	stats->vg_snap_errors = stats->hash_errors;
	stats->vg_clean_wins = 0;
	gettimeofday(&stats->freq_check_tv, NULL);
	if (!vg_save_rung(ztex->repr, lane, rung))
		applog(LOG_ERR,
			"%s-%d: governor proved %s alive but could not atomically persist it: %s",
			fpga->short_name, lane, vg_spec(rung)->state_id,
			strerror(errno));
	applog(LOG_WARNING,
		"%s-%d: governor image %s committed after %u clean CPU-verified progress samples",
		fpga->short_name, lane, vg_spec(rung)->state_id,
		SHA3_VARIANT_RECONFIG_MIN_CLEAN_CHECKS);
	return true;
}

/* Reload a known-safe image exactly once when a provisional image does not
 * prove liveness. This executes in the board worker, which is the sole USB
 * owner for its device. The restored image is itself provisional until it
	 * produces the required sequence of clean CPU-verified diagnostics. */
static bool vg_recover_reconfig(struct fpga_info *fpga,
		struct libztex_device *ztex, int lane, int num_fpgas, int thr_id,
		const char *reason)
{
	struct ztex_stats *stats = &fpga->ztex_stats[lane];
	int failed_rung = stats->gov_m;
	int fallback_rung = stats->vg_reconfig_fallback_rung;

	if (failed_rung >= 0 && failed_rung < (int)VG_NRUNGS)
		sha3_variant_taint_rung(&stats->vg_tainted_mask, VG_NRUNGS,
			failed_rung);
	if (stats->vg_reconfig_recovery_attempted || fallback_rung < 0 ||
	    fallback_rung >= (int)VG_NRUNGS || !vg_avail[fallback_rung]) {
		applog(LOG_ERR,
			"%s-%d: governor liveness recovery exhausted (%s); disabling lane and requiring operator recovery",
			fpga->short_name, lane, reason ? reason : "unknown failure");
		stats->vg_reconfig_pending = false;
		stats->vg_reconfig_started_us = 0;
		stats->enabled = false;
		clear_lane_hashrate(&stats->hashrate, &stats->hashrate_smooth);
		ztex_publish_hashrate(fpga, fpga->ztex_stats, num_fpgas, thr_id);
		return false;
	}

	applog(LOG_ERR,
		"%s-%d: provisional governor image %s failed (%s); reloading fallback %s",
		fpga->short_name, lane,
		vg_spec(failed_rung) ? vg_spec(failed_rung)->state_id : "invalid",
		reason ? reason : "unproven liveness",
		vg_spec(fallback_rung)->state_id);
	if (libztex_selectFpga(ztex, lane) &&
	    vg_verify_rung_file(fallback_rung, true) &&
	    libztex_configureFpga(ztex, vg_bitfile(fallback_rung))) {
		stats->gov_m = fallback_rung;
		stats->hash_clock_mhz =
			sha3_variant_clock_mhz(vg_spec(fallback_rung));
		/* Record rollback intent immediately. The fallback is already a
		 * catalog-qualified image, and retaining a failed faster state across
		 * a process crash would just select it again at startup. The ordinary
		 * commit path still requires fresh clean progress. */
		if (!vg_save_rung(ztex->repr, lane, fallback_rung))
			applog(LOG_ERR,
				"%s-%d: governor could not persist fallback %s: %s",
				fpga->short_name, lane,
				vg_spec(fallback_rung)->state_id, strerror(errno));
		vg_arm_reconfig_guard(stats, -1, true);
		work_restart[thr_id].restart = 1;
		applog(LOG_WARNING,
			"%s-%d: governor fallback %s reloaded; awaiting clean progress proof",
			fpga->short_name, lane,
			vg_spec(fallback_rung)->state_id);
		return true;
	}

	applog(LOG_ERR,
		"%s-%d: governor fallback configuration FAILED; disabling lane and requiring operator recovery",
		fpga->short_name, lane);
	stats->vg_reconfig_pending = false;
	stats->vg_reconfig_started_us = 0;
	stats->enabled = false;
	clear_lane_hashrate(&stats->hashrate, &stats->hashrate_smooth);
	ztex_publish_hashrate(fpga, fpga->ztex_stats, num_fpgas, thr_id);
	return false;
}

static void ztex_rb_wait_until(uint64_t target_us, volatile uint8_t *restart)
{
	for (;;) {
		uint64_t now_us, remain_us;
		if (restart && *restart)
			return;
		now_us = ztex_rb_now_us();
		if (now_us >= target_us)
			return;
		remain_us = target_us - now_us;
		if (remain_us > 10000ULL)
			nmsleep(10);
		else
			usleep((useconds_t)remain_us);
	}
}

static const char *ztex_rb_cause_name(enum ztex_rb_cause cause)
{
	switch (cause) {
	case ZTEX_RB_SELECT: return "select";
	case ZTEX_RB_SHORT: return "short";
	case ZTEX_RB_USB_ERROR: return "usb";
	case ZTEX_RB_ZERO: return "zero";
	case ZTEX_RB_JUMP: return "jump";
	case ZTEX_RB_NOISE: return "noise";
	default: return "clean";
	}
}

static const char *ztex_rb_match_name(enum ztex_rb_work_match match)
{
	switch (match) {
	case ZTEX_RB_MATCH_CURRENT: return "current";
	case ZTEX_RB_MATCH_PREVIOUS: return "previous";
	case ZTEX_RB_MATCH_BOTH: return "both";
	case ZTEX_RB_MATCH_NEITHER: return "neither";
	default: return "na";
	}
}

static void ztex_rb_count_cause(struct ztex_stats *stats,
				enum ztex_rb_cause cause)
{
	switch (cause) {
	case ZTEX_RB_SELECT: stats->rb_select_fail++; break;
	case ZTEX_RB_SHORT: stats->rb_short++; break;
	case ZTEX_RB_USB_ERROR: stats->rb_usb_error++; break;
	case ZTEX_RB_ZERO: stats->rb_zero++; break;
	case ZTEX_RB_JUMP: stats->rb_jump++; break;
	case ZTEX_RB_NOISE: stats->rb_noise++; break;
	default: break;
	}
}

static enum ztex_rb_cause ztex_rb_read_once(struct libztex_device *ztex,
		struct ztex_stats *stats, uint32_t last_nonce, int *rc,
		uint32_t *nonce, uint32_t *hash7, uint32_t golden[2],
		unsigned char raw[16], uint64_t *duration_us)
{
	*nonce = 0;
	*hash7 = 0;
	golden[0] = 0;
	golden[1] = 0;
	memset(raw, 0, 16);
	*duration_us = 0;
	*rc = libztex_readDataEx(ztex, nonce, hash7, golden, raw,
		duration_us);
	{
		enum ztex_rb_cause cause = ztex_rb_classify_frame(*rc, *nonce,
			*hash7, golden[0], last_nonce, opt_algo == ALGO_SHA3T);
		ztex_rb_count_cause(stats, cause);
		return cause;
	}
}

static enum ztex_rb_work_match ztex_rb_compare_work_hash7(
		const uint32_t *current, const uint32_t *previous,
		bool previous_valid, uint32_t nonce, uint32_t observed,
		uint32_t *current_hash7, uint32_t *previous_hash7)
{
	uint32_t header[20], hash[8];

	memcpy(header, current, sizeof(header));
	header[g_nonce_word_index] = nonce;
	calc_hash((unsigned char *)header, (unsigned char *)hash);
	*current_hash7 = hash[7];

	*previous_hash7 = 0;
	if (previous_valid) {
		memcpy(header, previous, sizeof(header));
		header[g_nonce_word_index] = nonce;
		calc_hash((unsigned char *)header, (unsigned char *)hash);
		*previous_hash7 = hash[7];
	}

	return ztex_rb_match_hash7(observed, *current_hash7,
		previous_valid, *previous_hash7);
}

static void ztex_rb_count_match(struct ztex_stats *stats,
				enum ztex_rb_work_match match)
{
	switch (match) {
	case ZTEX_RB_MATCH_CURRENT: stats->rb_match_current++; break;
	case ZTEX_RB_MATCH_PREVIOUS: stats->rb_match_previous++; break;
	case ZTEX_RB_MATCH_BOTH: stats->rb_match_both++; break;
	case ZTEX_RB_MATCH_NEITHER: stats->rb_match_neither++; break;
	default: break;
	}
}

static bool ztex_rb_send_trace_short(const struct libztex_send_trace *trace)
{
	unsigned i;
	for (i = 0; i < trace->stored; i++) {
		if (trace->returned[i] >= 0 &&
		    trace->returned[i] != trace->requested[i])
			return true;
	}
	return false;
}

static void ztex_rb_log_work(struct fpga_info *fpga,
		struct libztex_device *ztex, int lane, uint64_t work_seq,
		unsigned attempt, bool selected, uint64_t select_us, int rc,
		int expected, const struct libztex_send_trace *trace)
{
	applog(LOG_WARNING,
		"RBWORK v=1 board=%s serial=%s lane=%d work=%" PRIu64
		" try=%u sel=%d sel_us=%" PRIu64 " rc=%d expected=%d"
		" calls=%u stored=%u total=%d short=%d overflow=%d total_us=%" PRIu64
		" c0=%d/%d@%" PRIu64 " c1=%d/%d@%" PRIu64
		" c2=%d/%d@%" PRIu64 " c3=%d/%d@%" PRIu64,
		fpga->short_name, (const char *)ztex->snString, lane, work_seq,
		attempt, selected ? 1 : 0, select_us, rc, expected,
		trace->calls, trace->stored, trace->total,
		ztex_rb_send_trace_short(trace) ? 1 : 0,
		trace->overflow ? 1 : 0, trace->total_us,
		trace->requested[0], trace->returned[0], trace->duration_us[0],
		trace->requested[1], trace->returned[1], trace->duration_us[1],
		trace->requested[2], trace->returned[2], trace->duration_us[2],
		trace->requested[3], trace->returned[3], trace->duration_us[3]);
}

static void ztex_rb_log_frame(struct fpga_info *fpga,
		struct libztex_device *ztex, int lane, uint64_t work_seq,
		uint64_t poll_seq, uint64_t event_id, unsigned attempt,
		enum ztex_rb_cause cause, bool selected, int rc,
		uint64_t select_us, uint64_t read_us, uint32_t nonce,
		uint32_t hash7,
		const uint32_t golden[2], uint32_t last_nonce,
		bool clean_this_work, enum ztex_rb_work_match match,
		uint32_t current_hash7, uint32_t previous_hash7,
		const unsigned char raw[16])
{
	applog(LOG_WARNING,
		"RBFAIL v=1 board=%s serial=%s lane=%d work=%" PRIu64
		" poll=%" PRIu64 " event=%" PRIu64 " try=%u cause=%s"
		" sel=%d rc=%d sel_us=%" PRIu64 " read_us=%" PRIu64
		" nonce=%08X hash7=%08X"
		" g1=%08X g2=%08X last=%08X clean=%d cur_h7=%08X"
		" prev_h7=%08X match=%s raw="
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		fpga->short_name, (const char *)ztex->snString, lane,
		work_seq, poll_seq, event_id, attempt,
		ztex_rb_cause_name(cause), selected ? 1 : 0, rc,
		select_us, read_us, nonce, hash7, golden[0], golden[1], last_nonce,
		clean_this_work ? 1 : 0, current_hash7, previous_hash7,
		ztex_rb_match_name(match),
		raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}

#define BC3_ZTEX_V2_IO_TIMEOUT_MS 500u
#define BC3_ZTEX_V2_POLL_MS 10u
#define BC3_ZTEX_V2_WORK_RETRY_US UINT64_C(250000)
#define BC3_ZTEX_V2_STATUS_TIMEOUT_US UINT64_C(30000000)
#define BC3_ZTEX_V2_ACTION_TIMEOUT_US UINT64_C(20000000)
#define BC3_ZTEX_V2_DRAIN_TIMEOUT_US UINT64_C(30000000)
#define BC3_ZTEX_V2_RATE_STALE_US UINT64_C(2000000)
#define BC3_ZTEX_V2_NO_PROGRESS_TIMEOUT_US UINT64_C(60000000)
#define BC3_ZTEX_V2_STARTUP_DRAIN_TIMEOUT_US UINT64_C(5000000)
#define BC3_ZTEX_V2_FIRST_WORK_TIMEOUT_US UINT64_C(30000000)
#define BC3_ZTEX_V2_MAX_WORK_AGE_US UINT64_C(120000000)
#define BC3_ZTEX_V2_RATE_INTERVAL_US UINT64_C(30000000)
#define BC3_ZTEX_V2_DISPLAY_INTERVAL_US UINT64_C(1000000)
#define BC3_ZTEX_V2_MAX_HPS UINT64_C(22000000)
#define BC3_ZTEX_V2_SNAPSHOT_AGE_US UINT64_C(12000)
#define BC3_ZTEX_V2_BURST_SLACK UINT32_C(45)
#define BC3_ZTEX_V2_LANES 4

struct bc3_ztex_v2_lane {
	struct bc3_ztex_session_state session;
	struct bc3_ztex_result_state result;
	struct bc3_ztex_progress_state progress;
	struct work active_work;
	struct work pending_work;
	bool active_work_valid;
	bool pending_work_valid;
	bool want_new_work;
	bool sticky_error_seen;
	bool verification_failure_seen;
	bool ack_pending;
	bool publish_blocked;
	bool last_status_head_valid;
	bool drain_observed;
	bool drain_status_ok;
	struct bc3_ztex_result_key publish_key;
	uint8_t pending_frames[2][BC3_ZTEX_WORK_FRAME_SIZE];
	uint64_t pending_started_us;
	uint64_t pending_last_send_us;
	uint64_t ack_pending_since_us;
	uint64_t publish_blocked_since_us;
	uint64_t pause_last_send_us;
	uint64_t active_since_us;
	uint64_t last_good_status_us;
	uint64_t last_hash_progress_us;
	uint64_t first_work_wait_started_us;
};

enum bc3_ztex_v2_prepare_result {
	BC3_ZTEX_V2_PREPARE_FATAL = -1,
	BC3_ZTEX_V2_PREPARE_WAIT = 0,
	BC3_ZTEX_V2_PREPARE_READY = 1
};

static uint32_t bc3_ztex_v2_session_id(int board_index, int lane)
{
	uint32_t board_part = (uint32_t)(board_index + 1);
	uint32_t lane_part = (uint32_t)(lane + 1);

	return UINT32_C(0xb3000000) | (board_part << 8) | lane_part;
}

static void bc3_ztex_v2_record_rate(struct ztex_stats *stats, double raw)
{
	double sorted[25];
	int count;
	int history_size;
	int history_index;
	int i;

	if (!stats || raw <= 0.0)
		return;
	stats->hashrate = raw;
	history_size = (int)(sizeof(stats->hr_hist) / sizeof(stats->hr_hist[0]));
	history_index = stats->hr_idx;
	if (history_index < 0 || history_index >= history_size)
		history_index = 0;
	stats->hr_hist[history_index] = raw;
	history_index++;
	stats->hr_idx = history_index == history_size ? 0 : history_index;
	if (stats->hr_count < history_size)
		stats->hr_count++;
	count = stats->hr_count;
	for (i = 0; i < count; ++i)
		sorted[i] = stats->hr_hist[i];
	for (i = 1; i < count; ++i) {
		double value = sorted[i];
		int j = i - 1;
		while (j >= 0 && sorted[j] > value) {
			sorted[j + 1] = sorted[j];
			j--;
		}
		sorted[j + 1] = value;
	}
	stats->hashrate_smooth = sorted[count / 2];
}

static void bc3_ztex_v2_clear_rate(struct ztex_stats *stats)
{
	if (!stats)
		return;
	clear_lane_hashrate(&stats->hashrate, &stats->hashrate_smooth);
	memset(stats->hr_hist, 0, sizeof(stats->hr_hist));
	stats->hr_idx = 0;
	stats->hr_count = 0;
}

static enum bc3_ztex_v2_prepare_result bc3_ztex_v2_prepare_work(
	struct bc3_ztex_v2_lane *lane, struct thr_info *mythr,
	struct fpga_info *fpga, int lane_index)
{
	struct bc3_ztex_tuple tuple;
	struct work candidate;
	uint8_t physical_work[BC3_ZTEX_WORK_SIZE];

	if (!lane || !mythr || !fpga || lane_index < 0 ||
	    lane->pending_work_valid || lane->session.pending_valid)
		return BC3_ZTEX_V2_PREPARE_FATAL;
	if (!have_stratum)
		return BC3_ZTEX_V2_PREPARE_WAIT;
	memset(&candidate, 0, sizeof(candidate));
	candidate.dev_board = -1;
	candidate.dev_fpga = -1;
	{
		enum stratum_gen_result generated =
			stratum_gen_work_result(&stratum, &candidate);

		if (generated != STRATUM_GEN_READY) {
			work_free(&candidate);
			return generated == STRATUM_GEN_WAIT ?
				BC3_ZTEX_V2_PREPARE_WAIT : BC3_ZTEX_V2_PREPARE_FATAL;
		}
	}
	if (!bc3_ztex_pack_work(physical_work, candidate.data,
		    sizeof(candidate.data) / sizeof(candidate.data[0]),
		    candidate.target,
		    sizeof(candidate.target) / sizeof(candidate.target[0])) ||
	    !bc3_ztex_session_begin_offer(&lane->session, &tuple) ||
	    !bc3_ztex_encode_work_fragment(lane->pending_frames[0],
		    tuple.session, tuple.epoch, 0, physical_work) ||
	    !bc3_ztex_encode_work_fragment(lane->pending_frames[1],
		    tuple.session, tuple.epoch, 1, physical_work)) {
		work_free(&candidate);
		return BC3_ZTEX_V2_PREPARE_FATAL;
	}
	lane->pending_work = candidate;
	lane->pending_work.dev_board = fpga->board_idx;
	lane->pending_work.dev_fpga = lane_index;
	lane->pending_work_valid = true;
	lane->pending_started_us = ztex_rb_now_us();
	lane->pending_last_send_us = 0;
	lane->want_new_work = false;
	return BC3_ZTEX_V2_PREPARE_READY;
}

static bool bc3_ztex_v2_send_pending(const struct bc3_ztex_io_ops *ops,
	struct bc3_ztex_v2_lane *lane, struct ztex_stats *stats,
	int lane_index)
{
	unsigned failed_fragment;
	int error_code;
	bool sent;

	stats->v2_work_attempts++;
	if (lane->pending_last_send_us != 0)
		stats->v2_work_retries++;
	sent = bc3_ztex_io_send_work_pair(ops, lane_index,
		&lane->pending_frames[0][0], BC3_ZTEX_V2_IO_TIMEOUT_MS,
		&failed_fragment, &error_code);
	/* Timestamp after the possibly blocking USB request.  Using its start time
	 * can collapse the retry interval after a timeout. */
	lane->pending_last_send_us = ztex_rb_now_us();
	if (!sent) {
		stats->v2_io_errors++;
		applog(LOG_DEBUG,
			"R34 lane %d work pair attempt failed at fragment %u (rc=%d)",
			lane_index, failed_fragment, error_code);
	}
	return sent;
}

static bool bc3_ztex_v2_send_ack(const struct bc3_ztex_io_ops *ops,
	struct bc3_ztex_result_state *result_state,
	struct ztex_stats *stats, int lane_index,
	const struct bc3_ztex_status *status, bool retry)
{
	uint8_t frame[BC3_ZTEX_ACK_FRAME_SIZE];
	int rc;

	if (!bc3_ztex_result_ack_allowed(result_state, status) ||
	    !bc3_ztex_encode_ack(frame, status))
		return false;
	stats->v2_ack_attempts++;
	if (retry)
		stats->v2_ack_retries++;
	rc = bc3_ztex_io_send_selected(ops, lane_index, frame,
		(int)sizeof(frame), BC3_ZTEX_V2_IO_TIMEOUT_MS);
	if (rc != (int)sizeof(frame)) {
		stats->v2_io_errors++;
		return true; /* ambiguous: the identical head drives ACK_RETRY */
	}
	return true;
}

static bool bc3_ztex_v2_send_pause(const struct bc3_ztex_io_ops *ops,
	struct bc3_ztex_v2_lane *lane, struct ztex_stats *stats,
	int lane_index, uint32_t build_id)
{
	uint8_t frame[BC3_ZTEX_PAUSE_FRAME_SIZE];
	int rc;

	if (!bc3_ztex_encode_pause(frame, build_id))
		return false;
	stats->v2_pause_attempts++;
	if (lane->pause_last_send_us != 0)
		stats->v2_pause_retries++;
	rc = bc3_ztex_io_send_selected(ops, lane_index, frame,
		(int)sizeof(frame), BC3_ZTEX_V2_IO_TIMEOUT_MS);
	lane->pause_last_send_us = ztex_rb_now_us();
	if (rc != (int)sizeof(frame))
		stats->v2_io_errors++;
	/* Delivery is ambiguous on every transport failure.  The exact same
	 * build-bound frame is retried until status proves PAUSE_LATCHED and
	 * QUIESCED; only local encoding failure is terminal here. */
	return true;
}

/* Before the board worker exists, main is still the sole USB owner. Send
 * typed PAUSE only to lanes whose exact ABI/build was already decoded, then
 * require the same quiesced+empty proof used by the runtime barrier. */
static bool bc3_ztex_v2_prework_pause_barrier(struct libztex_device *ztex,
	uint8_t compatible_mask)
{
	struct bc3_ztex_io_ops ops;
	uint8_t pause_frame[BC3_ZTEX_PAUSE_FRAME_SIZE];
	uint8_t status_frame[BC3_ZTEX_STATUS_FRAME_SIZE];
	uint8_t pending = compatible_mask;
	uint64_t started_us;
	int lane;

	if (!ztex || compatible_mask == 0 ||
	    !bc3_ztex_encode_pause(pause_frame, bc3_ztex_v2_build_id))
		return false;
	ops = bc3_ztex_make_io_ops(ztex);
	started_us = ztex_rb_now_us();
	while (pending != 0 &&
	       ztex_rb_now_us() - started_us <=
		       BC3_ZTEX_V2_STARTUP_DRAIN_TIMEOUT_US) {
		for (lane = 0; lane < BC3_ZTEX_V2_LANES; ++lane) {
			struct bc3_ztex_status status;
			uint8_t lane_bit = (uint8_t)(UINT32_C(1) << (unsigned)lane);

			if (!(pending & lane_bit))
				continue;
			(void)bc3_ztex_io_send_selected(&ops, lane, pause_frame,
				(int)sizeof(pause_frame), BC3_ZTEX_V2_IO_TIMEOUT_MS);
			if (bc3_ztex_io_read_selected(&ops, lane, status_frame,
				    (int)sizeof(status_frame),
				    BC3_ZTEX_V2_IO_TIMEOUT_MS) ==
					    (int)sizeof(status_frame) &&
			    bc3_ztex_decode_status(&status, status_frame,
				    sizeof(status_frame)) &&
			    bc3_ztex_quiesced_empty_status_ok(&status,
				    bc3_ztex_v2_build_id))
				pending &= (uint8_t)~lane_bit;
		}
		if (pending != 0)
			nmsleep(10);
	}
	return pending == 0;
}

static uint8_t bc3_ztex_v2_refresh_compatible_mask(
	struct libztex_device *ztex, uint8_t configured_mask,
	uint8_t compatible_mask)
{
	struct bc3_ztex_io_ops ops;
	uint8_t status_frame[BC3_ZTEX_STATUS_FRAME_SIZE];
	int lane;

	if (!ztex)
		return compatible_mask;
	ops = bc3_ztex_make_io_ops(ztex);
	for (lane = 0; lane < BC3_ZTEX_V2_LANES; ++lane) {
		struct bc3_ztex_status status;
		uint8_t lane_bit = (uint8_t)(UINT32_C(1) << (unsigned)lane);

		if (!(configured_mask & lane_bit) ||
		    (compatible_mask & lane_bit))
			continue;
		if (bc3_ztex_io_read_selected(&ops, lane, status_frame,
			    (int)sizeof(status_frame), BC3_ZTEX_V2_IO_TIMEOUT_MS) ==
				    (int)sizeof(status_frame) &&
		    bc3_ztex_decode_status(&status, status_frame,
			    sizeof(status_frame)) &&
		    bc3_ztex_status_compatible(&status, bc3_ztex_v2_build_id))
			compatible_mask |= lane_bit;
	}
	return compatible_mask;
}

static int bc3_ztex_v2_startup_failure(const char *reason)
{
	uint8_t selected_mask = 0;
	uint8_t cleanup_mask;
	uint8_t unknown_mask;
	bool known;
	bool paused;

	if (!bc3_ztex_v2_active)
		return EXIT_FAILURE;
	if (ztex_lane_policies && g_ztex_fpga_count == 1)
		selected_mask = ztex_lane_policies[0].selection_mask;
	if (ztex_info)
		bc3_ztex_v2_compatible_lane_mask =
			bc3_ztex_v2_refresh_compatible_mask(&ztex_info[0],
				bc3_ztex_v2_configured_lane_mask,
				bc3_ztex_v2_compatible_lane_mask);
	cleanup_mask = bc3_ztex_v2_configured_lane_mask &
		bc3_ztex_v2_compatible_lane_mask;
	unknown_mask = (bc3_ztex_v2_attempted_lane_mask &
		(uint8_t)~bc3_ztex_v2_configured_lane_mask) |
		(bc3_ztex_v2_configured_lane_mask &
		 (uint8_t)~bc3_ztex_v2_compatible_lane_mask);
	paused = cleanup_mask == 0 ? bc3_ztex_v2_configured_lane_mask == 0 :
		(ztex_info && bc3_ztex_v2_prework_pause_barrier(&ztex_info[0],
			cleanup_mask));
	known = unknown_mask == 0 && paused &&
		cleanup_mask == bc3_ztex_v2_configured_lane_mask;
	if (known && paused)
		applog(LOG_ERR,
			"typed startup failed (%s); cleanup proven (selected=%02x configured=%02x paused=%02x)",
			reason ? reason : "unknown", selected_mask,
			bc3_ztex_v2_configured_lane_mask, cleanup_mask);
	else
		applog(LOG_ERR,
			"typed startup failed (%s); PAUSE/drain unproven (selected=%02x attempted=%02x configured=%02x compatible=%02x unknown=%02x); immediate rollback required",
			reason ? reason : "unknown", selected_mask,
			bc3_ztex_v2_attempted_lane_mask,
			bc3_ztex_v2_configured_lane_mask,
			bc3_ztex_v2_compatible_lane_mask, unknown_mask);
	return EXIT_FAILURE;
}

/* Observe ACK progress before work reconciliation.  A status that switches
 * to a new tuple may already expose that tuple's first result, so the prior
 * tuple's processed-key state must be retired before the per-work sequence
 * checker is reset. */
static bool bc3_ztex_v2_observe_head(struct bc3_ztex_v2_lane *lane,
	const struct bc3_ztex_status *status)
{
	struct bc3_ztex_result_key visible_key;
	bool head_valid;

	if (!lane || !status)
		return false;
	head_valid = (status->flags & BC3_ZTEX_FLAG_HEAD_VALID) != 0;
	lane->last_status_head_valid = head_valid;
	if (lane->ack_pending) {
		if (!head_valid) {
			lane->ack_pending = false;
			lane->ack_pending_since_us = 0;
		} else if (!bc3_ztex_result_key_from_status(status, &visible_key)) {
			return false;
		} else if (!bc3_ztex_result_key_equal(
			    lane->result.processed, visible_key)) {
			lane->ack_pending = false;
			lane->ack_pending_since_us = 0;
		}
	}
	if (lane->publish_blocked &&
	    (!head_valid ||
	     !bc3_ztex_result_key_from_status(status, &visible_key) ||
	     !bc3_ztex_result_key_equal(lane->publish_key, visible_key)))
		return false;
	return true;
}

/* Return 1 for a handled/empty status, 0 when queue publication must retry,
 * and -1 for an invariant violation requiring candidate rollback. */
static int bc3_ztex_v2_handle_result(const struct bc3_ztex_io_ops *ops,
	struct bc3_ztex_v2_lane *lane, struct ztex_stats *stats,
	struct thr_info *mythr, struct fpga_info *fpga, int lane_index,
	enum bc3_ztex_work_slot head_slot,
	const struct bc3_ztex_status *status, uint64_t status_now_us)
{
	struct bc3_ztex_result_key key;
	enum bc3_ztex_result_disposition disposition;
	struct work candidate;
	uint32_t hash[8];
	bool share;

	disposition = bc3_ztex_result_classify(&lane->result, status, &key);
	if (disposition == BC3_ZTEX_RESULT_EMPTY)
		return head_slot == BC3_ZTEX_SLOT_NONE &&
			!lane->publish_blocked ? 1 : -1;
	if (disposition == BC3_ZTEX_RESULT_INVALID)
		return -1;
	if (disposition == BC3_ZTEX_RESULT_ACK_RETRY) {
		if (!lane->ack_pending || lane->ack_pending_since_us == 0)
			return -1;
		return bc3_ztex_v2_send_ack(ops, &lane->result, stats,
			lane_index, status, true) ? 1 : -1;
	}
	if (head_slot != BC3_ZTEX_SLOT_ACTIVE || !lane->active_work_valid)
		return -1;

	candidate = lane->active_work; /* shallow, non-owning verification view */
	candidate.data[g_nonce_word_index] = key.nonce;
	calc_hash((unsigned char *)candidate.data, (unsigned char *)hash);
	stats->hash_checks++;
	share = fulltest(hash, candidate.target);
	if (hash[7] != key.hash7 || hash[7] > candidate.target[7] ||
	    (!share && hash[7] < candidate.target[7])) {
		stats->hash_errors++;
		stats->hw_errors++;
		fpga->hw_errors++;
		lane->verification_failure_seen = true;
		applog(LOG_ERR,
			"%s-%d: R34 result verification failed nonce=%08" PRIx32
			" reported=%08" PRIx32 " computed=%08" PRIx32,
			fpga->short_name, lane_index, key.nonce, key.hash7, hash[7]);
	} else if (share) {
		candidate.dev_board = fpga->board_idx;
		candidate.dev_fpga = lane_index;
		if (!work_publish_retry(mythr, &candidate, 3,
			    work_publish_submit_work, work_publish_retry_pause)) {
			if (!lane->publish_blocked) {
				lane->publish_blocked = true;
				lane->publish_key = key;
				lane->publish_blocked_since_us = status_now_us;
				applog(LOG_ERR,
					"%s-%d: R34 result publication blocked; retaining unacknowledged FIFO head",
					fpga->short_name, lane_index);
			}
			return 0;
		}
		lane->publish_blocked = false;
		lane->publish_blocked_since_us = 0;
		applog(LOG_WARNING,
			"%s-%d: Submit Nonce - %08" PRIx32 " (hash7=%08" PRIx32 ")",
			fpga->short_name, lane_index, key.nonce, hash[7]);
		stats->submitted++;
		if (fulltest(hash, candidate.block_target)) {
			applog(LOG_NOTICE, "%s-%d: %s***** BLOCK FOUND *****",
				fpga->short_name, lane_index, CL_GRN);
			g_block_count++;
		}
	} else {
		applog(LOG_DEBUG,
			"%s-%d: Share Above Target - %08" PRIx32 " (%.1f MH/s)",
			fpga->short_name, lane_index, key.nonce,
			stats->hashrate_smooth / 1000000.0);
	}

	if (!bc3_ztex_result_mark_processed(&lane->result, status, &key))
		return -1;
	lane->ack_pending = true;
	lane->ack_pending_since_us = status_now_us;
	return bc3_ztex_v2_send_ack(ops, &lane->result, stats, lane_index,
		status, false) ? 1 : -1;
}

/* Qualify every displayed completion-rate window with a coherent diagnostic
 * from the same active work tuple. Generation, nonce, and hash7 are snapshotted
 * atomically in RTL; nonce zero is ordinary data because generation zero alone
 * denotes "not yet valid". */
static bool bc3_ztex_v2_verify_progress(struct bc3_ztex_v2_lane *lane,
	struct ztex_stats *stats, struct fpga_info *fpga, int lane_index,
	const struct bc3_ztex_status *status, bool baseline)
{
	struct bc3_ztex_progress_key key;
	struct work candidate;
	uint32_t hash[8];
	enum bc3_ztex_progress_disposition disposition;

	if (!lane || !stats || !fpga || !status || !lane->active_work_valid)
		return false;
	disposition = bc3_ztex_progress_classify(&lane->progress, status, &key);
	/* An advancing SAMPLE requires NEW.  A non-publishing long-gap BASELINE
	 * may reuse only the exact immutable diagnostic already CPU-verified. */
	if (!bc3_ztex_progress_allowed_for_rate(disposition, baseline)) {
		stats->hash_errors++;
		stats->hw_errors++;
		fpga->hw_errors++;
		applog(LOG_ERR,
			"%s-%d: R34 progress identity invalid/stale generation=%08" PRIx32,
			fpga->short_name, lane_index, status->progress_generation);
		return false;
	}
	if (disposition == BC3_ZTEX_PROGRESS_REPEAT)
		return true;
	candidate = lane->active_work; /* shallow, non-owning verification view */
	candidate.data[g_nonce_word_index] = key.nonce;
	calc_hash((unsigned char *)candidate.data, (unsigned char *)hash);
	stats->hash_checks++;
	if (hash[7] != key.hash7 ||
	    !bc3_ztex_progress_mark_verified(&lane->progress, status, &key)) {
		stats->hash_errors++;
		stats->hw_errors++;
		fpga->hw_errors++;
		applog(LOG_ERR,
			"%s-%d: R34 progress verification failed generation=%08" PRIx32
			" nonce=%08" PRIx32 " reported=%08" PRIx32
			" computed=%08" PRIx32,
			fpga->short_name, lane_index, key.generation, key.nonce,
			key.hash7, hash[7]);
		return false;
	}
	return true;
}

static void bc3_ztex_v2_activate_pending(struct bc3_ztex_v2_lane *lane,
	uint64_t now_us)
{
	if (lane->active_work_valid)
		work_free(&lane->active_work);
	lane->active_work = lane->pending_work;
	memset(&lane->pending_work, 0, sizeof(lane->pending_work));
	lane->active_work_valid = true;
	lane->pending_work_valid = false;
	bc3_ztex_result_init(&lane->result);
	bc3_ztex_progress_init(&lane->progress);
	lane->ack_pending = false;
	lane->ack_pending_since_us = 0;
	memset(lane->pending_frames, 0, sizeof(lane->pending_frames));
	lane->pending_started_us = 0;
	lane->pending_last_send_us = 0;
	lane->active_since_us = now_us;
	lane->last_hash_progress_us = now_us;
	lane->first_work_wait_started_us = 0;
}

static void bc3_ztex_v2_cleanup(struct bc3_ztex_v2_lane *lanes,
	int num_fpgas)
{
	int lane_index;

	if (!lanes)
		return;
	for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
		if (lanes[lane_index].active_work_valid)
			work_free(&lanes[lane_index].active_work);
		if (lanes[lane_index].pending_work_valid)
			work_free(&lanes[lane_index].pending_work);
	}
}

static void bc3_ztex_v2_latch_drain(struct bc3_ztex_v2_lane *lanes,
	int num_fpgas, bool *drain_requested, uint64_t *drain_started_us,
	const char **drain_reason, uint64_t now_us, const char *reason)
{
	int lane_index;

	if (!lanes || !drain_requested || !drain_started_us ||
	    !drain_reason || *drain_requested)
		return;
	*drain_requested = true;
	*drain_started_us = now_us;
	*drain_reason = reason;
	for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
		lanes[lane_index].want_new_work = false;
		lanes[lane_index].drain_observed = false;
		lanes[lane_index].drain_status_ok = false;
		lanes[lane_index].pause_last_send_us = 0;
	}
}

static void bc3_ztex_v2_latch_failure(struct bc3_ztex_v2_lane *lanes,
	int num_fpgas, bool *drain_requested, uint64_t *drain_started_us,
	const char **drain_reason, const char **failure_reason,
	uint64_t now_us, const char *reason)
{
	if (!failure_reason || !reason)
		return;
	/* Record the process-wide failure before beginning the hardware barrier.
	 * This is monotone and makes the eventual typed workio STOP ineligible for
	 * a successful exit even if the local worker result were mishandled. */
	bc3_ztex_v2_request_control_stop(true);
	if (!*failure_reason)
		*failure_reason = reason;
	bc3_ztex_v2_latch_drain(lanes, num_fpgas, drain_requested,
		drain_started_us, drain_reason, now_us, reason);
}

static bool bc3_ztex_v2_drain_complete(
	const struct bc3_ztex_v2_lane *lanes,
	const struct ztex_stats *stats, int num_fpgas)
{
	int lane_index;

	if (!lanes || !stats)
		return false;
	for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
		if (!stats[lane_index].enabled)
			continue;
		if (!lanes[lane_index].drain_observed ||
		    !lanes[lane_index].drain_status_ok ||
		    lanes[lane_index].last_status_head_valid ||
		    lanes[lane_index].ack_pending ||
		    lanes[lane_index].publish_blocked)
			return false;
	}
	return true;
}

static void *bc3_ztex_v2_miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	struct fpga_info *fpga = mythr->fpga;
	struct libztex_device *ztex = fpga->ztex_info;
	struct ztex_stats *stats = fpga->ztex_stats;
	struct bc3_ztex_io_ops ops = bc3_ztex_make_io_ops(ztex);
	struct bc3_ztex_v2_lane lane_storage[BC3_ZTEX_V2_LANES];
	struct bc3_ztex_v2_lane *lanes = lane_storage;
	uint64_t observed_generation = current_work_generation();
	uint64_t rotation_us;
	time_t last_heartbeat = 0;
	int num_fpgas = ztex->numberOfFpgas;
	int lane_index;
	const char *fatal_reason = NULL;
	const char *drain_reason = NULL;
	bool drain_requested = false;
	uint64_t drain_started_us = 0;

	if (num_fpgas != BC3_ZTEX_V2_LANES) {
		applog(LOG_ERR, "%s: typed runtime lane topology changed to %d",
			fpga->short_name, num_fpgas);
		if (!bc3_ztex_v2_prework_pause_barrier(ztex,
			    bc3_ztex_v2_compatible_lane_mask))
			applog(LOG_ERR,
				"%s: topology failure PAUSE/drain unproven; immediate rollback required",
				fpga->short_name);
		bc3_ztex_v2_request_control_stop(true);
		if (!bc3_ztex_v2_enqueue_workio_stop())
			proper_exit(EXIT_FAILURE);
		return (void *)(intptr_t)EXIT_FAILURE;
	}
	memset(lane_storage, 0, sizeof(lane_storage));
	rotation_us = fpga->timeout > 0 ?
		(uint64_t)fpga->timeout * UINT64_C(1000000) : UINT64_C(5000000);
	if (rotation_us > BC3_ZTEX_V2_MAX_WORK_AGE_US)
		rotation_us = BC3_ZTEX_V2_MAX_WORK_AGE_US;
	for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
		if (!stats[lane_index].enabled)
			continue;
		if (!bc3_ztex_session_init(&lanes[lane_index].session,
			    bc3_ztex_v2_build_id,
			    bc3_ztex_v2_session_id(fpga->board_idx, lane_index))) {
			bc3_ztex_v2_latch_failure(lanes, num_fpgas,
				&drain_requested, &drain_started_us,
				&drain_reason, &fatal_reason, ztex_rb_now_us(),
				"session initialization failed");
			continue;
		}
		bc3_ztex_result_init(&lanes[lane_index].result);
		bc3_ztex_progress_init(&lanes[lane_index].progress);
		lanes[lane_index].want_new_work = true;
		lanes[lane_index].last_good_status_us = ztex_rb_now_us();
		lanes[lane_index].first_work_wait_started_us =
			lanes[lane_index].last_good_status_us;
	}
	applog(LOG_WARNING,
		"%s: R34 typed miner active (BUILD_ID=%08" PRIx32
		", rotation=%" PRIu64 " ms)",
		fpga->short_name, bc3_ztex_v2_build_id, rotation_us / 1000);

	for (;;) {
		uint64_t generation = current_work_generation();
		bool control_stop_requested = false;
		bool control_stop_failure = false;

		bc3_ztex_v2_control_snapshot(&control_stop_requested,
			&control_stop_failure);
		if (control_stop_failure && !fatal_reason)
			fatal_reason = "work/service thread stopped";
		if (!drain_requested &&
		    (bc3_ztex_v2_signal_stop_requested ||
		     control_stop_requested)) {
			uint64_t stop_now_us = ztex_rb_now_us();
			const char *stop_reason;

			/* Signal handlers can only publish sig_atomic state. Mirror that
			 * observation into the mutex-protected coordinator before PAUSE. */
			if (bc3_ztex_v2_signal_stop_requested)
				bc3_ztex_v2_request_control_stop(false);
			if (control_stop_failure) {
				stop_reason = "work/service thread stopped";
			} else if (bc3_ztex_v2_stop_signal == SIGTERM) {
				stop_reason = "SIGTERM requested orderly shutdown";
			} else if (bc3_ztex_v2_stop_signal == SIGINT) {
				stop_reason = "SIGINT requested orderly shutdown";
			}
#ifndef WIN32
			else if (bc3_ztex_v2_stop_signal == SIGHUP) {
				stop_reason = "SIGHUP requested orderly shutdown";
			} else if (bc3_ztex_v2_stop_signal == SIGQUIT) {
				stop_reason = "SIGQUIT requested orderly shutdown";
			}
#endif
			else {
				stop_reason = "orderly shutdown requested";
			}
			applog(control_stop_failure ? LOG_ERR : LOG_WARNING,
				"%s: %s; entering typed PAUSE/drain barrier",
				fpga->short_name, stop_reason);
			bc3_ztex_v2_latch_drain(lanes, num_fpgas,
				&drain_requested, &drain_started_us,
				&drain_reason, stop_now_us, stop_reason);
		}

		if (generation != observed_generation) {
			observed_generation = generation;
			if (!drain_requested)
				for (lane_index = 0; lane_index < num_fpgas; ++lane_index)
					if (stats[lane_index].enabled)
						lanes[lane_index].want_new_work = true;
		}
		for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
			struct bc3_ztex_v2_lane *lane = &lanes[lane_index];
			struct bc3_ztex_status status;
			enum bc3_ztex_work_slot head_slot;
			enum bc3_ztex_rate_disposition rate_disposition;
			enum bc3_ztex_display_rate_disposition display_rate_disposition;
			bool switched;
			uint8_t status_frame[BC3_ZTEX_STATUS_FRAME_SIZE];
			uint32_t completed_delta;
			uint64_t elapsed_us;
			uint64_t lane_now_us;
			uint64_t status_now_us;
			int rc;
			int handled;

			if (!stats[lane_index].enabled)
				continue;
			lane_now_us = ztex_rb_now_us();
			if ((lane->pending_work_valid &&
			     (lane->pending_started_us == 0 ||
			      lane_now_us - lane->pending_started_us >
				      BC3_ZTEX_V2_ACTION_TIMEOUT_US)) ||
			    (lane->ack_pending &&
			     (lane->ack_pending_since_us == 0 ||
			      lane_now_us - lane->ack_pending_since_us >
				      BC3_ZTEX_V2_ACTION_TIMEOUT_US)) ||
			    (lane->publish_blocked &&
			     (lane->publish_blocked_since_us == 0 ||
			      lane_now_us - lane->publish_blocked_since_us >
				      BC3_ZTEX_V2_ACTION_TIMEOUT_US))) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, lane_now_us,
					"typed work/result action made no progress");
			}
			if (!drain_requested && lane->active_work_valid &&
			    !lane->pending_work_valid &&
			    lane_now_us - lane->active_since_us >= rotation_us)
				lane->want_new_work = true;
			if (bc3_ztex_first_work_timed_out(drain_requested,
				    lane->want_new_work, lane->active_work_valid,
				    lane->pending_work_valid,
				    lane->first_work_wait_started_us, lane_now_us,
				    BC3_ZTEX_V2_FIRST_WORK_TIMEOUT_US)) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, lane_now_us,
					"initial work activation timed out");
				goto next_lane;
			}
			if (!drain_requested && lane->want_new_work &&
			    !lane->pending_work_valid) {
				enum bc3_ztex_v2_prepare_result prepared =
					bc3_ztex_v2_prepare_work(lane, mythr, fpga,
						lane_index);
				if (prepared == BC3_ZTEX_V2_PREPARE_FATAL) {
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, lane_now_us,
						"work preparation invariant failed");
					goto next_lane;
				}
			}
			if (!drain_requested && lane->pending_work_valid &&
			    (lane->pending_last_send_us == 0 ||
			     lane_now_us - lane->pending_last_send_us >=
				     BC3_ZTEX_V2_WORK_RETRY_US))
				(void)bc3_ztex_v2_send_pending(&ops, lane,
					&stats[lane_index], lane_index);
			if (drain_requested &&
			    (lane->pause_last_send_us == 0 ||
			     lane_now_us - lane->pause_last_send_us >=
				     BC3_ZTEX_V2_WORK_RETRY_US) &&
			    !bc3_ztex_v2_send_pause(&ops, lane,
				    &stats[lane_index], lane_index,
				    bc3_ztex_v2_build_id)) {
				fatal_reason = "typed PAUSE encoding failed";
				goto fatal;
			}

			stats[lane_index].v2_status_reads++;
			rc = bc3_ztex_io_read_selected(&ops, lane_index,
				status_frame, (int)sizeof(status_frame),
				BC3_ZTEX_V2_IO_TIMEOUT_MS);
			status_now_us = ztex_rb_now_us();
			if (rc != (int)sizeof(status_frame)) {
				stats[lane_index].v2_io_errors++;
				if (status_now_us - lane->last_good_status_us >
				    BC3_ZTEX_V2_RATE_STALE_US)
					bc3_ztex_v2_clear_rate(&stats[lane_index]);
				if (drain_requested)
					lane->drain_observed = false;
				lane->drain_status_ok = false;
				if (status_now_us - lane->last_good_status_us >
				    BC3_ZTEX_V2_STATUS_TIMEOUT_US) {
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, status_now_us,
						"typed status transport timed out");
				}
				goto next_lane;
			}
			if (!bc3_ztex_decode_status(&status, status_frame,
				    sizeof(status_frame))) {
				stats[lane_index].v2_decode_errors++;
				if (status_now_us - lane->last_good_status_us >
				    BC3_ZTEX_V2_RATE_STALE_US)
					bc3_ztex_v2_clear_rate(&stats[lane_index]);
				if (drain_requested)
					lane->drain_observed = false;
				lane->drain_status_ok = false;
				if (status_now_us - lane->last_good_status_us >
				    BC3_ZTEX_V2_STATUS_TIMEOUT_US) {
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, status_now_us,
						"typed status decode timed out");
				}
				goto next_lane;
			}
			if (!bc3_ztex_status_compatible(&status,
				    bc3_ztex_v2_build_id)) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed status ABI/build/state mismatch");
				goto next_lane;
			}
			lane->last_good_status_us = status_now_us;
			if (!drain_requested &&
			    (status.flags & BC3_ZTEX_FLAG_PAUSE_LATCHED)) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"FPGA reported an unsolicited PAUSE latch");
			}
			if (!drain_requested &&
			    (status.flags & BC3_ZTEX_FLAG_ROTATION_REQUIRED))
				lane->want_new_work = true;
			if (!bc3_ztex_status_healthy(&status,
				    bc3_ztex_v2_build_id)) {
				if (!lane->sticky_error_seen)
					applog(LOG_ERR,
						"%s-%d: R34 sticky protocol error; draining known head then rollback required",
						fpga->short_name, lane_index);
				lane->sticky_error_seen = true;
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"FPGA reported sticky protocol error");
			}
			if (drain_requested &&
			    bc3_ztex_quiesced_empty_status_ok(&status,
				    bc3_ztex_v2_build_id) &&
			    !lane->ack_pending && !lane->publish_blocked) {
				lane->last_status_head_valid = false;
				lane->drain_observed = true;
				lane->drain_status_ok = true;
				bc3_ztex_v2_clear_rate(&stats[lane_index]);
				goto next_lane;
			}
			if (!bc3_ztex_v2_observe_head(lane, &status)) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed ACK/publication progress invariant failed");
				goto next_lane;
			}
			if (!bc3_ztex_session_reconcile(&lane->session, &status,
				    &head_slot, &switched)) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed work/session reconciliation failed");
				goto next_lane;
			}
			if (switched) {
				if (!lane->pending_work_valid) {
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, status_now_us,
						"hardware activated missing pending work");
					goto next_lane;
				}
				bc3_ztex_v2_activate_pending(lane, status_now_us);
				if (head_slot == BC3_ZTEX_SLOT_PENDING)
					head_slot = BC3_ZTEX_SLOT_ACTIVE;
			}
			handled = bc3_ztex_v2_handle_result(&ops, lane,
				&stats[lane_index], mythr, fpga, lane_index,
				head_slot, &status, status_now_us);
			if (handled < 0) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed result/ACK invariant failed");
				goto next_lane;
			}
			if (lane->sticky_error_seen) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"FPGA reported sticky protocol error");
			}
			if (lane->verification_failure_seen) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"FPGA result verification failed");
			}
			if (lane->result.exhausted) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed result sequence exhausted");
			}
			if (drain_requested) {
				lane->drain_observed = true;
				lane->drain_status_ok =
					bc3_ztex_quiesced_empty_status_ok(&status,
						bc3_ztex_v2_build_id);
				bc3_ztex_v2_clear_rate(&stats[lane_index]);
				goto next_lane;
			}
			if (!(status.flags & BC3_ZTEX_FLAG_ACTIVE_VALID)) {
				bc3_ztex_v2_clear_rate(&stats[lane_index]);
				goto next_lane;
			}
			rate_disposition = bc3_ztex_session_rate_sample(
				&lane->session, &status, status_now_us,
				BC3_ZTEX_V2_RATE_INTERVAL_US,
				BC3_ZTEX_V2_MAX_HPS,
				BC3_ZTEX_V2_SNAPSHOT_AGE_US,
				BC3_ZTEX_V2_BURST_SLACK,
				&completed_delta, &elapsed_us);
			if (rate_disposition == BC3_ZTEX_RATE_INVALID) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed completion-rate invariant failed");
				goto next_lane;
			}
			display_rate_disposition = bc3_ztex_session_display_rate_sample(
				&lane->session, &status, status_now_us,
				BC3_ZTEX_V2_DISPLAY_INTERVAL_US,
				BC3_ZTEX_V2_RATE_INTERVAL_US,
				BC3_ZTEX_V2_MAX_HPS,
				BC3_ZTEX_V2_SNAPSHOT_AGE_US,
				BC3_ZTEX_V2_BURST_SLACK,
				&completed_delta, &elapsed_us);
			if (display_rate_disposition ==
			    BC3_ZTEX_DISPLAY_RATE_INVALID) {
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"typed display-rate invariant failed");
				goto next_lane;
			}
			/* Anchor a diagnostic already present in the first coherent rate
			 * snapshot.  Otherwise a frozen baseline key could be mistaken for
			 * the NEW key qualifying the first advancing display window. */
			if (display_rate_disposition ==
				    BC3_ZTEX_DISPLAY_RATE_BASELINE &&
			    status.progress_generation != 0 &&
			    !bc3_ztex_v2_verify_progress(lane,
				    &stats[lane_index], fpga, lane_index, &status,
				    true)) {
				lane->verification_failure_seen = true;
				bc3_ztex_v2_latch_failure(lanes, num_fpgas,
					&drain_requested, &drain_started_us,
					&drain_reason, &fatal_reason, status_now_us,
					"FPGA baseline progress verification failed");
				goto next_lane;
			}
			if (rate_disposition == BC3_ZTEX_RATE_BASELINE &&
			    lane->last_hash_progress_us == 0)
				lane->last_hash_progress_us = status_now_us;
			if (rate_disposition == BC3_ZTEX_RATE_SAMPLE ||
			    rate_disposition ==
				    BC3_ZTEX_RATE_REBASELINE_PROGRESS)
				lane->last_hash_progress_us = status_now_us;
			if (display_rate_disposition ==
			    BC3_ZTEX_DISPLAY_RATE_SAMPLE) {
				if (!bc3_ztex_v2_verify_progress(lane,
					    &stats[lane_index], fpga, lane_index, &status,
					    false)) {
					lane->verification_failure_seen = true;
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, status_now_us,
						"FPGA diagnostic progress verification failed");
					goto next_lane;
				} else {
					bc3_ztex_v2_record_rate(&stats[lane_index],
						(double)completed_delta * 1000000.0 /
						(double)elapsed_us);
				}
			} else if (rate_disposition == BC3_ZTEX_RATE_NO_PROGRESS &&
				   lane->last_hash_progress_us != 0 &&
				   status_now_us - lane->last_hash_progress_us >=
					   BC3_ZTEX_V2_RATE_STALE_US) {
				bc3_ztex_v2_clear_rate(&stats[lane_index]);
				if (bc3_ztex_hash_progress_timed_out(drain_requested,
					    lane->active_work_valid,
					    lane->pending_work_valid, lane->ack_pending,
					    lane->publish_blocked,
					    (status.flags & BC3_ZTEX_FLAG_FIFO_FULL) != 0,
					    lane->last_hash_progress_us, status_now_us,
					    BC3_ZTEX_V2_NO_PROGRESS_TIMEOUT_US)) {
					bc3_ztex_v2_latch_failure(lanes, num_fpgas,
						&drain_requested, &drain_started_us,
						&drain_reason, &fatal_reason, status_now_us,
						"active FPGA made no hash progress");
				}
			}
		next_lane:
			;
		}
		ztex_publish_hashrate(fpga, stats, num_fpgas, mythr->id);
		if (drain_requested) {
			uint64_t drain_now_us = ztex_rb_now_us();

			if (bc3_ztex_v2_drain_complete(lanes, stats, num_fpgas)) {
				int exit_status;

				for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
					if (lanes[lane_index].sticky_error_seen ||
					    lanes[lane_index].verification_failure_seen ||
					    lanes[lane_index].result.exhausted) {
						if (!fatal_reason)
							fatal_reason =
								"lane failure state present at drain boundary";
						break;
					}
				}
				exit_status = fatal_reason ? EXIT_FAILURE : EXIT_SUCCESS;

				applog(exit_status == EXIT_SUCCESS ? LOG_WARNING : LOG_ERR,
					"%s: typed PAUSE/drain barrier proven (%s)",
					fpga->short_name, drain_reason ? drain_reason :
					"orderly shutdown");
				for (lane_index = 0; lane_index < num_fpgas; ++lane_index)
					clear_lane_hashrate(&stats[lane_index].hashrate,
						&stats[lane_index].hashrate_smooth);
				ztex_publish_hashrate(fpga, stats, num_fpgas, mythr->id);
				bc3_ztex_v2_cleanup(lanes, num_fpgas);
				bc3_ztex_v2_request_control_stop(
					exit_status != EXIT_SUCCESS);
				if (!bc3_ztex_v2_enqueue_workio_stop())
					proper_exit(EXIT_FAILURE);
				return (void *)(intptr_t)exit_status;
			}
			if (drain_started_us == 0 ||
			    drain_now_us - drain_started_us >
				    BC3_ZTEX_V2_DRAIN_TIMEOUT_US) {
				fatal_reason = "candidate failure drain timed out";
				goto fatal;
			}
		}
		if (time(NULL) - last_heartbeat >= 30) {
			last_heartbeat = time(NULL);
			for (lane_index = 0; lane_index < num_fpgas; ++lane_index) {
				if (!stats[lane_index].enabled)
					continue;
				applog(LOG_WARNING,
					"R34 HEARTBEAT %s%d %.2f MH/s HW=%d verify=%d/%d IO=%" PRIu64
					" decode=%" PRIu64 " work=%" PRIu64 "/%" PRIu64
					" ack=%" PRIu64 "/%" PRIu64
					" pause=%" PRIu64 "/%" PRIu64,
					fpga->short_name, lane_index,
					stats[lane_index].hashrate_smooth / 1000000.0,
					stats[lane_index].hw_errors,
					stats[lane_index].hash_errors,
					stats[lane_index].hash_checks,
					stats[lane_index].v2_io_errors,
					stats[lane_index].v2_decode_errors,
					stats[lane_index].v2_work_attempts,
					stats[lane_index].v2_work_retries,
					stats[lane_index].v2_ack_attempts,
					stats[lane_index].v2_ack_retries,
					stats[lane_index].v2_pause_attempts,
					stats[lane_index].v2_pause_retries);
			}
		}
		nmsleep(BC3_ZTEX_V2_POLL_MS);
	}

fatal:
	applog(LOG_ERR,
		"%s: typed candidate termination without proven PAUSE/drain: %s; immediate rollback required",
		fpga->short_name, fatal_reason ? fatal_reason : "unknown error");
	for (lane_index = 0; lane_index < num_fpgas; ++lane_index)
		clear_lane_hashrate(&stats[lane_index].hashrate,
			&stats[lane_index].hashrate_smooth);
	ztex_publish_hashrate(fpga, stats, num_fpgas, mythr->id);
	bc3_ztex_v2_cleanup(lanes, num_fpgas);
	bc3_ztex_v2_request_control_stop(true);
	if (!bc3_ztex_v2_enqueue_workio_stop())
		proper_exit(EXIT_FAILURE);
	return (void *)(intptr_t)EXIT_FAILURE;
}


static void *ztex_miner_thread(void *userdata)
{
	if (bc3_ztex_v2_active)
		return bc3_ztex_v2_miner_thread(userdata);

	struct thr_info *mythr = userdata;
	struct fpga_info *fpga = mythr->fpga;
	struct libztex_device *ztex = fpga->ztex_info;
	struct ztex_stats *ztex_stats = fpga->ztex_stats;
	int thr_id = mythr->id;
	struct work *work;
	int i, j, rc, count = 0;
	bool display_summary = false;
	bool vg_resend_after_recovery = false;
	time_t last_hb = 0;   /* per-thread heartbeat timer (MUST NOT be static:
	                       * a static here is shared across all board threads,
	                       * so only ~one board per 30s wins the print race and
	                       * the others never report — looks like starvation). */

	uint32_t nonce, hash7, golden[2], hash[8];
	struct timeval tv_start, tv_finish, elapsed, tv_end, diff;

	uint32_t golden_nonce1, golden_nonce2;
	uint32_t last_nonce[4], last_golden1[4], last_golden2[4], hw_errors[4];
	uint32_t start_nonce[4];  // nonce value at start of work item, for delta-based rate calc
	bool overflow[4];
	uint64_t rb_work_seq = 0, rb_poll_seq[4] = { 0 };
	uint64_t rb_event_id[4] = { 0 }, rb_event_start_us[4] = { 0 };
	uint64_t rb_event_bad_polls[4] = { 0 };
	uint32_t rb_prev_work[4][20] = {{ 0 }};
	bool rb_current_valid[4] = { false }, rb_prev_valid[4] = { false };
	bool rb_clean_this_work[4] = { false }, rb_event_active[4] = { false };
	bool rb_event_match_recorded[4] = { false };
	struct sha3_nonce_zero_key nonce_zero_key[4] = { 0 };
	uint64_t rb_phase_us = ztex_rb_board_phase_us(fpga->board_idx,
		g_ztex_fpga_count);
	uint64_t rb_lane_gap_us = ztex_rb_lane_gap_us(g_ztex_fpga_count);
	uint64_t rb_next_poll_us = 0;

	unsigned char data[184], send_buf[184], midstate[32];
	unsigned char* b = (unsigned char*)send_buf;

	int num_fpgas = ztex->numberOfFpgas;

	work = (struct work *) calloc(num_fpgas, sizeof(struct work));
	if(!work) {
		applog(LOG_ERR, "calloc failed");
		return NULL;
	}
	for (i = 0; i < num_fpgas; i++) { work[i].dev_board = -1; work[i].dev_fpga = -1; }
	if (ztex_rb_enabled(ztex_rb_mode))
		applog(LOG_WARNING,
			"RBMODE v=1 board=%s serial=%s mode=%s phase_us=%" PRIu64
			" lane_gap_us=%" PRIu64,
			fpga->short_name, (const char *)ztex->snString,
			ztex_rb_mode_name(ztex_rb_mode), rb_phase_us,
			rb_lane_gap_us);

	while (1) {
		vg_resend_after_recovery = false;
		if (ztex_rb_enabled(ztex_rb_mode)) {
			uint64_t now_us = ztex_rb_now_us();
			for (i = 0; i < num_fpgas; i++) {
				if (rb_event_active[i]) {
					applog(LOG_WARNING,
						"RBEND v=1 board=%s serial=%s lane=%d work=%" PRIu64
						" event=%" PRIu64 " reason=work-boundary elapsed_ms=%" PRIu64
						" bad_polls=%" PRIu64 " clean_seen=%d",
						fpga->short_name, (const char *)ztex->snString, i,
						rb_work_seq, rb_event_id[i],
						(now_us - rb_event_start_us[i]) / 1000ULL,
						rb_event_bad_polls[i], rb_clean_this_work[i] ? 1 : 0);
					rb_event_active[i] = false;
					rb_event_match_recorded[i] = false;
				}
			}
			rb_work_seq++;
			if (ztex_rb_stagger_enabled(ztex_rb_mode)) {
				uint64_t work_slot = ztex_rb_next_slot_us(now_us, rb_phase_us);
				ztex_rb_wait_until(work_slot, NULL);
			}
		}

		// Send Data To Be Hashed To Each Chip On FPGA
		for (i=0; i<num_fpgas; i++) {
			struct work prior_work;
			uint32_t *target = work[i].target;

			// Skip Over Any Disabled FPGAs
			if(!ztex_stats[i].enabled)
				continue;

			if (have_stratum) {
				enum stratum_gen_result generated;

				while (!jsonrpc_2 && time(NULL) >= current_work_time() + 120)
					nmsleep(10);
				if (ztex_rb_enabled(ztex_rb_mode) && rb_current_valid[i]) {
					memcpy(rb_prev_work[i], work[i].data, 80);
					rb_prev_valid[i] = true;
				}
				/* Keep ownership of the last hardware-visible work until the
				 * replacement has passed the nonce-zero gate and USB publication.
				 * This lets a queue failure restore a coherent polling context. */
				work_publish_move(&work[i], &prior_work, sizeof(work[i]));
				work[i].dev_board = -1;
				work[i].dev_fpga = -1;
				generated = stratum_gen_work_result(&stratum, &work[i]);
				if (generated != STRATUM_GEN_READY) {
					work_publish_restore(&work[i], &prior_work,
						sizeof(work[i]), work_publish_release_work);
					nmsleep(100);
					continue;
				}
			}
			else {
				applog(LOG_ERR, "ERROR: Only Stratum Protocol Has Been Implemented");
				goto out;
			}

			/* Successor SHA3T RTL starts at nonce 1 because the legacy ZTEX
			 * two-golden wire protocol uses zero as its empty sentinel.  Reserve
			 * nonce 0 for the host so the complete 2^32 nonce space is still
			 * covered. The exact normalized 80-byte header and full 256-bit
			 * target key prevent duplicate submissions while forcing a recheck
			 * after a target-only change. This gate precedes hardware publication. */
			if (opt_algo == ALGO_SHA3T &&
			    !sha3_nonce_zero_key_matches(&nonce_zero_key[i],
				    work[i].data, target)) {
				uint32_t nonce_zero_hash[8];
				bool nonce_zero_qualifies = sha3_nonce_zero_check(
					work[i].data, target, nonce_zero_hash,
					calc_hash, fulltest);
				if (nonce_zero_qualifies) {
					struct work nonce_zero_work = work[i];
					bool nonce_zero_queued;
					nonce_zero_work.data[SHA3_NONCE_ZERO_NONCE_WORD] = 0;
					nonce_zero_work.dev_board = fpga->board_idx;
					nonce_zero_work.dev_fpga = i;
					nonce_zero_queued = work_publish_retry(mythr,
						&nonce_zero_work, 3, work_publish_submit_work,
						work_publish_retry_pause);
					if (!nonce_zero_queued) {
						applog(LOG_ERR,
							"%s-%d: reserved nonce 0 queue failed after 3 attempts; restoring prior hardware work",
							fpga->short_name, i);
						work_publish_restore(&work[i], &prior_work,
							sizeof(work[i]), work_publish_release_work);
						continue;
					}
					applog(LOG_WARNING,
						"%s-%d: Host Submit Reserved Nonce - 00000000 (hash7=%08X)",
						fpga->short_name, i, nonce_zero_hash[7]);
					ztex_stats[i].submitted++;
					if (fulltest(nonce_zero_hash,
							nonce_zero_work.block_target)) {
						applog(LOG_NOTICE, "%s-%d: %s***** BLOCK FOUND *****",
							fpga->short_name, i, CL_GRN);
						g_block_count++;
					}
				}
				sha3_nonce_zero_key_store(&nonce_zero_key[i],
					work[i].data, target);
			}

			if ( g_fpga_use_midstate ) {
				calc_midstate((unsigned char *)work[i].data, (unsigned char *)midstate);
				memcpy(data, midstate, 32);
				memcpy(data + 32, (unsigned char*)work[i].data + 64, 12);
			}
			else if (opt_algo == ALGO_ODO) {
					/*
					 * OdoCrypt/DigiByte: Send 76 raw LE bytes (header without nonce).
					 * FPGA generates nonce internally.
					 * Shift register puts first byte at LSB = byte 0 of header.
					 * No byte reversal or swap needed.
					 */
					/* Send 76 bytes of work.data; swap_endian applied later in send path */
					memcpy(data, (unsigned char*)work[i].data, 76);
					/* ODO DIAG: compute hash for nonce=0 to verify */
					if (count <= 1 && i == 0) {
						extern void odohash(void *output, const void *input, uint32_t odo_key);
						uint32_t diag_header[20];
						swap_endian(diag_header, (uint32_t*)work[i].data, 80);
						diag_header[19] = 0; /* nonce = 0 (LE) */
						uint32_t diag_hash[8];
						uint32_t ntime = diag_header[17]; /* correct integer after swap */
						uint32_t okey = ntime - ntime % 864000;
						odohash(diag_hash, diag_header, okey);
						applog(LOG_DEBUG, "ODO_DIAG: nonce=0 hash7=%08X key=%u ntime=%08X",
							diag_hash[7], okey, ntime);
					}
				}
				else if (opt_algo == ALGO_BLAKE3) {
				/*
				 * BLAKE3/Decred: Host precomputes blocks 0-1, sends 84 bytes:
				 *   Bytes 0-31:  CV after block 1 (from precompute)
				 *   Bytes 32-43: Block 2 m[0]-m[2] (Height, Size, Timestamp)
				 *   Bytes 44-79: Block 2 m[4]-m[12] (ExtraData + StakeVersion)
				 *   Bytes 80-83: Target (hash7 threshold)
				 *
				 * work.data[0..44] = full 180-byte header as LE uint32 words
				 * Block 0 = words 0-15, Block 1 = words 16-31
				 * Block 2 = words 32-44 (m[0]=w32, m[1]=w33, m[2]=w34, m[3]=w35=nonce,
				 *           m[4]=w36, ..., m[12]=w44)
				 */
				{
					uint32_t cv[8], block_words[16];
					unsigned char *hdr = (unsigned char *)work[i].data;
					int w;

					/* Block 0: header words 0-15 (bytes 0-63) */
					for (w = 0; w < 16; w++)
						block_words[w] = work[i].data[w];

					/* Compress block 0: CV=IV, flags=CHUNK_START */
					extern void blake3_compress_host(const uint32_t cv[8],
						const uint32_t block_words[16], uint64_t counter,
						uint32_t block_len, uint32_t flags, uint32_t out[8]);

					uint32_t iv[8] = {
						0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
						0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
					};
					uint32_t cv0[8];
					blake3_compress_host(iv, block_words, 0, 64, 1, cv0); /* CHUNK_START=1 */

					/* Block 1: header words 16-31 (bytes 64-127) */
					for (w = 0; w < 16; w++)
						block_words[w] = work[i].data[16 + w];
					blake3_compress_host(cv0, block_words, 0, 64, 0, cv); /* flags=0 */

					/* Pack 84-byte work unit */
					/* CV: 32 bytes */
					memcpy(data, (unsigned char *)cv, 32);
					/* Block2 m[0]-m[2]: words 32-34 (Height, Size, Timestamp) */
					memcpy(data + 32, (unsigned char *)&work[i].data[32], 12);
					/* Block2 m[4]-m[12]: words 36-44 (ExtraData + StakeVersion) */
					memcpy(data + 44, (unsigned char *)&work[i].data[36], 36);
					/* Target: send relaxed target (0xFF) for debugging golden flow.
				 * hash7 <= 0xFF: ~1 in 16M hashes, ~0.6/sec at 10 MH/s */
					{
						uint32_t fpga_tgt = 0x000000FF;
						memcpy(data + 80, &fpga_tgt, 4);
					}

					/* DIAGNOSTIC: verify precompute matches full hash */
					if (count <= 2) {
						uint32_t test_nonce = 0x42;
						uint32_t full_hash[8], pre_hash[8];
						uint32_t saved_nonce = work[i].data[35];
						work[i].data[35] = test_nonce;
						blake3_hash_180((void*)work[i].data, (void*)full_hash);

						/* Block 2 via precompute */
						uint32_t b2[16];
						b2[0] = work[i].data[32]; b2[1] = work[i].data[33]; b2[2] = work[i].data[34];
						b2[3] = test_nonce;
						for (w = 4; w < 13; w++) b2[w] = work[i].data[32 + w];
						b2[13] = 0; b2[14] = 0; b2[15] = 0;
						blake3_compress_host(cv, b2, 0, 52, 2|8, pre_hash);

						applog(LOG_DEBUG, "DIAG: full_hash7=%08X pre_hash7=%08X %s",
							full_hash[7], pre_hash[7],
							full_hash[7] == pre_hash[7] ? "MATCH" : "MISMATCH");
						applog(LOG_DEBUG, "DIAG: CV=%08X%08X%08X%08X%08X%08X%08X%08X",
							cv[7],cv[6],cv[5],cv[4],cv[3],cv[2],cv[1],cv[0]);
						work[i].data[35] = saved_nonce;
					}
				}
			}
			else {
				memcpy(data, (unsigned char*)work[i].data, 76);
				memcpy(data + 76, (unsigned char*)work[i].target + 28, 4);
			}

			// Prepare send buffer
			if (opt_algo == ALGO_BLAKE3) {
				// BLAKE3: send raw LE bytes, no manipulation needed.
				memcpy(send_buf, data, g_fpga_work_len);
			} else {
				// Standard (Groestl etc): swap_endian (byte-reverse each 4-byte word)
				swap_endian(send_buf, data, g_fpga_work_len);
			}

			applog(LOG_DEBUG, "%s BUF_1: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", fpga->short_name, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15],b[16],b[17],b[18],b[19],b[20],b[21],b[22],b[23],b[24],b[25],b[26],b[27],b[28],b[29],b[30],b[31],b[32],b[33],b[34],b[35],b[36],b[37],b[38],b[39]);
			applog(LOG_DEBUG, "%s BUF_2: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", fpga->short_name, b[40],b[41],b[42],b[43],b[44],b[45],b[46],b[47],b[48],b[49],b[50],b[51],b[52],b[53],b[54],b[55],b[56],b[57],b[58],b[59],b[60],b[61],b[62],b[63],b[64],b[65],b[66],b[67],b[68],b[69],b[70],b[71],b[72],b[73],b[74],b[75],b[76],b[77],b[78],b[79]);

			// Send Work To FPGA
			{	/* DIAG: save send buffer for later comparison */
				extern unsigned char g_saved_send[4][84];
				memcpy(g_saved_send[i], send_buf, g_fpga_work_len);
			}
			if (!ztex_rb_enabled(ztex_rb_mode)) {
				libztex_selectFpga(ztex, i);
				rc = libztex_sendData(ztex, send_buf, g_fpga_work_len);
				if (rc < 0) {
					applog(LOG_ERR, "%s: Failed to send hash data with err %d, retrying", fpga->short_name, rc);
					nmsleep(500);
					rc = libztex_sendData(ztex, send_buf, g_fpga_work_len);
					if (rc < 0) {
						if (ztex_stats[i].vg_reconfig_pending) {
							work_publish_commit_prior(&prior_work,
								sizeof(prior_work), work_publish_release_work);
							(void)vg_recover_reconfig(fpga, ztex, i,
								num_fpgas, thr_id,
								"work publication failed twice");
							vg_resend_after_recovery = true;
							break;
						}
						ztex_stats[i].enabled = false;
						clear_lane_hashrate(&ztex_stats[i].hashrate,
							&ztex_stats[i].hashrate_smooth);
						ztex_publish_hashrate(fpga, ztex_stats,
							num_fpgas, thr_id);
						work_publish_commit_prior(&prior_work,
							sizeof(prior_work), work_publish_release_work);
						continue;
					}
				}
			} else {
				bool selected;
				uint64_t select_start_us, select_us;
				struct libztex_send_trace send_trace;
				select_start_us = ztex_rb_now_us();
				selected = libztex_selectFpga(ztex, i);
				select_us = ztex_rb_now_us() - select_start_us;
				if (!selected)
					ztex_stats[i].rb_select_fail++;
				ztex_stats[i].rb_work_attempts++;
				rc = libztex_sendDataEx(ztex, send_buf, g_fpga_work_len,
					&send_trace);
				if (ztex_rb_send_trace_short(&send_trace))
					ztex_stats[i].rb_work_short++;
				if (rc < 0)
					ztex_stats[i].rb_work_errors++;
				ztex_rb_log_work(fpga, ztex, i, rb_work_seq, 0, selected,
					select_us, rc, g_fpga_work_len, &send_trace);
				if (rc < 0) {
					applog(LOG_ERR, "%s: Failed to send hash data with err %d, retrying", fpga->short_name, rc);
					nmsleep(500);
					ztex_stats[i].rb_work_retries++;
					ztex_stats[i].rb_work_attempts++;
					rc = libztex_sendDataEx(ztex, send_buf,
						g_fpga_work_len, &send_trace);
					if (ztex_rb_send_trace_short(&send_trace))
						ztex_stats[i].rb_work_short++;
					if (rc < 0)
						ztex_stats[i].rb_work_errors++;
					ztex_rb_log_work(fpga, ztex, i, rb_work_seq, 1,
						selected, select_us, rc, g_fpga_work_len,
						&send_trace);
				}
				if (rc < 0) {
					if (ztex_stats[i].vg_reconfig_pending) {
						work_publish_commit_prior(&prior_work,
							sizeof(prior_work), work_publish_release_work);
						(void)vg_recover_reconfig(fpga, ztex, i,
							num_fpgas, thr_id,
							"instrumented work publication failed twice");
						vg_resend_after_recovery = true;
						break;
					}
					ztex_stats[i].enabled = false;
					clear_lane_hashrate(&ztex_stats[i].hashrate,
						&ztex_stats[i].hashrate_smooth);
					ztex_publish_hashrate(fpga, ztex_stats,
						num_fpgas, thr_id);
					work_publish_commit_prior(&prior_work,
						sizeof(prior_work), work_publish_release_work);
					continue;
				}
				rb_current_valid[i] = true;
				rb_clean_this_work[i] = false;
				rb_poll_seq[i] = 0;
			}

			/* The replacement is now hardware-visible; release the prior
			 * work's dynamically owned Stratum fields only after publication. */
			work_publish_commit_prior(&prior_work, sizeof(prior_work),
				work_publish_release_work);
			vg_note_work_published(&ztex_stats[i]);
			
			overflow[i] = false;
			last_golden1[i] = 0;
			last_golden2[i] = 0;
			// Designs may start scanning at zero or one; zero remains the
			// correct pre-progress baseline for either SHA3T contract.
			// checkNonce dedup is work-local: the same numeric nonce under a new
			// header is a different hash and must be checked again.
			if (opt_algo == ALGO_SHA3T) {
				last_nonce[i] = 0;
				ztex_stats[i].last_checked_nonce = 0;
			}
			start_nonce[i] = last_nonce[i];  // snapshot current nonce as baseline for delta calc
			hw_errors[i] = 0;
		
		}
		
		if (vg_resend_after_recovery)
			continue;

		work_restart[thr_id].restart = 0;
		count = 0;
		if (ztex_rb_stagger_enabled(ztex_rb_mode))
			rb_next_poll_us = ztex_rb_next_slot_us(ztex_rb_now_us(), rb_phase_us);
		
		gettimeofday(&tv_start, NULL);

		applog(LOG_DEBUG, "%s: entering poll loop", fpga->short_name);
		while (mythr && !work_restart[thr_id].restart) {
			uint64_t rb_poll_base_us = 0;
			count++;

			if (ztex_rb_stagger_enabled(ztex_rb_mode)) {
				rb_poll_base_us = rb_next_poll_us;
				ztex_rb_wait_until(rb_poll_base_us,
					&work_restart[thr_id].restart);
			} else {
				int sleepcount = 0;
				while (work_restart[thr_id].restart == 0 && sleepcount < 25) {
					nmsleep(10);
					sleepcount += 1;
				}
			}

			// Check If New Work Is Available
			if (work_restart[thr_id].restart) {
				applog(LOG_DEBUG, "%s: New work detected", fpga->short_name);
				break;
			}
			
			for (i=0; i < num_fpgas; i++) {
				if (ztex_rb_stagger_enabled(ztex_rb_mode)) {
					ztex_rb_wait_until(rb_poll_base_us +
						(uint64_t)i * rb_lane_gap_us,
						&work_restart[thr_id].restart);
					if (work_restart[thr_id].restart)
						break;
				}

				/* A provisional fixed image is judged independently of displayed
				 * hashrate. This is deliberately inside the poll loop so a silent
				 * zero-nonce image cannot bypass the governor forever. */
				if (opt_algo == ALGO_SHA3T &&
				    !sha3_bitstream_override_active && vg_enabled &&
				    opt_auto_freq && ztex_stats[i].vg_reconfig_pending) {
					struct ztex_stats *zs = &ztex_stats[i];
					enum sha3_variant_reconfig_action guard_action;
					const char *guard_reason = "liveness deadline expired";

					if (zs->hash_checks < 0 || zs->hash_errors < 0 ||
					    zs->hash_errors > zs->hash_checks) {
						guard_action = SHA3_VARIANT_RECONFIG_ROLLBACK;
						guard_reason = "diagnostic counter invariant failed";
					} else {
						guard_action = sha3_variant_reconfig_decide(true,
							zs->vg_reconfig_started_us, ztex_rb_now_us(),
							(unsigned)zs->hash_checks,
							(unsigned)zs->hash_errors);
						if (zs->hash_errors > 0)
							guard_reason = "CPU-verified hash mismatch";
					}
					if (guard_action == SHA3_VARIANT_RECONFIG_PROVEN) {
						if (!vg_commit_reconfig(fpga, ztex, i)) {
							(void)vg_recover_reconfig(fpga, ztex, i,
								num_fpgas, thr_id,
								"commit invariant failed");
							break;
						}
					} else if (guard_action ==
						   SHA3_VARIANT_RECONFIG_ROLLBACK) {
						(void)vg_recover_reconfig(fpga, ztex, i,
							num_fpgas, thr_id, guard_reason);
						break;
					}
				}

				// Skip Any Disabled FPGA Or If All Nonces Have Been Checked
				if(!ztex_stats[i].enabled || overflow[i])
					continue;
			
				int read_recovered = 0;
				if (!ztex_rb_enabled(ztex_rb_mode)) {
				/* Retained default read/retry path. rc==-99 means that the
				 * 16-byte frame was incomplete. Re-select remains part of the
				 * historical policy, although every fresh firmware request 0x81
				 * also pulses wr_start and restarts the FPGA read snapshot. Never
				 * stitch fragments: a second request is a new snapshot. */
				libztex_selectFpga(ztex, i);
				rc = libztex_readData(ztex, &nonce, &hash7, golden);
				{
					int rr;
					for (rr = 0; rr < 4 && rc == -99; rr++) {
						ztex_stats[i].readback_resync++;
						read_recovered = 1;
						nmsleep(2);
						libztex_selectFpga(ztex, i);
						rc = libztex_readData(ztex, &nonce, &hash7, golden);
					}
				}
				/* -99 exhausted: skip this poll, NEVER disable the FPGA for
				 * bus weather. The next poll retries, but the FPGA retains only
				 * its newest two golden nonces, so recovery is not guaranteed. */
				if (rc == -99) {
					if ((ztex_stats[i].readback_resync % 200) == 0)
						applog(LOG_INFO, "%s-%d: short-read storm (RS=%d), polls skipped",
							fpga->short_name, i, ztex_stats[i].readback_resync);
					continue;
				}

				/* Shared-bus readback DESYNC fix (now a rare backstop): a read can silently return
				 * all-zeros while the FPGA is provably hashing (nonce was
				 * already deep into the range). golden==0 is skipped silently
				 * by the dedup logic below, so every desynced poll throws away
				 * latched shares -- this was worth a 3-4x pool hashrate loss.
				 * Detect nonce==0 after real progress and retain the historical
				 * re-select/re-read mitigation. A clean read recovers only hits
				 * still present in the FPGA's latest-two golden slots. */
				if (rc >= 0 && nonce == 0 && golden[0] == 0 && last_nonce[i] > 2000000) {
					int rs;
					for (rs = 0; rs < 3 && nonce == 0 && golden[0] == 0; rs++) {
						ztex_stats[i].readback_resync++;
						nmsleep(2);
						libztex_selectFpga(ztex, i);
						rc = libztex_readData(ztex, &nonce, &hash7, golden);
						if (rc < 0) break;
					}
				}
				/* Garbage-read guard (desync can also return junk, not just
				 * zeros): the max legitimate nonce advance between polls is
				 * ~5M (250ms @ 12MH/s) plus first-poll slack, so a jump of
				 * >60M is bus corruption. Resync and re-read; if it persists,
				 * skip this poll entirely so junk never poisons last_nonce
				 * (hashrate spikes) or the golden dedup. */
				if (rc >= 0 && opt_algo == ALGO_SHA3T &&
				    nonce > last_nonce[i] && (nonce - last_nonce[i]) > 60000000) {
					int rs;
					for (rs = 0; rs < 3; rs++) {
						ztex_stats[i].readback_resync++;
						nmsleep(2);
						libztex_selectFpga(ztex, i);
						rc = libztex_readData(ztex, &nonce, &hash7, golden);
						if (rc < 0) break;
						if (nonce <= last_nonce[i] ||
						    (nonce - last_nonce[i]) <= 60000000) break;
					}
					if (rc >= 0 && nonce > last_nonce[i] &&
					    (nonce - last_nonce[i]) > 60000000)
						continue;   /* still junk: drop this poll, keep FPGA enabled */
				}

				/* short reads (-99) from ANY path incl. the backstop retry
				 * loops: bus weather, never a device failure. Skip the poll;
				 * later hits can overwrite the two retained golden slots. */
				if (rc == -99)
					continue;
				if (rc < 0) {
					applog(LOG_ERR, "ERROR: Failed To Read Data From %s-%d (rc=%d), retrying...", fpga->short_name, i, rc);
					nmsleep(500);
					rc = libztex_readData(ztex, &nonce, &hash7, golden);
					if (rc < 0) {
						if (ztex_stats[i].vg_reconfig_pending) {
							(void)vg_recover_reconfig(fpga, ztex, i,
								num_fpgas, thr_id,
								"readback failed twice");
							break;
						}
						ztex_stats[i].enabled = false;
						clear_lane_hashrate(&ztex_stats[i].hashrate,
							&ztex_stats[i].hashrate_smooth);
						ztex_publish_hashrate(fpga, ztex_stats,
							num_fpgas, thr_id);
						continue;
					}
				}
				} else {
					unsigned char rb_raw[16] = { 0 };
					uint64_t rb_duration_us = 0;
					uint64_t rb_select_start_us, rb_select_us;
					uint32_t rb_current_hash7 = 0, rb_previous_hash7 = 0;
					enum ztex_rb_work_match rb_match = ZTEX_RB_MATCH_NA;
					enum ztex_rb_cause rb_cause = ZTEX_RB_CLEAN;
					bool rb_selected, rb_log_this_poll = false;
					bool rb_bad_poll = false;
					unsigned rb_retries_this_poll = 0;
					int rb_try;

					nonce = hash7 = 0;
					golden[0] = golden[1] = 0;
					rb_poll_seq[i]++;
					ztex_stats[i].rb_polls++;
					rb_select_start_us = ztex_rb_now_us();
					rb_selected = libztex_selectFpga(ztex, i);
					rb_select_us = ztex_rb_now_us() - rb_select_start_us;
					if (!rb_selected) {
						ztex_rb_count_cause(&ztex_stats[i], ZTEX_RB_SELECT);
						rb_bad_poll = true;
						if (!rb_event_active[i]) {
							rb_event_active[i] = true;
							rb_event_match_recorded[i] = false;
							rb_event_id[i]++;
							rb_event_start_us[i] = ztex_rb_now_us();
							rb_event_bad_polls[i] = 0;
							ztex_stats[i].rb_episodes++;
							if (rb_clean_this_work[i])
								ztex_stats[i].rb_postclean_bad++;
							else
								ztex_stats[i].rb_preclean_bad++;
							rb_log_this_poll = true;
						}
						if (rb_log_this_poll)
							ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
								rb_poll_seq[i], rb_event_id[i], 0,
								ZTEX_RB_SELECT, false, 0, rb_select_us, 0, 0, 0,
								golden, last_nonce[i], rb_clean_this_work[i],
								ZTEX_RB_MATCH_NA, 0, 0, rb_raw);
					}

					if (ztex_rb_retry_enabled(ztex_rb_mode) && !rb_selected) {
						for (rb_try = 0; rb_try < 2 && !rb_selected; rb_try++) {
							ztex_stats[i].rb_retry_attempts++;
							rb_retries_this_poll++;
							nmsleep(rb_try == 0 ? 1 : 4);
							rb_select_start_us = ztex_rb_now_us();
							rb_selected = libztex_selectFpga(ztex, i);
							rb_select_us = ztex_rb_now_us() - rb_select_start_us;
							if (!rb_selected) {
								ztex_rb_count_cause(&ztex_stats[i], ZTEX_RB_SELECT);
								if (rb_log_this_poll)
								ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
									rb_poll_seq[i], rb_event_id[i],
									(unsigned)rb_try + 1, ZTEX_RB_SELECT,
									false, 0, rb_select_us, 0, 0, 0, golden,
										last_nonce[i], rb_clean_this_work[i],
										ZTEX_RB_MATCH_NA, 0, 0, rb_raw);
							}
						}
						if (!rb_selected) {
							rb_event_bad_polls[i]++;
							ztex_stats[i].rb_dropped++;
							continue;
						}
					}
					if (ztex_rb_retry_enabled(ztex_rb_mode) && rb_selected)
						usleep(250);

					rb_cause = ztex_rb_read_once(ztex, &ztex_stats[i],
						last_nonce[i], &rc, &nonce, &hash7, golden,
						rb_raw, &rb_duration_us);
					if (rb_cause != ZTEX_RB_CLEAN && rb_cause != ZTEX_RB_NOISE) {
						rb_bad_poll = true;
						if (!rb_event_active[i]) {
							rb_event_active[i] = true;
							rb_event_match_recorded[i] = false;
							rb_event_id[i]++;
							rb_event_start_us[i] = ztex_rb_now_us();
							rb_event_bad_polls[i] = 0;
							ztex_stats[i].rb_episodes++;
							if (rb_clean_this_work[i])
								ztex_stats[i].rb_postclean_bad++;
							else
								ztex_stats[i].rb_preclean_bad++;
							rb_log_this_poll = true;
						}
						if (rb_cause == ZTEX_RB_JUMP && !rb_event_match_recorded[i]) {
							rb_match = ztex_rb_compare_work_hash7(work[i].data,
								rb_prev_work[i], rb_prev_valid[i], nonce, hash7,
								&rb_current_hash7, &rb_previous_hash7);
							ztex_rb_count_match(&ztex_stats[i], rb_match);
							rb_event_match_recorded[i] = true;
						}
						if (rb_log_this_poll)
						ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
							rb_poll_seq[i], rb_event_id[i], 0, rb_cause,
							rb_selected, rc, rb_select_us, rb_duration_us,
							nonce, hash7,
								golden, last_nonce[i], rb_clean_this_work[i],
								rb_match, rb_current_hash7, rb_previous_hash7,
								rb_raw);
					} else if (rb_cause == ZTEX_RB_NOISE && rb_event_active[i]) {
						rb_bad_poll = true;
					}

					if (rb_cause == ZTEX_RB_SHORT) {
						read_recovered = 1;
						for (rb_try = 0; rb_try < 4 && rb_cause == ZTEX_RB_SHORT; rb_try++) {
							ztex_stats[i].readback_resync++;
							ztex_stats[i].rb_retry_attempts++;
							rb_retries_this_poll++;
							nmsleep(ztex_rb_retry_enabled(ztex_rb_mode) ?
								ztex_rb_retry_delay_ms(ZTEX_RB_SHORT, rb_try) : 2);
							if (!ztex_rb_retry_enabled(ztex_rb_mode)) {
								rb_select_start_us = ztex_rb_now_us();
								rb_selected = libztex_selectFpga(ztex, i);
								rb_select_us = ztex_rb_now_us() - rb_select_start_us;
								if (!rb_selected)
									ztex_rb_count_cause(&ztex_stats[i], ZTEX_RB_SELECT);
							}
							rb_cause = ztex_rb_read_once(ztex, &ztex_stats[i],
								last_nonce[i], &rc, &nonce, &hash7, golden,
								rb_raw, &rb_duration_us);
							if (rb_cause == ZTEX_RB_JUMP) {
								rb_match = ztex_rb_compare_work_hash7(work[i].data,
									rb_prev_work[i], rb_prev_valid[i], nonce, hash7,
									&rb_current_hash7, &rb_previous_hash7);
								if (!rb_event_match_recorded[i]) {
									ztex_rb_count_match(&ztex_stats[i], rb_match);
									rb_event_match_recorded[i] = true;
								}
							}
							if (rb_log_this_poll)
								ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
									rb_poll_seq[i], rb_event_id[i],
									(unsigned)rb_try + 1, rb_cause,
									rb_selected, rc, rb_select_us, rb_duration_us,
									nonce, hash7,
									golden, last_nonce[i], rb_clean_this_work[i],
									rb_match, rb_current_hash7,
									rb_previous_hash7, rb_raw);
						}
					}
					if (rb_cause == ZTEX_RB_SHORT) {
						if ((ztex_stats[i].readback_resync % 200) == 0)
							applog(LOG_INFO, "%s-%d: short-read storm (RS=%d), polls skipped",
								fpga->short_name, i, ztex_stats[i].readback_resync);
						rb_event_bad_polls[i]++;
						ztex_stats[i].rb_dropped++;
						continue;
					}

					if (rb_cause == ZTEX_RB_ZERO) {
						for (rb_try = 0; rb_try < 3 && rb_cause == ZTEX_RB_ZERO; rb_try++) {
							ztex_stats[i].readback_resync++;
							ztex_stats[i].rb_retry_attempts++;
							rb_retries_this_poll++;
							nmsleep(ztex_rb_retry_enabled(ztex_rb_mode) ?
								ztex_rb_retry_delay_ms(ZTEX_RB_ZERO, rb_try) : 2);
							if (!ztex_rb_retry_enabled(ztex_rb_mode)) {
								rb_select_start_us = ztex_rb_now_us();
								rb_selected = libztex_selectFpga(ztex, i);
								rb_select_us = ztex_rb_now_us() - rb_select_start_us;
								if (!rb_selected)
									ztex_rb_count_cause(&ztex_stats[i], ZTEX_RB_SELECT);
							}
							rb_cause = ztex_rb_read_once(ztex, &ztex_stats[i],
								last_nonce[i], &rc, &nonce, &hash7, golden,
								rb_raw, &rb_duration_us);
							if (rb_log_this_poll)
								ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
									rb_poll_seq[i], rb_event_id[i],
									(unsigned)rb_try + 1, rb_cause,
									rb_selected, rc, rb_select_us, rb_duration_us,
									nonce, hash7,
									golden, last_nonce[i], rb_clean_this_work[i],
									ZTEX_RB_MATCH_NA, 0, 0, rb_raw);
							if (rc < 0)
								break;
						}
					}

					if (rb_cause == ZTEX_RB_JUMP) {
						for (rb_try = 0; rb_try < 3 && rb_cause == ZTEX_RB_JUMP; rb_try++) {
							ztex_stats[i].readback_resync++;
							ztex_stats[i].rb_retry_attempts++;
							rb_retries_this_poll++;
							nmsleep(ztex_rb_retry_enabled(ztex_rb_mode) ?
								ztex_rb_retry_delay_ms(ZTEX_RB_JUMP, rb_try) : 2);
							if (!ztex_rb_retry_enabled(ztex_rb_mode)) {
								rb_select_start_us = ztex_rb_now_us();
								rb_selected = libztex_selectFpga(ztex, i);
								rb_select_us = ztex_rb_now_us() - rb_select_start_us;
								if (!rb_selected)
									ztex_rb_count_cause(&ztex_stats[i], ZTEX_RB_SELECT);
							}
							rb_cause = ztex_rb_read_once(ztex, &ztex_stats[i],
								last_nonce[i], &rc, &nonce, &hash7, golden,
								rb_raw, &rb_duration_us);
							rb_match = ZTEX_RB_MATCH_NA;
							rb_current_hash7 = rb_previous_hash7 = 0;
							if (rb_cause == ZTEX_RB_JUMP) {
								rb_match = ztex_rb_compare_work_hash7(work[i].data,
									rb_prev_work[i], rb_prev_valid[i], nonce, hash7,
									&rb_current_hash7, &rb_previous_hash7);
								if (!rb_event_match_recorded[i]) {
									ztex_rb_count_match(&ztex_stats[i], rb_match);
									rb_event_match_recorded[i] = true;
								}
							}
							if (rb_log_this_poll)
								ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
									rb_poll_seq[i], rb_event_id[i],
									(unsigned)rb_try + 1, rb_cause,
									rb_selected, rc, rb_select_us, rb_duration_us,
									nonce, hash7,
									golden, last_nonce[i], rb_clean_this_work[i],
									rb_match, rb_current_hash7,
									rb_previous_hash7, rb_raw);
							if (rc < 0)
								break;
						}
						if (rb_cause == ZTEX_RB_JUMP) {
							rb_event_bad_polls[i]++;
							ztex_stats[i].rb_dropped++;
							continue;
						}
					}

					if (rb_cause == ZTEX_RB_SHORT) {
						rb_event_bad_polls[i]++;
						ztex_stats[i].rb_dropped++;
						continue;
					}
					if (rc < 0) {
						applog(LOG_ERR, "ERROR: Failed To Read Data From %s-%d (rc=%d), retrying...", fpga->short_name, i, rc);
						nmsleep(500);
						ztex_stats[i].rb_retry_attempts++;
						rb_retries_this_poll++;
						rb_cause = ztex_rb_read_once(ztex, &ztex_stats[i],
							last_nonce[i], &rc, &nonce, &hash7, golden,
							rb_raw, &rb_duration_us);
						if (rb_log_this_poll)
							ztex_rb_log_frame(fpga, ztex, i, rb_work_seq,
								rb_poll_seq[i], rb_event_id[i],
								rb_retries_this_poll, rb_cause,
								rb_selected, rc, rb_select_us, rb_duration_us,
								nonce, hash7,
								golden, last_nonce[i], rb_clean_this_work[i],
								ZTEX_RB_MATCH_NA, 0, 0, rb_raw);
						if (rc < 0) {
							if (ztex_stats[i].vg_reconfig_pending) {
								(void)vg_recover_reconfig(fpga, ztex, i,
									num_fpgas, thr_id,
									"instrumented readback failed twice");
								break;
							}
							ztex_stats[i].enabled = false;
							clear_lane_hashrate(&ztex_stats[i].hashrate,
								&ztex_stats[i].hashrate_smooth);
							ztex_publish_hashrate(fpga, ztex_stats,
								num_fpgas, thr_id);
							rb_event_bad_polls[i]++;
							ztex_stats[i].rb_dropped++;
							continue;
						}
					}

					if (rb_bad_poll)
						rb_event_bad_polls[i]++;
					if (rb_cause == ZTEX_RB_CLEAN) {
						rb_clean_this_work[i] = true;
						if (rb_event_active[i]) {
							applog(LOG_WARNING,
								"RBRECOVER v=1 board=%s serial=%s lane=%d work=%" PRIu64
								" poll=%" PRIu64 " event=%" PRIu64
								" elapsed_ms=%" PRIu64 " bad_polls=%" PRIu64
								" retries=%u nonce=%08X hash7=%08X",
								fpga->short_name, (const char *)ztex->snString, i,
								rb_work_seq, rb_poll_seq[i], rb_event_id[i],
								(ztex_rb_now_us() - rb_event_start_us[i]) / 1000ULL,
								rb_event_bad_polls[i], rb_retries_this_poll,
								nonce, hash7);
							ztex_stats[i].rb_retry_recovered++;
							rb_event_active[i] = false;
							rb_event_match_recorded[i] = false;
						}
					}
				}

				// Debug: log raw readback data
				if (count <= 5)
					applog(LOG_DEBUG, "%s%d: readback nonce=%08X hash7=%08X golden1=%08X golden2=%08X", fpga->short_name, i, nonce, hash7, golden[0], golden[1]);

				// Get Rid of FPGA Noise
				if ((nonce == 0x00000000) || (nonce == hash7)) {
					if (ztex_rb_enabled(ztex_rb_mode))
						ztex_stats[i].rb_dropped++;
					continue;
				}

				// The disabled legacy check below is retained for non-SHA3T
				// algorithms whose diagnostic pair was not proven atomic. SHA3T's
				// ztex_comm_80 readback exports one coherent registered pair and is
				// CPU-verified in the algorithm-specific block below.

				// ODO VERIFY: compare host hash with FPGA hash for readback nonce
				if (opt_algo == ALGO_ODO && count == 3 && i == 0) {
					extern void odohash(void *output, const void *input, uint32_t odo_key);
					uint32_t endian_data[20], vhash[8];
					swap_endian(endian_data, (uint32_t*)work[i].data, 80);
					uint32_t vtime = swab32(work[i].data[17]);
					uint32_t vkey = vtime - vtime % 864000;
					/* Use LE nonce (FPGA nonce is LE uint32) */
					endian_data[19] = nonce;
					odohash(vhash, endian_data, vkey);
					applog(LOG_DEBUG, "ODO_VERIFY: nonce=%08X fpga_h7=%08X host_h7=%08X %s",
						nonce, hash7, vhash[7],
						vhash[7] == hash7 ? "*** MATCH ***" : "MISMATCH");
				}

				// HOST-SIDE SHARE CHECK: check readback nonce against pool target
				if ((opt_algo == ALGO_BLAKE3 || opt_algo == ALGO_ODO) && count > 2) {
					work[i].data[g_nonce_word_index] = nonce;
					uint32_t check_hash[8];
					calc_hash((unsigned char *)work[i].data, (unsigned char *)check_hash);
					/* Debug: show hash for diff 0.01 check */
					if (opt_algo == ALGO_ODO && count == 4 && i == 0) {
						uint32_t *tgt = (uint32_t*)work[i].target;
						applog(LOG_DEBUG, "ODO_CHECK: nonce=%08X hash7=%08X target7=%08X %s",
							nonce, check_hash[7], tgt[7],
							fulltest(check_hash, work[i].target) ? "PASS" : "FAIL");
					}
					if (fulltest(check_hash, work[i].target)) {
						work[i].dev_board = fpga->board_idx;  /* for per-FPGA A/R attribution */
						work[i].dev_fpga = i;
						if (work_publish_retry(mythr, &work[i], 3,
								work_publish_submit_work,
								work_publish_retry_pause)) {
							applog(LOG_WARNING, "%s-%d: HOST FOUND SHARE! Nonce=%08X hash7=%08X",
								fpga->short_name, i, nonce, check_hash[7]);
							ztex_stats[i].submitted++;
						} else {
							applog(LOG_ERR, "%s-%d: host-found share queue failed after 3 attempts",
								fpga->short_name, i);
						}
					}
				}

				work[i].data[g_nonce_word_index] = nonce;
				/* DATA CONSISTENCY CHECK: recompute hash from saved send buffer */
				if (count == 3 && i == 0 && opt_algo == ALGO_BLAKE3) {
					extern void blake3_compress_host(const uint32_t cv[8],
						const uint32_t block_words[16], uint64_t counter,
						uint32_t block_len, uint32_t flags, uint32_t out[8]);
					extern unsigned char g_saved_send[4][84];
					/* Recompute from saved send_buf (what FPGA actually received) */
					uint32_t *sb32 = (uint32_t*)g_saved_send[i];
					uint32_t scv[8], sb2[16] = {0}, sout[8];
					for (int w=0; w<8; w++) scv[w] = sb32[w]; /* CV from send buf */
					for (int w=0; w<3; w++) sb2[w] = sb32[8+w]; /* b2_low */
					sb2[3] = nonce; /* nonce from FPGA */
					for (int w=0; w<9; w++) sb2[4+w] = sb32[11+w]; /* b2_high */
					blake3_compress_host(scv, sb2, 0, 52, 2|8, sout);
					/* Also compute from work.data for comparison */
					uint32_t *wd = (uint32_t*)work[i].data;
					uint32_t vhash[8];
					blake3_hash_180((void*)wd, (void*)vhash);
					applog(LOG_DEBUG, "VERIFY: send_cv0=%08X work_hash7=%08X sendbuf_hash7=%08X fpga=%08X nonce=%08X",
						scv[0], vhash[7], sout[7], hash7, nonce);
					if (sout[7] == hash7)
						applog(LOG_DEBUG, "VERIFY: *** SENDBUF HASH MATCHES FPGA! ***");
				}
				if (0 && ztex_checkNonce((unsigned char*)work[i].data) != hash7) {
					if (count > 2) {
						hw_errors[i]++;
						ztex_stats[i].hw_errors++;
						applog(LOG_DEBUG, "%s%d: Check Nonce Failed - Nonce: %08X, Hash: %08X, Expected: %08X", fpga->short_name, i, nonce, ztex_checkNonce((unsigned char*)work[i].data), hash7);
					}
					/* BYTE ORDER DIAGNOSTIC: try different interpretations */
					if (count == 3 && i == 0 && opt_algo == ALGO_BLAKE3) {
						extern void blake3_compress_host(const uint32_t cv[8],
							const uint32_t block_words[16], uint64_t counter,
							uint32_t block_len, uint32_t flags, uint32_t out[8]);
						/* Print the send_buf bytes */
						unsigned char *b = send_buf;
						applog(LOG_DEBUG, "SENDBUF[0..15]: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
							b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
						applog(LOG_DEBUG, "SENDBUF[16..31]: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
							b[16],b[17],b[18],b[19],b[20],b[21],b[22],b[23],b[24],b[25],b[26],b[27],b[28],b[29],b[30],b[31]);
						/* Try: FPGA sees words as swab32 of what we sent */
						uint32_t *sw = (uint32_t*)send_buf;
						uint32_t tcv[8], tb2[16], th[8];
						/* Interpretation A: FPGA words = send words (no swap) */
						for (int w=0;w<8;w++) tcv[w]=sw[w];
						tb2[0]=sw[8]; tb2[1]=sw[9]; tb2[2]=sw[10]; tb2[3]=nonce;
						for (int w=4;w<13;w++) tb2[w]=sw[w+7];
						tb2[13]=tb2[14]=tb2[15]=0;
						blake3_compress_host(tcv,tb2,0,52,2|8,th);
						applog(LOG_DEBUG, "InterpA(raw): hash7=%08X fpga=%08X %s", th[7], hash7, th[7]==hash7?"MATCH":"");
						/* Interpretation B: FPGA words = swab32 of send words */
						for (int w=0;w<8;w++) tcv[w]=swab32(sw[w]);
						tb2[0]=swab32(sw[8]); tb2[1]=swab32(sw[9]); tb2[2]=swab32(sw[10]); tb2[3]=nonce;
						for (int w=4;w<13;w++) tb2[w]=swab32(sw[w+7]);
						tb2[13]=tb2[14]=tb2[15]=0;
						blake3_compress_host(tcv,tb2,0,52,2|8,th);
						applog(LOG_DEBUG, "InterpB(swab): hash7=%08X fpga=%08X %s", th[7], hash7, th[7]==hash7?"MATCH":"");
						/* Interpretation C: FPGA sees reversed word order */
						for (int w=0;w<8;w++) tcv[w]=sw[20-w];
						tb2[0]=sw[12]; tb2[1]=sw[11]; tb2[2]=sw[10]; tb2[3]=nonce;
						for (int w=4;w<13;w++) tb2[w]=sw[16-w];
						tb2[13]=tb2[14]=tb2[15]=0;
						blake3_compress_host(tcv,tb2,0,52,2|8,th);
						applog(LOG_DEBUG, "InterpC(rev_word): hash7=%08X fpga=%08X %s", th[7], hash7, th[7]==hash7?"MATCH":"");
						/* Interpretation D: reversed word order + swab32 */
						for (int w=0;w<8;w++) tcv[w]=swab32(sw[20-w]);
						tb2[0]=swab32(sw[12]); tb2[1]=swab32(sw[11]); tb2[2]=swab32(sw[10]); tb2[3]=nonce;
						for (int w=4;w<13;w++) tb2[w]=swab32(sw[16-w]);
						tb2[13]=tb2[14]=tb2[15]=0;
						blake3_compress_host(tcv,tb2,0,52,2|8,th);
						applog(LOG_DEBUG, "InterpD(rev+swab): hash7=%08X fpga=%08X %s", th[7], hash7, th[7]==hash7?"MATCH":"");
						/* Also try swapped nonce */
						tb2[3]=swab32(nonce);
						for (int w=0;w<8;w++) tcv[w]=sw[w];
						tb2[0]=sw[8]; tb2[1]=sw[9]; tb2[2]=sw[10];
						for (int w=4;w<13;w++) tb2[w]=sw[w+7];
						tb2[13]=tb2[14]=tb2[15]=0;
						blake3_compress_host(tcv,tb2,0,52,2|8,th);
						applog(LOG_DEBUG, "InterpE(raw+swab_nonce): hash7=%08X fpga=%08X %s", th[7], hash7, th[7]==hash7?"MATCH":"");
					}
					continue;
				}

				// SHA3T cores scan autonomously and reset on every new work. Newer
				// bitstreams also round-robin the diagnostic pair across cores, so
				// successive samples may move slightly backward within the common
				// nonce frontier. The generic monotonic overflow check would then
				// disable a healthy FPGA. Track the running maximum for progress;
				// because all lanes cover a contiguous nonce range, it remains an
				// aggregate-rate marker with only bounded frontier-width jitter.
				if (opt_algo == ALGO_SHA3T) {
					if (nonce > last_nonce[i])
						last_nonce[i] = nonce;

					/* checkNonce (ported from the proven cgminer ztex driver):
					 * the FPGA latches one coherent (nonce, hash7) diagnostic
					 * pair. Production bitstreams expose core 0; rotating-context
					 * candidates round-robin the same pair across physical cores.
					 * The host hash is valid for either protocol, so do not infer
					 * a core from nonce residue or require this sample to equal the
					 * running-max progress marker. Recompute every new clean pair;
					 * a mismatch is a real hash/readback error and feeds the clock
					 * governor. Skip only the first polls (stale-work race), retry-
					 * recovered reads, tiny startup nonces, and exact duplicates. */
					if (!read_recovered && count >= 3 && nonce > 1000 &&
					    nonce != ztex_stats[i].last_checked_nonce) {
						uint32_t chk_hash[8];
						uint32_t saved = work[i].data[g_nonce_word_index];
						work[i].data[g_nonce_word_index] = nonce;
						calc_hash((unsigned char *)work[i].data, (unsigned char *)chk_hash);
						work[i].data[g_nonce_word_index] = saved;
						ztex_stats[i].hash_checks++;
						if (chk_hash[7] != hash7)
							ztex_stats[i].hash_errors++;
						ztex_stats[i].last_checked_nonce = nonce;
						/* governor ledger (cgminer semantics): decayed
						 * error count/weight per frequency step M */
						{
							int m = ztex_stats[i].gov_m;
							ztex_stats[i].gov_errorCount[m] *= 0.995;
							ztex_stats[i].gov_errorWeight[m] = ztex_stats[i].gov_errorWeight[m] * 0.995 + 1.0;
							if (chk_hash[7] != hash7)
								ztex_stats[i].gov_errorCount[m] += 1.0;
							ztex_stats[i].gov_errorRate[m] = ztex_stats[i].gov_errorCount[m] / ztex_stats[i].gov_errorWeight[m]
								* (ztex_stats[i].gov_errorWeight[m] < 100 ? ztex_stats[i].gov_errorWeight[m] * 0.01 : 1.0);
							if (ztex_stats[i].gov_errorRate[m] > ztex_stats[i].gov_maxErrorRate[m])
								ztex_stats[i].gov_maxErrorRate[m] = ztex_stats[i].gov_errorRate[m];
						}
					}
				}
				// Check If FPGA Has Processed All Nonces For The Work
				else if ( nonce < last_nonce[i] ) {
					applog(LOG_DEBUG, "%s%d: Overflow - Nonce=%08X, Last=%08X", fpga->short_name, i, nonce, last_nonce[i]);
					overflow[i] = true;
					continue;
				}
				else
					last_nonce[i] = nonce;

				// Check If Golden Nonce Found
				/* SHA3T readback is newest-first: golden[0] is the latest hit
				 * and golden[1] is the preceding hit.  Consume its older slot
				 * first.  Otherwise accepting slot 0 rotates last_golden1 into
				 * last_golden2 before slot 1 is tested, can evict the only record
				 * of slot 1, and resubmits that previous hit.  Preserve the
				 * historical slot order for the other ZTEX protocols. */
				for (j = 0; j < 2; j++) {
					struct ztex_golden_checkpoint golden_checkpoint =
						ztex_golden_checkpoint_capture(last_golden1[i],
							last_golden2[i]);
					uint32_t candidate = ztex_golden_consume(
						opt_algo == ALGO_SHA3T, (unsigned)j, golden,
						&last_golden1[i], &last_golden2[i]);
					
					if (candidate != 0) {
						work[i].data[g_nonce_word_index] = candidate;
						calc_hash((unsigned char *)work[i].data, (unsigned char *)hash);
					
						// Log golden nonce hash for debugging
						if (opt_algo == ALGO_ODO) {
							extern unsigned char g_saved_send[4][84];
							unsigned char *sb = g_saved_send[i];
							/* Check if verify data matches what was sent */
							unsigned char verify_buf[76];
							swap_endian((uint32_t*)verify_buf, (uint32_t*)work[i].data, 76);
							int mismatch = memcmp(sb, verify_buf, 76);
							applog(LOG_DEBUG, "GOLDEN: nonce=%08X hash7=%08X target7=%08X %s fpga=%d DATA_%s",
									candidate, hash[7], work[i].target[7],
								fulltest(hash, work[i].target) ? "PASS" : "FAIL", i,
								mismatch ? "STALE!" : "OK");
							applog(LOG_DEBUG, "  SEND[0-39]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
								sb[0],sb[1],sb[2],sb[3],sb[4],sb[5],sb[6],sb[7],sb[8],sb[9],
								sb[10],sb[11],sb[12],sb[13],sb[14],sb[15],sb[16],sb[17],sb[18],sb[19],
								sb[20],sb[21],sb[22],sb[23],sb[24],sb[25],sb[26],sb[27],sb[28],sb[29],
								sb[30],sb[31],sb[32],sb[33],sb[34],sb[35],sb[36],sb[37],sb[38],sb[39]);
							applog(LOG_DEBUG, "  SEND[40-75]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
								sb[40],sb[41],sb[42],sb[43],sb[44],sb[45],sb[46],sb[47],sb[48],sb[49],
								sb[50],sb[51],sb[52],sb[53],sb[54],sb[55],sb[56],sb[57],sb[58],sb[59],
								sb[60],sb[61],sb[62],sb[63],sb[64],sb[65],sb[66],sb[67],sb[68],sb[69],
								sb[70],sb[71],sb[72],sb[73],sb[74],sb[75]);
						} else if (opt_algo == ALGO_BLAKE3 && opt_debug && ztex_stats[i].submitted < 3) {
							applog(LOG_DEBUG, "GOLDEN: nonce=%08X hash7=%08X hash6=%08X target7=%08X target6=%08X",
									candidate, hash[7], hash[6],
									work[i].target[7], work[i].target[6]);
						}
						// Check If Hash < Target Sent To FPGA
							if (opt_algo != ALGO_BLAKE3 && opt_algo != ALGO_ODO && opt_algo != ALGO_SHA3T && swab32(hash[7]) > swab32(work[i].target[7])) {
							fpga->hw_errors++;
								applog(LOG_INFO, "%s-%d: HW Error (Nonce: %08x, Hash: %08X, Target: %08X)", fpga->short_name, i, candidate, swab32(hash[7]), swab32(work[i].target[7]));
							continue;
						}
					
						// Check If Hash < Work Target
						if(fulltest(hash, work[i].target)) {
							work[i].dev_board = fpga->board_idx;  /* for per-FPGA A/R attribution */
							work[i].dev_fpga = i;
							if (!work_publish_retry(mythr, &work[i], 3,
									work_publish_submit_work,
									work_publish_retry_pause)) {
								ztex_golden_checkpoint_restore(
									&golden_checkpoint, &last_golden1[i],
									&last_golden2[i]);
								applog(LOG_ERR,
									"%s-%d: share queue failed after 3 attempts; dedup state restored",
									fpga->short_name, i);
								break;
							}
							applog(LOG_WARNING, "%s-%d: Submit Nonce - %08X (hash7=%08X)", fpga->short_name, i, candidate, hash[7]);
							ztex_stats[i].submitted++;
							if(fulltest(hash, work[i].block_target)) {
								applog(LOG_NOTICE, "%s-%d: %s***** BLOCK FOUND *****", fpga->short_name, i, CL_GRN);
								g_block_count++;
							}
						} else {
							// hash7 met the FPGA threshold but full 256-bit target
							// not met: legitimate near-miss, NOT an error.
							applog(LOG_DEBUG, "%s-%d: Share Above Target - %08X (%1.1f MH/s)", fpga->short_name, i, candidate, ztex_stats[i].hashrate/1000000.0);
						}
					}
					}
				}
				if (ztex_rb_stagger_enabled(ztex_rb_mode)) {
					uint64_t now_us = ztex_rb_now_us();
					do {
						rb_next_poll_us += ZTEX_RB_PERIOD_US;
					} while (rb_next_poll_us <= now_us);
				}

				// Calculate Elapsed Time
			gettimeofday(&tv_end, NULL);
			timeval_subtract(&elapsed, &tv_end, &tv_start);

			// Calculate Hashrates using delta from work-item start
			// (FPGA nonce counter may not reset on new block, so we compute
			// the growth since work-start rather than using the absolute value)
			{
				double elapsed_secs = (double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000);
				if (elapsed_secs >= 2.0) {
					for (i=0; i < num_fpgas; i++) {
						if (!ztex_stats[i].enabled) {
							(void)active_lane_hashrate(0,
								&ztex_stats[i].hashrate,
								&ztex_stats[i].hashrate_smooth);
							continue;
						}
						uint32_t delta = last_nonce[i] - start_nonce[i];
						double raw = (double)delta / elapsed_secs;
						ztex_stats[i].hashrate = raw;
						/* Smoothed display value: MEDIAN of the last N raw samples.
						 * The raw delta-nonce rate both spikes high (a stratum work
						 * reset straddles the window) and dips low (partial window),
						 * so a median is used — robust to both, and it never gets
						 * "stuck" the way a ratio-gated EMA can. Do not impose a
						 * core-count/frequency ceiling here: newer bitstreams may
						 * legitimately exceed the old 14 MH/s assumption. Large corrupt
						 * counter jumps are resynced or dropped before last_nonce is
						 * updated; smaller corrupt pairs remain visible in the CPU-check
						 * error counters instead of being hidden by a display clamp. */
						if (raw > 0.0) {
							int H = (int)(sizeof(ztex_stats[i].hr_hist)/sizeof(double));
							ztex_stats[i].hr_hist[ztex_stats[i].hr_idx % H] = raw;
							ztex_stats[i].hr_idx++;
							if (ztex_stats[i].hr_count < H) ztex_stats[i].hr_count++;
							int n = ztex_stats[i].hr_count, k;
							double tmp[25];
							for (k = 0; k < n; k++) tmp[k] = ztex_stats[i].hr_hist[k];
							/* insertion sort (n<=15) */
							for (k = 1; k < n; k++) {
								double v = tmp[k]; int j = k - 1;
								while (j >= 0 && tmp[j] > v) { tmp[j+1] = tmp[j]; j--; }
								tmp[j+1] = v;
							}
							ztex_stats[i].hashrate_smooth = tmp[n/2];
						}
					}
				}
			}

			ztex_publish_hashrate(fpga, ztex_stats, num_fpgas, thr_id);

			// Always-on HW heartbeat (for the freq supervisor to parse).
			// Production is ~30s; an interlocked lane-0 canary may use ~20s.
			{
				time_t nowt = time(NULL);
				if (nowt - last_hb >=
				    (time_t)g_ztex_heartbeat_interval_seconds) {
					last_hb = nowt;
					double board_mhps = 0.0; int board_active = 0;
					for (i=0; i < num_fpgas; i++) {
						if (!ztex_stats[i].enabled) continue;
						double mhps = ztex_stats[i].hashrate_smooth/1000000.0;
						double wmh = (mhps > 0.01) ? (opt_watts_per_fpga / mhps) : 0.0;
						double mhw = (opt_watts_per_fpga > 0.01) ? (mhps / opt_watts_per_fpga) : 0.0;
						if (!ztex_rb_enabled(ztex_rb_mode)) {
							applog(LOG_WARNING, "HEARTBEAT %s%d %.2f MH/s %.1fW %.2f MH/s/W %.3f W/MHs HWtotal=%u RS=%d ERR=%.3f%%(%d/%d)",
								fpga->short_name, i, mhps, opt_watts_per_fpga, mhw, wmh, ztex_stats[i].hw_errors,
								ztex_stats[i].readback_resync,
								ztex_stats[i].hash_checks ? 100.0 * ztex_stats[i].hash_errors / ztex_stats[i].hash_checks : 0.0,
								ztex_stats[i].hash_errors,
								ztex_stats[i].hash_checks);
						} else {
							applog(LOG_WARNING,
							"HEARTBEAT %s%d %.2f MH/s %.1fW %.2f MH/s/W %.3f W/MHs HWtotal=%u RS=%d ERR=%.3f%%(%d/%d)"
							" RB[poll=%" PRIu64 " sel=%" PRIu64
							" wsend=%" PRIu64 " wretry=%" PRIu64
							" werr=%" PRIu64 " wshort=%" PRIu64 " short=%" PRIu64
								" usb=%" PRIu64 " zero=%" PRIu64 " jump=%" PRIu64
								" noise=%" PRIu64 " retry=%" PRIu64 " rec=%" PRIu64
								" drop=%" PRIu64 " ep=%" PRIu64 " pre=%" PRIu64
								" post=%" PRIu64 " cur=%" PRIu64 " prev=%" PRIu64
								" both=%" PRIu64 " neither=%" PRIu64 "]",
								fpga->short_name, i, mhps, opt_watts_per_fpga, mhw, wmh,
								ztex_stats[i].hw_errors, ztex_stats[i].readback_resync,
								ztex_stats[i].hash_checks ? 100.0 * ztex_stats[i].hash_errors / ztex_stats[i].hash_checks : 0.0,
							ztex_stats[i].hash_errors, ztex_stats[i].hash_checks,
							ztex_stats[i].rb_polls, ztex_stats[i].rb_select_fail,
							ztex_stats[i].rb_work_attempts, ztex_stats[i].rb_work_retries,
							ztex_stats[i].rb_work_errors, ztex_stats[i].rb_work_short,
							ztex_stats[i].rb_short, ztex_stats[i].rb_usb_error,
								ztex_stats[i].rb_zero, ztex_stats[i].rb_jump,
								ztex_stats[i].rb_noise, ztex_stats[i].rb_retry_attempts,
								ztex_stats[i].rb_retry_recovered, ztex_stats[i].rb_dropped,
								ztex_stats[i].rb_episodes, ztex_stats[i].rb_preclean_bad,
								ztex_stats[i].rb_postclean_bad, ztex_stats[i].rb_match_current,
								ztex_stats[i].rb_match_previous, ztex_stats[i].rb_match_both,
								ztex_stats[i].rb_match_neither);
						}
						board_mhps += mhps; board_active++;
					}
					if (board_active > 0) {
						double board_w = board_active * opt_watts_per_fpga;
						double board_wmh = (board_mhps > 0.01) ? (board_w / board_mhps) : 0.0;
						double board_mhw = (board_w > 0.01) ? (board_mhps / board_w) : 0.0;
						applog(LOG_WARNING, "BOARD %s %d fpgas %.2f MH/s %.1fW %.2f MH/s/W %.3f W/MHs",
							fpga->name, board_active, board_mhps, board_w, board_mhw, board_wmh);
					}
				}
			}

			if (elapsed.tv_sec >= fpga->timeout) {
				applog(LOG_DEBUG, "%s: End Scan For Nonces - Time = %d sec", fpga->short_name, elapsed.tv_sec);
				break;
			}
			
		}

		// Check & Adjust ZTEX Clock Frequency
		for (i=0; i < num_fpgas; i++) {
			if (ztex_stats[i].enabled && ztex_stats[i].hashrate > 0) {

				// Ellapsed Time Since Last Frequency Check
				timeval_subtract(&elapsed, &tv_end, &ztex_stats[i].freq_check_tv);

				/* SHA3T variant-ladder governor (--auto-freq): every 60s per
				 * chip, evaluate CPU-verified checkNonce samples. Any mismatch
				 * in a sufficiently sampled window steps DOWN; five consecutive
				 * zero-error windows may probe an untainted faster fixed image.
					 * Assignments persist in family-bound state IDs. */
				if (opt_algo == ALGO_SHA3T && !sha3_bitstream_override_active &&
				    vg_enabled && opt_auto_freq) {
					if (elapsed.tv_sec >= 60) {
						struct ztex_stats *zs = &ztex_stats[i];
						int checks = zs->hash_checks - zs->vg_snap_checks;
						int errs   = zs->hash_errors - zs->vg_snap_errors;
						int rung = zs->gov_m, nr = -1;
						if (checks < 0 || errs < 0 || errs > checks ||
						    rung < 0 || rung >= (int)VG_NRUNGS || !vg_avail[rung]) {
							zs->vg_clean_wins = 0;
							applog(LOG_ERR,
								"%s-%d: governor window invariant failed (rung=%d checks=%d errors=%d); holding",
								fpga->short_name, i, rung, checks, errs);
						} else {
							int slower = sha3_variant_next_slower(vg_avail,
								VG_NRUNGS, rung);
							int faster = sha3_variant_next_faster(vg_avail,
								VG_NRUNGS, rung);
							enum sha3_variant_window_action action;
							double er = checks > 0 ? (double)errs / checks : 0.0;

							/* The per-rung maximum is a session-local taint latch: a
							 * rung that produced a verified mismatch is not probed again
							 * until the operator starts a fresh qualification session. */
							if (er > zs->gov_maxErrorRate[rung])
								zs->gov_maxErrorRate[rung] = er;
							if (errs > 0)
								sha3_variant_taint_rung(&zs->vg_tainted_mask,
									VG_NRUNGS, rung);
							action = sha3_variant_window_decide(
								(unsigned)checks, (unsigned)errs, faster >= 0,
								faster >= 0 && sha3_variant_rung_is_tainted(
									zs->vg_tainted_mask, VG_NRUNGS, faster),
								&zs->vg_clean_wins);
							if (action == SHA3_VARIANT_STEP_DOWN) {
								nr = slower;
								if (nr < 0)
									applog(LOG_ERR,
										"%s-%d: verified hash error at slowest available variant %s",
										fpga->short_name, i, vg_spec(rung)->state_id);
							} else if (action == SHA3_VARIANT_PROBE_UP) {
								nr = faster;
							}
						}
						if (nr >= 0 && nr != rung) {
							int fallback_rung;

							if (nr > rung) {
								fallback_rung = rung;
							} else {
								int safer = sha3_variant_next_slower(vg_avail,
									VG_NRUNGS, nr);
								fallback_rung = safer >= 0 ? safer : nr;
							}

							applog(LOG_WARNING,
								"%s-%d: governor %s -> %s (%.6f -> %.6f MH/s; win err %d/%d)",
								fpga->short_name, i, vg_spec(rung)->state_id,
								vg_spec(nr)->state_id,
								vg_spec(rung)->expected_rate_hps_floor / 1000000.0,
								vg_spec(nr)->expected_rate_hps_floor / 1000000.0,
								errs, checks);
							if (!libztex_selectFpga(ztex, i)) {
								applog(LOG_ERR,
									"%s-%d: governor could not select lane; old image left untouched",
									fpga->short_name, i);
							} else if (vg_verify_rung_file(nr, true) &&
								   libztex_configureFpga(ztex, vg_bitfile(nr))) {
								zs->gov_m = nr;
								zs->hash_clock_mhz =
									sha3_variant_clock_mhz(vg_spec(nr));
								/* Configuration success is provisional. Persist only
								 * after sustained clean CPU-verified progress; a probe-up falls
								 * back to its proven prior rung, while a step-down
								 * retries the known-safe target itself once. */
								vg_arm_reconfig_guard(zs, fallback_rung, false);
								if (nr < rung &&
								    !vg_save_rung(ztex->repr, i, nr))
									applog(LOG_ERR,
										"%s-%d: governor could not persist safer rollback target %s: %s",
										fpga->short_name, i,
										vg_spec(nr)->state_id, strerror(errno));
								work_restart[thr_id].restart = 1;
							} else {
								/* The target configuration may have destroyed the old
								 * image. Probe-up restores the proven prior rung; a failed
								 * error-driven step-down must never restore the rung that
								 * just produced a verified mismatch, so it uses the already
								 * selected safer fallback instead. */
								zs->gov_m = nr;
								zs->hash_clock_mhz =
									sha3_variant_clock_mhz(vg_spec(nr));
								zs->vg_reconfig_pending = true;
								zs->vg_reconfig_recovery_attempted = false;
								zs->vg_reconfig_fallback_rung = fallback_rung;
								zs->vg_reconfig_started_us = 0;
								(void)vg_recover_reconfig(fpga, ztex, i,
									num_fpgas, thr_id,
									"target configuration failed");
							}
						} else {
							zs->vg_snap_checks = zs->hash_checks;
							zs->vg_snap_errors = zs->hash_errors;
						}
						gettimeofday(&zs->freq_check_tv, NULL);
					}
					continue;   /* replaces the legacy auto-freq below */
				}
				/* Fixed-clock SHA3T must never fall through to the legacy
				 * dcm_prog-pin governor, even if a future invariant disables
				 * the separately implemented image ladder at runtime. */
				if (opt_algo == ALGO_SHA3T)
					continue;

				// Restart Frequency Check Error Count Every 2 Minutes
				if(elapsed.tv_sec > 120) {

					// Increase Frequency If No Error Found In Last 2 Minutes
					if(opt_auto_freq && !ztex_stats[i].max_freq_found && ztex_stats[i].freq_check_errors == 0 && hw_errors[i] == 0) {
						ztex_stats[i].freq++;
						libztex_selectFpga(ztex, i);
						libztex_setFreq(ztex, ztex_stats[i].freq);
					}

					ztex_stats[i].freq_check_errors = hw_errors[i];
					gettimeofday(&ztex_stats[i].freq_check_tv, NULL);
				}
				else {
					ztex_stats[i].freq_check_errors += hw_errors[i];
				}

				// Decrease Frequency If More Than 1 Error In Last 2 Minutes
				// (only when auto-freq is explicitly enabled — otherwise a
				// transient error must never silently downclock the board)
				if(opt_auto_freq && ztex_stats[i].freq_check_errors > 1) {
					if(!ztex_stats[i].max_freq_found) {
						ztex_stats[i].max_freq_found = true;
						ztex_stats[i].hw_errors = 0;
					}
					ztex_stats[i].freq--;
					libztex_selectFpga(ztex, i);
					libztex_setFreq(ztex, ztex_stats[i].freq);
					ztex_stats[i].freq_check_errors = 0;
					gettimeofday(&ztex_stats[i].freq_check_tv, NULL);
				}
			}
		}
		
		// Display FPGA Summary
		if (display_summary != opt_fpga_summary) {
			
			display_summary = opt_fpga_summary;

			applog(LOG_WARNING, "----------------- FPGA Summary for %s -----------------", fpga->name);
			
			for (i=0; i < num_fpgas; i++) {

				if(ztex_stats[i].enabled)
					applog(LOG_WARNING, "Hash: %-4.2f Mh/s  Freq: %-7.3f Mhz  Submitted: %u  HW: %u", ztex_stats[i].hashrate_smooth / 1000000.0, ztex_stats[i].hash_clock_mhz, ztex_stats[i].submitted, ztex_stats[i].hw_errors);
				else
					applog(LOG_WARNING, "Hash: DISABLED     Freq: %-7.3f Mhz  Submitted: %u  HW: %u", ztex_stats[i].hash_clock_mhz, ztex_stats[i].submitted, ztex_stats[i].hw_errors);
					
			}

			applog(LOG_WARNING, "--------------------------------------------------------------------");
		}
	}

out:
	for (i = 0; i < num_fpgas; i++)
		clear_lane_hashrate(&ztex_stats[i].hashrate,
			&ztex_stats[i].hashrate_smooth);
	fpga->hashrate = 0.0;
	pthread_mutex_lock(&stats_lock);
	clear_hashrate_slot(thr_hashrates, thr_hashrates_count,
		(size_t)thr_id);
	pthread_mutex_unlock(&stats_lock);
	libztex_destroy_device(ztex);
	tq_freeze(mythr->q);
	
	return NULL;
}

static double ConvertBitsToDouble(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

/* BS1 worker for the current Stratum work/submit APIs.  Include this after
 * the existing work, Stratum and publication helpers in fpga-miner.c.
 * Thread allocation and process signal handling remain with the caller.
 */
static bool vu9p_work_is_current(const struct work *work, int thr_id,
                                uint64_t generation)
{
	return have_stratum && !jsonrpc_2 &&
	       !work_restart[thr_id].restart &&
	       current_work_generation() == generation &&
	       time(NULL) < current_work_time() + 120 &&
	       stratum_is_share_current(&stratum,
		work->connection_generation, work->job_epoch);
}

static void *vu9p_miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	int ci = mythr->vu9p_card;
	struct vu9p_card *card = &g_vu9p_cards[ci];
	struct work work;
	unsigned char hdr76[76];
	uint32_t nonce, hash7, last_hash7, htarg;
	uint64_t epoch_hashes = 0;
	uint64_t previous_epoch_hashes = 0;
	uint64_t completed_hashes = 0;
	uint64_t measured_rate_hps = 0;
	uint32_t edata[20], hash[8];
	struct timeval tv_session_start, tv_now;
	bool session_started = false;
	bool epoch_running = false;
	time_t last_hb = 0;
	time_t last_temp = 0;
	int k, rc;

	memset(&work, 0, sizeof(work));
	applog(LOG_INFO, "VU9P %d: miner thread %d started (bridge %s:%d)",
	       ci, thr_id, card->host, card->port);

	while (card->enabled) {
		enum stratum_gen_result generated;
		uint64_t generation;
		unsigned retry_delay_ms = 0;

		/* The preceding epoch is stopped before any owned fields are freed.
		 * READY is the only result that may publish a new header. */
		work_free(&work);
		memset(&work, 0, sizeof(work));
		if (!have_stratum || jsonrpc_2) {
			applog(LOG_ERR, "VU9P: only standard Stratum is supported");
			card->enabled = false;
			break;
		}
		if (time(NULL) >= current_work_time() + 120) {
			nmsleep(100);
			continue;
		}
		/* A restart racing with the flag clear is also detected by the
		 * generation comparison after generation and at every poll. */
		generation = current_work_generation();
		work_restart[thr_id].restart = 0;
		generated = stratum_gen_work_result(&stratum, &work);
		if (generated == STRATUM_GEN_WAIT) {
			work_free(&work);
			nmsleep(100);
			continue;
		}
		if (generated == STRATUM_GEN_FATAL) {
			/* The generator requests reconnect on fatal ownership/allocation
			 * failure.  No hardware work exists while it recovers. */
			work_free(&work);
			nmsleep(100);
			continue;
		}
		if (generated != STRATUM_GEN_READY) {
			card->enabled = false;
			break;
		}
		/* Measure only while stopped: TEMP must not add a transaction to
		 * the active POLL/STOP nonce guard, nor be starved by FOUND replies. */
		if (time(NULL) - last_temp >= VU9P_TEMP_INTERVAL_S) {
			struct vu9p_temp_reply temp_reply;
			if (vu9p_temp(card, &temp_reply) < 0) {
				card->enabled = false;
				applog(LOG_ERR,
				       "VU9P %d: bridge TEMP failed; disabling card",
				       ci);
				break;
			}
			last_temp = time(NULL);
			applog(LOG_INFO,
			       "VU9P %d: TEMP MASTER_SLR_ONLY C=%.3f VCCINT=%.4f VCCAUX=%.4f VCCBRAM=%.4f",
			       ci, temp_reply.temp_c, temp_reply.vccint_v,
			       temp_reply.vccaux_v, temp_reply.vccbram_v);
		}
		if (!vu9p_work_is_current(&work, thr_id, generation))
			continue;
		work.dev_board = -1;  /* keep VU9P out of ZTEX TUI attribution */
		work.dev_fpga = -1;

		/* FPGA sees be32enc()'d header words — sha3t.c serialization */
		swap_endian(hdr76, work.data, 76);
		htarg = work.target[7];

		/* The measured rate includes every bridge WORK transaction and every
		 * inter-epoch gap.  Start the clock before the first byte is sent. */
		gettimeofday(&tv_now, NULL);
		if (!session_started) {
			tv_session_start = tv_now;
			session_started = true;
		}
		epoch_hashes = 0;
		previous_epoch_hashes = 0;
		card->last_hashes = 0;
		epoch_running = true; /* A lost WORK reply can still mean running. */
		if (vu9p_send_work(card, hdr76, htarg, 0) < 0) {
			/* The bridge can have started this epoch even when its OK reply
			 * was lost.  Never leave that ambiguous epoch running while the
			 * host sleeps or retries. */
			applog(LOG_ERR,
			       "VU9P %d: WORK send failed; stopping ambiguous epoch",
			       ci);
			retry_delay_ms = 1000;
			goto epoch_done;
		}

		while (card->enabled &&
		       vu9p_work_is_current(&work, thr_id, generation)) {
			enum vu9p_roll_decision roll_decision;
			uint64_t accounted_hashes;
			uint64_t roll_limit;
			double secs;
			bool roll_after_poll;
			uint64_t counter_previous;

			rc = vu9p_poll(card, &nonce, &hash7, &epoch_hashes,
			               &last_hash7);
			if (rc < 0) {
				applog(LOG_ERR, "VU9P %d: bridge poll failed, reconnecting", ci);
				break;
			}

			/* FOUND and NONE both include the rollover-checked counter. Account
			 * first so a hit cannot bypass rate or nonce-wrap enforcement. */
			gettimeofday(&tv_now, NULL);
			accounted_hashes = vu9p_add_unique_hashes(completed_hashes,
				epoch_hashes, opt_vu9p_active_lanes);
			secs = (tv_now.tv_sec - tv_session_start.tv_sec) +
			       (tv_now.tv_usec - tv_session_start.tv_usec) / 1e6;
			if (secs > 0.0) {
				double observed_hps = (double)accounted_hashes / secs;

				card->mhs = observed_hps / 1e6;
				pthread_mutex_lock(&stats_lock);
				thr_hashrates[thr_id] = observed_hps;
				pthread_mutex_unlock(&stats_lock);
				measured_rate_hps = observed_hps >= (double)UINT64_MAX ?
					UINT64_MAX : (uint64_t)(observed_hps + 0.5);
			}
			card->last_hashes = epoch_hashes;
			roll_limit = vu9p_roll_limit(opt_vu9p_active_lanes,
				opt_vu9p_rate_hps, measured_rate_hps,
				opt_vu9p_poll_work_ms);
			counter_previous = previous_epoch_hashes;
			roll_decision = vu9p_classify_hash_counter(
				counter_previous, epoch_hashes,
				opt_vu9p_active_lanes, opt_vu9p_rate_hps,
				measured_rate_hps, opt_vu9p_poll_work_ms);
			if (roll_decision == VU9P_ROLL_COUNTER_REGRESSION ||
			    roll_decision == VU9P_ROLL_COUNTER_OVERRUN ||
			    roll_decision == VU9P_ROLL_INVALID_CONFIG) {
				card->enabled = false;
				applog(LOG_ERR,
				       "VU9P %d: disabling after unsafe hash counter decision=%d previous=%" PRIu64 " current=%" PRIu64 " capacity=%" PRIu64 " limit=%" PRIu64,
				       ci, (int)roll_decision, counter_previous,
				       epoch_hashes,
				       vu9p_unique_epoch_capacity(opt_vu9p_active_lanes),
				       roll_limit);
				break;
			}
			previous_epoch_hashes = epoch_hashes;
			roll_after_poll = roll_decision == VU9P_ROLL_THRESHOLD;

			if (time(NULL) - last_hb >= 30) {
				last_hb = time(NULL);
				applog(LOG_INFO,
				       "VU9P %d: %.1f MH/s, epoch_hashes=%" PRIu64 "/%" PRIu64 ", roll_limit=%" PRIu64 ", last_hash7=%08X, hw_errors=%llu",
				       ci, card->mhs, epoch_hashes,
				       vu9p_unique_epoch_capacity(opt_vu9p_active_lanes),
				       roll_limit, last_hash7,
				       (unsigned long long)card->hw_errors);
			}
			/* A notification/disconnect can arrive during a blocking POLL.
			 * Never attribute its result to a replacement job. */
			if (!vu9p_work_is_current(&work, thr_id, generation))
				break;
			if (rc == 1) {
				/* checkNonce: host recompute before anything else */
				for (k = 0; k < 19; k++)
					be32enc(&edata[k], work.data[k]);
				be32enc(&edata[19], nonce);
				sha3256t_hash(hash, edata);
				if (hash[7] != hash7) {
					card->hw_errors++;
					applog(LOG_ERR,
					    "VU9P %d: checkNonce FAILED nonce=%08X fpga=%08X host=%08X (hw_errors=%llu)",
					    ci, nonce, hash7, hash[7],
					    (unsigned long long)card->hw_errors);
				} else if (hash[7] <= htarg && fulltest(hash, work.target)) {
					work.data[19] = nonce;
					applog(LOG_WARNING, "VU9P %d: SHARE FOUND nonce=%08X hash7=%08X",
					       ci, nonce, hash7);
					if (!submit_work(mythr, &work)) {
						/* Queue backpressure must not extend a live sweep.
						 * submit_work clones on success; keep this owned
						 * record unchanged across the remaining retries. */
						int stopped = vu9p_stop(card);
						epoch_running = false;
						if (stopped < 0) {
							card->enabled = false;
							applog(LOG_ERR,
							    "VU9P %d: STOP failed after share queue rejection; disabling card", ci);
							goto epoch_done;
						}
						if (!work_publish_retry(mythr, &work, 2,
						        work_publish_submit_work,
						        work_publish_retry_pause)) {
							card->enabled = false;
							applog(LOG_ERR,
							    "VU9P %d: share queue failed after 3 attempts; card stopped and disabled", ci);
						}
						goto epoch_done;
					}
				}
				if (roll_after_poll)
					break;
				continue;  /* poll again immediately; more may be pending */
			}

			if (roll_after_poll)
				break;

			nmsleep(VU9P_POLL_INTERVAL_MS);
		}
	epoch_done:
		completed_hashes = vu9p_add_unique_hashes(completed_hashes,
			epoch_hashes, opt_vu9p_active_lanes);
		/* STOP is required even after TEMP/counter failures disable the card.
		 * A failed transaction closes its socket; the bridge also stops the
		 * old owner on EOF, and quarantines itself if that STOP fails. */
		if (epoch_running) {
			int stopped = vu9p_stop(card);
			epoch_running = false;
			if (stopped < 0) {
				card->enabled = false;
				applog(LOG_ERR,
				       "VU9P %d: failed to stop nonce epoch; disabling card", ci);
			}
		}
		work_free(&work);
		pthread_mutex_lock(&stats_lock);
		thr_hashrates[thr_id] = 0;
		pthread_mutex_unlock(&stats_lock);
		card->mhs = 0;
		if (card->enabled && retry_delay_ms)
			nmsleep(retry_delay_ms);
	}
	work_free(&work);
	if (card->fd >= 0) {
		close(card->fd);
		card->fd = -1;
	}
	pthread_mutex_lock(&stats_lock);
	thr_hashrates[thr_id] = 0;
	pthread_mutex_unlock(&stats_lock);
	card->mhs = 0;
	return NULL;
}


static void *key_monitor_thread(void *userdata)
{
	struct timeval now;

	double network_difficulty = 0.0, block_difficulty = 0.0, diff_factor;
	double net_diff_snapshot;
	int ch, day, hour, min, sec, total_sec;

	pthread_mutex_lock(&stats_lock);
	diff_factor = opt_diff_factor;
	pthread_mutex_unlock(&stats_lock);
	switch (opt_algo) {
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
		case ALGO_MYR_GR:
			diff_factor *= 256.0;
			break;
		default:
			break;
	}
	
	while(true)
	{
		nmsleep(100);
		ch = getchar();
		ch = toupper( ch );
		if (ch == '\n')
			continue;

		switch(ch)
		{
		case 'S':
			{
				gettimeofday(&now, NULL);
				total_sec = now.tv_sec - g_miner_start_time.tv_sec;
				day  = total_sec / 3600 / 24;
				hour = total_sec / 3600 - day*24;
				min  = total_sec / 60 - (day*24 + hour)*60;
				sec  = total_sec % 60;

				applog(LOG_WARNING, "************************** Mining Summary **************************");
				
				if (have_stratum)
				{
					struct stratum_ctx *sctx = &stratum;
					pthread_mutex_lock(&sctx->work_lock);
					network_difficulty = ConvertBitsToDouble(swab32(le32dec(sctx->job.nbits)));
					pthread_mutex_unlock(&sctx->work_lock);

					block_difficulty = stratum_diff / diff_factor;

				}
				
				applog(LOG_WARNING, "Hash: %1.2f Mh/s  A: %u  R: %u (%1.2f%%)  HW: %u  BF: %d"
					,(double)global_hashrate/1000000.0
					,accepted_count
					,rejected_count
					,100.0 * accepted_count / (accepted_count + rejected_count)
					,0
					,g_block_count );
				pthread_mutex_lock(&stats_lock);
				net_diff_snapshot = g_net_diff;
				pthread_mutex_unlock(&stats_lock);
				if (have_stratum)
					net_diff_snapshot = network_difficulty;
				applog(LOG_WARNING, "Net Diff: %1.3f, Block Diff: %1.3f  Run Time: %02d Days %02d:%02d:%02d", net_diff_snapshot, block_difficulty, day, hour, min, sec);

				applog(LOG_WARNING, "********************************************************************");

			}
			break;
		case 'D':
			opt_debug = !opt_debug;
			applog(LOG_WARNING, "Debug Mode: %s", opt_debug ? "On" : "Off");
			break;
		case 'F':
			opt_fpga_summary = !opt_fpga_summary;
			break;
		case 'Q':
			opt_quiet = !opt_quiet;
			applog(LOG_WARNING, "Quiet Mode: %s", opt_quiet ? "On" : "Off");
			break;
		}
	}
	return 0;
}


int main(int argc, char *argv[]) {
	struct thr_info *thr;
	long flags;
	int i, err, thr_idx;
	int v2_ztex_thr_id = -1;
	void *v2_worker_result = NULL;

	bc3_ztex_shutdown_init(&bc3_ztex_v2_shutdown);
	stratum_submit_map_init(&g_submit_map);

	show_credits();

	rpc_user = strdup("");
	rpc_pass = strdup("");
	opt_api_allow = strdup("127.0.0.1"); /* 0.0.0.0 for all ips */

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif
	if (num_cpus < 1)
		num_cpus = 1;

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!rpc_url) {
		// try default config file in binary folder
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig)) {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
	}

	if (!opt_n_threads)
		opt_n_threads = num_cpus;
	if (!opt_n_threads)
		opt_n_threads = 1;

	/* Keep backend selection failures free of device side effects. USB and
	 * VU9P fleets use separate processes of this same executable. */
	if (opt_vu9p_options_seen && !opt_use_vu9p) {
		applog(LOG_ERR, "VU9P options require --vu9p");
		return 1;
	}
	if (opt_use_vu9p) {
		uint64_t roll_limit;
		if (opt_use_ztex || opt_use_serial || opt_firmware || opt_auto_freq) {
			applog(LOG_ERR, "Use separate miner processes for VU9P and USB/serial FPGA backends");
			return 1;
		}
		if (opt_algo != ALGO_SHA3T || !want_stratum || !have_stratum ||
		    jsonrpc_2 || !opt_vu9p_build_id_set ||
		    !vu9p_production_identity_matches(opt_vu9p_build_id,
			opt_vu9p_active_lanes) ||
		    opt_vu9p_rate_hps != UINT64_C(300000000)) {
			applog(LOG_ERR, "VU9P BS1 requires standard Stratum, sha3t, --vu9p-build-id 5a3d0001, --vu9p-active-lanes 1 and --vu9p-rate-hps 300000000");
			return 1;
		}
		roll_limit = vu9p_roll_limit(opt_vu9p_active_lanes,
			opt_vu9p_rate_hps, 0, opt_vu9p_poll_work_ms);
		if (!roll_limit || vu9p_set_io_timeout_ms(
		    vu9p_transaction_timeout_ms(opt_vu9p_poll_work_ms)) < 0) {
			applog(LOG_ERR, "Invalid VU9P polling/STOP bound: it must leave a positive transaction deadline and nonce epoch");
			return 1;
		}
		applog(LOG_INFO,
			"VU9P BS1 build_id=0x%08x active_lanes=1 expected_rate=300000000H/s poll_work_bound=%ums txn_deadline=%ums roll_limit=%" PRIu64,
			opt_vu9p_build_id, opt_vu9p_poll_work_ms,
			vu9p_transaction_timeout_ms(opt_vu9p_poll_work_ms), roll_limit);
	}

	/* This gate is intentionally before curl setup, libusb_init(), device scan,
	 * FPGA selection, and configuration.  Actual serial presence and the board's
	 * reported lane count remain post-scan facts; the pre-USB policy requires the
	 * exact syntactic selectors that make those later checks single-board/lane. */
	{
		const struct bc3_ztex_heartbeat_scope heartbeat_scope = {
			.option_seen = opt_heartbeat_interval_seen,
			.interval_seconds = g_ztex_heartbeat_interval_seconds,
			.algorithm_sha3t = opt_algo == ALGO_SHA3T,
			.use_ztex = opt_use_ztex,
			.use_cpu = opt_use_cpu,
			.use_serial = opt_use_serial,
			.serial_only = getenv("ZTEX_SERIAL_ONLY"),
			.fpga_only = getenv("FPGA_ONLY"),
			.bitstream = getenv("SHA3_BITSTREAM"),
			.api_listen = opt_api_listen,
			.force_firmware = opt_firmware,
			.auto_frequency = opt_auto_freq,
			.ztex_frequency_explicit = opt_ztex_frequency_explicit,
			.ztex_frequency_exact_96 = opt_ztex_frequency_exact_96,
			.hash_clock_explicit = opt_hash_clock_explicit,
			.hash_clock_exact_96 = opt_hash_clock_exact_96
		};
		enum bc3_ztex_heartbeat_policy_result heartbeat_result =
			bc3_ztex_heartbeat_policy_validate(&heartbeat_scope);

		if (heartbeat_result != BC3_ZTEX_HEARTBEAT_POLICY_OK) {
			applog(LOG_ERR,
				"--heartbeat-interval rejected before USB access: %s",
				bc3_ztex_heartbeat_policy_result_text(heartbeat_result));
			return 1;
		}
	}

	/* Finish all pure/network process setup before any candidate can be
	 * configured. This leaves only USB configuration itself inside the
	 * pre-worker PAUSE cleanup window. */
	if (!rpc_url) {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
	}
	if (!rpc_userpass) {
		rpc_userpass = (char*) malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	stratum.sock = CURL_SOCKET_BAD;
	stratum_transport_init(&stratum.transport);

	flags = strncmp(rpc_url, "https:", 6)
	        ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	        : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

	/* A candidate request is recognizable before detect_fpga validates and
	 * opens USB. Install termination handlers before that boundary. */
	bc3_ztex_v2_signal_drain_mode =
		(getenv("SHA3_PROTOCOL_V2_BUILD_ID") != NULL && opt_use_ztex &&
		 opt_algo == ALGO_SHA3T) ? 1 : 0;
#ifndef WIN32
	{
		struct sigaction action;
		struct sigaction ignored_action;

		memset(&action, 0, sizeof(action));
		action.sa_handler = signal_handler;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGINT, &action, NULL) != 0 ||
		    (bc3_ztex_v2_signal_drain_mode &&
		     (sigaction(SIGTERM, &action, NULL) != 0 ||
		      sigaction(SIGHUP, &action, NULL) != 0 ||
		      sigaction(SIGQUIT, &action, NULL) != 0))) {
			applog(LOG_ERR, "unable to install termination signal handlers");
			return 1;
		}
		/* A closed Stratum socket must become an ordinary send error, never a
		 * process-fatal SIGPIPE that can orphan configured candidate hardware. */
		if (bc3_ztex_v2_signal_drain_mode) {
			memset(&ignored_action, 0, sizeof(ignored_action));
			ignored_action.sa_handler = SIG_IGN;
			sigemptyset(&ignored_action.sa_mask);
			if (sigaction(SIGPIPE, &ignored_action, NULL) != 0) {
				applog(LOG_ERR,
					"unable to ignore SIGPIPE for typed candidate");
				return 1;
			}
		}
	}
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
#endif

#ifndef WIN32
	if (opt_tui && !isatty(STDOUT_FILENO)) {
		applog(LOG_WARNING, "--tui requires a terminal; disabling TUI");
		opt_tui = false;
	}
#endif
	if (opt_tui) {
		pthread_t tui_pth;
		tui_init();   /* takes over the terminal; applog now routes to the log pane */
		pthread_create(&tui_pth, NULL, tui_thread, NULL);
		pthread_detach(tui_pth);
	}


	if(!opt_use_cpu)
		g_miner_count = 0;
	else
		g_miner_count = opt_n_threads;

	// Detect Serial & ZTEX FGPAs Connected To The Miner
	if(opt_use_serial || opt_use_ztex) {
		err = libusb_init(NULL);
		if (err) {
			applog(LOG_ERR, "ERROR: libusb_init() Failed To Initialize (%d)", err);
			return 1;
		}
		if(!detect_fpga()) {
			return bc3_ztex_v2_active ?
				bc3_ztex_v2_startup_failure("FPGA detection/configuration") : 1;
		}
	}

	g_miner_count += g_fpga_count;

	if (opt_use_vu9p) {
		if (vu9p_init(opt_vu9p_build_id) <= 0) {
			applog(LOG_ERR, "ERROR: no VU9P bridge responded (--vu9p)");
			return 1;
		}
		g_miner_count += g_vu9p_card_count;
	}

	switch (opt_algo) {
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			g_fpga_use_midstate = true;
			g_fpga_work_len = 44;
			g_nonce_word_index = 19;
			break;
		case ALGO_BLAKE3:
			g_fpga_use_midstate = false;
			g_fpga_work_len = 84;
			g_nonce_word_index = 35;
			break;
		case ALGO_ODO:
			g_fpga_use_midstate = false;
			g_fpga_work_len = 76;  // 80-byte header minus 4-byte nonce
			g_nonce_word_index = 19;  // standard nonce position
			break;
		default:
			g_fpga_use_midstate = false;
			g_fpga_work_len = 80;
			g_nonce_word_index = 19;
	}
	
#ifdef WIN32
	if (opt_priority > 0) {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority) {
		case 1:
			prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
		case 3:
			prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		case 4:
			prio = HIGH_PRIORITY_CLASS;
			break;
		case 5:
			prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
#endif
	if (opt_affinity != -1) {
		if (!opt_quiet)
			applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
		affine_to_cpu_mask(-1, opt_affinity);
	}

	/* One thread per CPU worker AND per FPGA board (serial + ztex), plus 4
	 * service threads (work/longpoll/stratum/api) + 1 slack. Previously sized
	 * to only (g_miner_count + 5), which overflowed with >1 ZTEX board since
	 * one ztex_miner_thread is spawned per board. */
	int n_alloc_threads = (int)hashrate_slot_count((size_t)g_miner_count,
		(size_t)(g_serial_fpga_count + g_ztex_fpga_count +
		         (opt_use_vu9p ? g_vu9p_card_count : 0)));

	work_restart = (struct work_restart*) calloc(n_alloc_threads, sizeof(*work_restart));
	if (!work_restart)
		return bc3_ztex_v2_active ?
			bc3_ztex_v2_startup_failure("work-restart allocation") : 1;

	thr_info = (struct thr_info*) calloc(n_alloc_threads, sizeof(*thr));
	if (!thr_info)
		return bc3_ztex_v2_active ?
			bc3_ztex_v2_startup_failure("thread-info allocation") : 1;

	thr_hashrates = (double *) calloc(n_alloc_threads, sizeof(double));
	if (!thr_hashrates)
		return bc3_ztex_v2_active ?
			bc3_ztex_v2_startup_failure("hashrate allocation") : 1;
	thr_hashrates_count = (size_t)n_alloc_threads;

	/* init workio thread info */
	work_thr_id = g_miner_count;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return bc3_ztex_v2_active ?
			bc3_ztex_v2_startup_failure("work queue allocation") : 1;

	/* start work I/O thread */
	if (thread_create(thr, workio_thread)) {
		applog(LOG_ERR, "work thread create failed");
		return bc3_ztex_v2_active ?
			bc3_ztex_v2_startup_failure("work thread creation") : 1;
	}

	/* ESET-NOD32 Detects these 2 thread_create... */
	if (want_longpoll && !have_stratum) {
		/* init longpoll thread info */
		longpoll_thr_id = g_miner_count + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return bc3_ztex_v2_active ?
				bc3_ztex_v2_startup_failure("longpoll queue allocation") : 1;

		/* start longpoll thread */
		err = thread_create(thr, longpoll_thread);
		if (err) {
			applog(LOG_ERR, "long poll thread create failed");
			return bc3_ztex_v2_active ?
				bc3_ztex_v2_startup_failure("longpoll thread creation") : 1;
		}
	}
	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = g_miner_count + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return bc3_ztex_v2_active ?
				bc3_ztex_v2_startup_failure("stratum queue allocation") : 1;

		/* start stratum thread */
		err = thread_create(thr, stratum_thread);
		if (err) {
			applog(LOG_ERR, "stratum thread create failed");
			return bc3_ztex_v2_active ?
				bc3_ztex_v2_startup_failure("stratum thread creation") : 1;
		}
		if (have_stratum) {
			char *stratum_url = strdup(rpc_url);

			if (!stratum_url ||
			    !tq_push(thr_info[stratum_thr_id].q, stratum_url)) {
				free(stratum_url);
				return bc3_ztex_v2_active ?
					bc3_ztex_v2_startup_failure(
						"initial stratum queue handoff") : 1;
			}
		}
	}

	if (opt_api_listen) {
		/* api thread */
		api_thr_id = g_miner_count + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create(thr, api_thread);
		if (err) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
	}

	applog(LOG_INFO, "Attempting to start %d miner threads using '%s' algorithm", g_miner_count, algo_names[opt_algo]);
	thr_idx = 0;

	// Start CPU Mining Threads
	// NOTE: CPU threads occupy ids [0 .. g_miner_count-1]; the 4 service threads
	// occupy [g_miner_count .. g_miner_count+3]. Device (serial/ztex) threads must
	// therefore start at g_miner_count+4 to avoid aliasing the service threads
	// (critical once >1 board is present). See device-thread section below.
	if (opt_use_cpu) {
		for (i = 0; i < opt_n_threads; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return 1;

			err = thread_create(thr, miner_thread);
			if (err) {
				applog(LOG_ERR, "thread %d create failed", i);
				return 1;
			}
		}
		applog(LOG_INFO, "\t%d CPU miner threads started.", opt_n_threads);
	}

	// Device threads (serial/ztex) start AFTER the 4 service threads so their
	// ids never alias work/longpoll/stratum/api (which sit at g_miner_count+0..3).
	thr_idx = g_miner_count + 4;

	// Start Serial FPGA Mining Threads
	if (opt_use_serial) {
		for (i = 0; i < g_serial_fpga_count; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return 1;

			thr->fpga = calloc(1, sizeof(struct fpga_info));
			if ( !thr->fpga ) {
				applog(LOG_ERR, "ERROR: Unable to allocate Serial FPGA Info");
				return 1;
			}
			
			if (!initialize_serial_miner(thr, i)) {
				applog(LOG_ERR,
					"ERROR: Unable to initialize Serial FPGA miner %d", i);
				return 1;
			}

			err = thread_create(thr, serial_miner_thread);
			if (err) {
				applog(LOG_ERR, "ERROR: Serial FPGA minner thread %d create failed", i);
				return 1;
			}
		}
		applog(LOG_INFO, "\t%d Serial FPGA miner threads started.", g_serial_fpga_count);
	}
	
	// Start ZTEX FPGA Mining Threads
	if (opt_use_ztex) {
		for (i = 0; i < g_ztex_fpga_count; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return bc3_ztex_v2_active ?
					bc3_ztex_v2_startup_failure("ZTEX queue allocation") : 1;

			thr->fpga = calloc(1, sizeof(struct fpga_info));
			if ( !thr->fpga ) {
				applog(LOG_ERR, "ERROR: Unable to allocate ZTEX FPGA Info");
				return bc3_ztex_v2_active ?
					bc3_ztex_v2_startup_failure("ZTEX state allocation") : 1;
			}
			
			if (!initialize_ztex_miner(thr, i)) {
				applog(LOG_ERR,
					"ERROR: Unable to initialize ZTEX FPGA miner %d", i);
				return bc3_ztex_v2_active ?
					bc3_ztex_v2_startup_failure("ZTEX state initialization") : 1;
			}

			err = thread_create(thr, ztex_miner_thread);
			if (err) {
				applog(LOG_ERR, "ERROR: ZTEX FPGA miner thread %d create failed", i);
				return bc3_ztex_v2_active ?
					bc3_ztex_v2_startup_failure("ZTEX worker creation") : 1;
			}
			if (bc3_ztex_v2_active)
				v2_ztex_thr_id = thr->id;
		}
		gettimeofday(&g_miner_start_time, NULL);
		applog(LOG_INFO, "\t%d ZTEX FPGA miner threads started.", g_ztex_fpga_count);
	}

	if (opt_use_vu9p) {
		for (i = 0; i < g_vu9p_card_count; i++) {
			thr = &thr_info[thr_idx];
			thr->id = thr_idx++;
			thr->vu9p_card = i;
			thr->q = tq_new();
			if (!thr->q)
				return 1;
			if (thread_create(thr, vu9p_miner_thread)) {
				applog(LOG_ERR, "VU9P miner thread %d create failed", i);
				return 1;
			}
		}
		gettimeofday(&g_miner_start_time, NULL);
		applog(LOG_INFO, "\t%d VU9P miner threads started.", g_vu9p_card_count);
	}

	// Start the keyboard monitor only after every device-worker slot.  The old
	// fixed g_miner_count+4 index aliased the first serial/ZTEX worker and
	// overwrote its queue/thread metadata after it had started.
	if ((size_t)thr_idx != hashrate_monitor_index((size_t)g_miner_count,
		(size_t)(g_serial_fpga_count + g_ztex_fpga_count +
		         (opt_use_vu9p ? g_vu9p_card_count : 0))) ||
	    thr_idx >= n_alloc_threads) {
		applog(LOG_ERR, "internal thread-slot layout mismatch");
		if (bc3_ztex_v2_active && v2_ztex_thr_id >= 0)
			goto v2_post_worker_startup_failure;
		return 1;
	}
	thr = &thr_info[thr_idx];
	thr->id = thr_idx;
	thr->q = tq_new();
	if (!thr->q) {
		if (bc3_ztex_v2_active && v2_ztex_thr_id >= 0)
			goto v2_post_worker_startup_failure;
		return 1;
	}
	if (thread_create(thr, key_monitor_thread)) {
		applog(LOG_ERR, "key monitor thread create failed");
		if (bc3_ztex_v2_active && v2_ztex_thr_id >= 0)
			goto v2_post_worker_startup_failure;
		return 1;
	}
	goto startup_complete;

v2_post_worker_startup_failure:
	bc3_ztex_v2_request_control_stop(true);
	pthread_join(thr_info[v2_ztex_thr_id].pth, &v2_worker_result);
	pthread_join(thr_info[work_thr_id].pth, NULL);
	return EXIT_FAILURE;

startup_complete:
	
	// Main Loop - Wait for workio thread to exit
	pthread_join(thr_info[work_thr_id].pth, NULL);

	if (bc3_ztex_v2_active && v2_ztex_thr_id >= 0) {
		bool expected_workio_stop =
			bc3_ztex_v2_workio_stop_handshake_complete();

		/* The v2 worker normally appends the NULL sentinel only after its
		 * PAUSE barrier. If workio died independently, this same request makes
		 * the sole board owner enter that barrier before main can return. */
		if (!expected_workio_stop)
			bc3_ztex_v2_request_control_stop(true);
		pthread_join(thr_info[v2_ztex_thr_id].pth, &v2_worker_result);
		return expected_workio_stop && bc3_ztex_v2_final_success(
			(int)(intptr_t)v2_worker_result) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	applog(LOG_WARNING, "workio thread dead, exiting.");

	return 0;
}
