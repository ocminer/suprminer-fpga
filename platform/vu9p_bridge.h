/* vu9p_bridge.h - generic register transport for VU9P (BCU-1525 and similar)
 * boards reached through a Vivado Lab JTAG-AXI bridge (platform/vu9p_bridge.tcl).
 *
 * Algorithm-agnostic: the bridge exposes 32-bit register reads/writes plus the
 * on-chip sensors; an algorithm driver (platform/vu9p_driver.h) gives the
 * registers their meaning.  Device specs come from --device, never from code:
 *   host:port             connect to a bridge somebody already started
 *   jtag:SERIAL[:port]    start a bridge for the board with that JTAG serial
 *                         (port defaults to 13400 + device index); a bridge
 *                         already answering on that port is reused
 *   ftdi:SERIAL           direct: the miner drives the board's FTDI JTAG cable itself
 *                         (bitstream must carry the BSCANE2 register bus); no Vivado needed
 *   SERIAL[:port]         bare serial: jtag: in --vu9p-mode bridge (default), ftdi: in --vu9p-mode direct
 */
#ifndef VU9P_BRIDGE_H
#define VU9P_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>

#define VU9P_MAX_DEVICES   16
#define VU9P_TRANSPORT_BRIDGE 0     /* host:port or jtag:SERIAL  -> vivado_lab JTAG-AXI bridge */
#define VU9P_TRANSPORT_JTAG   1     /* ftdi:SERIAL -> the miner drives the FTDI cable itself (no bridge) */
#define VU9P_SPEC_LEN      128
#define VU9P_BRIDGE_BASE_PORT 13400

struct vu9p_dev {
	int      index;                 /* position in --device list */
	char     spec[VU9P_SPEC_LEN];
	char     host[64];
	int      port;
	char     serial[48];            /* empty when connecting to an external bridge */
	int      transport;             /* VU9P_TRANSPORT_BRIDGE or VU9P_TRANSPORT_JTAG */
	void    *jtag;                  /* native JTAG state (platform/vu9p_jtag.c) */
	bool     own_bridge;            /* we spawned the vivado_lab bridge */
	pid_t    bridge_pid;
	int      fd;
	pthread_mutex_t lock;
	bool     enabled;

	/* filled by vu9p_connect */
	uint32_t build_id;

	/* sensors (last vu9p_temp) */
	double   temp_c, vccint_v, vccaux_v, vccbram_v;

	/* statistics maintained by the miner thread */
	uint64_t hw_errors;
	double   hps;
	void    *algo_state;            /* owned by the algorithm driver */
};

struct vu9p_tools {
	const char *vivado_lab;         /* vivado_lab executable (PATH lookup when no slash) */
	const char *tcl_dir;            /* directory holding vu9p_bridge.tcl / vu9p_program.tcl */
	const char *hw_server;          /* host:port of the Xilinx hw_server, default 127.0.0.1:3121 */
	const char *log_dir;            /* where bridge/program logs go */
	int      io_timeout_ms;         /* per-command bridge timeout */
	int      tck_hz;                /* native JTAG clock (default 15 MHz) */
};

extern struct vu9p_dev g_vu9p_devs[VU9P_MAX_DEVICES];
extern int g_vu9p_count;

/* default_transport decides what a bare SERIAL[:port] entry means (--vu9p-mode bridge|direct);
 * explicit prefixes (host:port, jtag:, ftdi:) always win. */
int  vu9p_parse_devices(const char *spec, int default_transport);  /* fills g_vu9p_devs; returns count or -1 */
int  vu9p_program(struct vu9p_dev *d, const char *bitstream, const struct vu9p_tools *t);   /* 0 ok */
int  vu9p_spawn_bridge(struct vu9p_dev *d, const struct vu9p_tools *t);                      /* 0 ok */
int  vu9p_connect(struct vu9p_dev *d, const struct vu9p_tools *t);                           /* 0 ok */
void vu9p_close(struct vu9p_dev *d);
void vu9p_shutdown_all(void);

int  vu9p_rd(struct vu9p_dev *d, uint32_t addr, uint32_t *val);
int  vu9p_wr(struct vu9p_dev *d, uint32_t addr, uint32_t val);
int  vu9p_rb(struct vu9p_dev *d, uint32_t addr, uint32_t *vals, int n);     /* n <= 64 */
int  vu9p_wb(struct vu9p_dev *d, uint32_t addr, const uint32_t *vals, int n);
int  vu9p_sensors(struct vu9p_dev *d);                                        /* updates d->temp_c etc. */
int  vu9p_ping(struct vu9p_dev *d, uint32_t *id);

#endif /* VU9P_BRIDGE_H */
