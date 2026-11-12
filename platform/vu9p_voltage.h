#ifndef VU9P_VOLTAGE_H
#define VU9P_VOLTAGE_H
/* vu9p_voltage.h - VU9P core voltage (VCCINT) setpoint through NextJTAG and the board BMC (BCU-1525 and
 * similar). The setpoint survives bitstream loads until the board is power cycled, so it is applied once per
 * boot, right before programming: NextJTAG's BMC setup (-B) may load a helper image. */
#include <stdbool.h>
#include "vu9p_bridge.h"

#define VU9P_VCCINT_DEFAULT 0.720   /* --vu9p-voltage default (AMD low-voltage mode 0.698-0.742 V) */
#define VU9P_VCCINT_MIN     0.698
#define VU9P_VCCINT_MAX     0.876

struct vu9p_voltage_tools {
	const char *nextjtag;        /* NextJTAG executable (PATH lookup when no slash), default "nextjtag" */
	const char *license;         /* NEXTJTAG_LICENSE file, NULL = inherit the environment */
	const char *log_dir;
	const char *state_dir;       /* per-boot record, NULL = $XDG_RUNTIME_DIR (or /run/user/<uid>)/suprminer-fpga, else /tmp/suprminer-fpga-<uid> */
};

/* result codes of vu9p_set_vccint */
#define VU9P_VCCINT_SET        0     /* written and both regulator phases read back within 5 mV */
#define VU9P_VCCINT_ALREADY    1     /* already set to this value since the last boot */
#define VU9P_VCCINT_NO_TOOL   -2     /* NextJTAG not found */
#define VU9P_VCCINT_BUSY      -3     /* cable held by another program (Vivado hw_server?) */
#define VU9P_VCCINT_FAILED    -1

int  vu9p_set_vccint(const struct vu9p_dev *d, double volts, const struct vu9p_voltage_tools *t);
bool vu9p_vccint_is_set(const struct vu9p_dev *d, double volts, const struct vu9p_voltage_tools *t);   /* recorded this boot */

/* helpers (unit tested) */
int  vu9p_vccint_ftdi_serial(const char *serial, char *out, int outlen);   /* strip the channel letter A-D */
int  vu9p_vccint_parse(const char *out, double volts, double *ph0, double *ph1);   /* 0 = confirmed */
bool vu9p_vccint_cable_busy(const char *out);
#endif
