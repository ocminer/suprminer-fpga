/* vu9p_jtag.h - native JTAG transport for VU9P boards: the miner drives the board's FTDI
 * JTAG cable itself (platform/ftdi_mpsse.c) and talks to the bitstream's BSCANE2 USER1
 * register bus (rtl/b2b_jtag_axi.sv: 64-bit DR = request in, response out).  No Vivado,
 * no hw_server, no bridge process.  Also programs the FPGA over JTAG (JPROGRAM / CFG_IN / JSTART).
 *
 * Device spec: ftdi:SERIAL[A-D]  (USB serial of the cable, channel letter as hw_server shows it).
 */
#ifndef VU9P_JTAG_H
#define VU9P_JTAG_H

#include <stdint.h>
#include "vu9p_bridge.h"

int  vu9p_jtag_open(struct vu9p_dev *d, int tck_hz);          /* open cable, check IDCODE and the register bus */
void vu9p_jtag_close(struct vu9p_dev *d);
int  vu9p_jtag_rd(struct vu9p_dev *d, uint32_t addr, uint32_t *val);
int  vu9p_jtag_wr(struct vu9p_dev *d, uint32_t addr, uint32_t val);
int  vu9p_jtag_rb(struct vu9p_dev *d, uint32_t addr, uint32_t *vals, int n);
int  vu9p_jtag_wb(struct vu9p_dev *d, uint32_t addr, const uint32_t *vals, int n);
int  vu9p_jtag_sensors(struct vu9p_dev *d);
int  vu9p_jtag_program(struct vu9p_dev *d, const char *bitfile);  /* needs the cable open (vu9p_jtag_open_cable) */
int  vu9p_jtag_open_cable(struct vu9p_dev *d, int tck_hz);     /* cable only, no bus check (before programming) */
int  vu9p_jtag_check_bus(struct vu9p_dev *d);                  /* IDCODE + USER1 magic */

/* register bus local registers (served by b2b_jtag_axi, not by the design's AXI slave) */
#define VU9P_JTAG_REG_MAGIC    0xF00
#define VU9P_JTAG_REG_TEMP     0xF04
#define VU9P_JTAG_REG_VCCINT   0xF08
#define VU9P_JTAG_REG_VCCAUX   0xF0C
#define VU9P_JTAG_REG_VCCBRAM  0xF10
#define VU9P_JTAG_REG_UPTIME   0xF14
#define VU9P_JTAG_REG_CTRLKHZ  0xF18
#define VU9P_JTAG_MAGIC        0x4A544147u

#endif /* VU9P_JTAG_H */
