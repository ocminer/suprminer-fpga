/* ftdi_mpsse.h - minimal FTDI MPSSE JTAG master over libusb-1.0 (no libftdi needed).
 *
 * Drives the JTAG port of FT2232H / FT4232H / FT232H cables (the BCU-1525 has an
 * FT4232H whose channel A is the FPGA's JTAG). Pin assignment is the usual one:
 * ADBUS0 TCK, ADBUS1 TDI, ADBUS2 TDO, ADBUS3 TMS.
 */
#ifndef FTDI_MPSSE_H
#define FTDI_MPSSE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct libusb_context;
struct libusb_device_handle;

struct mpsse {
	struct libusb_context *ctx;
	struct libusb_device_handle *h;
	int      iface;                 /* 0 = channel A */
	uint8_t  ep_out, ep_in;
	uint16_t max_packet;
	uint8_t *obuf;                  /* queued MPSSE commands */
	size_t   olen, ocap;
	size_t   expect_in;             /* bytes the queued commands will return */
	char     serial[64];
	int      tck_hz;
};

/* serial: the USB serial string, optionally with the channel letter appended (e.g. "214302895021A"). */
int  mpsse_open(struct mpsse *m, const char *serial, int tck_hz);
void mpsse_close(struct mpsse *m);
int  mpsse_flush(struct mpsse *m, uint8_t *in, size_t inlen);   /* send queued commands, read inlen reply bytes */

/* JTAG primitives (queued; results come back from mpsse_flush in command order) */
void mpsse_tms(struct mpsse *m, const uint8_t *bits, int nbits, int tdi);   /* <= 7 bits per call, LSB first */
void mpsse_tms_seq(struct mpsse *m, uint32_t seq, int nbits);               /* up to 32 bits, LSB first */
/* Shift nbits of tdi (LSB first); if last, the final bit is clocked with TMS=1 (leaves Shift-xR).
 * TDO bits are returned by mpsse_flush: mpsse_shift_reply_len() bytes; decode with mpsse_shift_decode(). */
void   mpsse_shift(struct mpsse *m, const uint8_t *tdi, int nbits, bool last);
size_t mpsse_shift_reply_len(int nbits, bool last);
void   mpsse_shift_decode(const uint8_t *reply, uint8_t *tdo, int nbits, bool last);
void mpsse_clock(struct mpsse *m, int ncycles);                             /* TCK cycles with TMS/TDI idle */

/* TAP helpers (queue + flush where a reply is needed) */
int  jtag_reset_to_idle(struct mpsse *m);
int  jtag_scan_ir(struct mpsse *m, uint32_t ir, int irlen, uint32_t *captured);
/* DR scan from Run-Test/Idle back to Run-Test/Idle: tdi/tdo nbits (LSB first) */
int  jtag_scan_dr(struct mpsse *m, const uint8_t *tdi, uint8_t *tdo, int nbits);

#endif /* FTDI_MPSSE_H */
