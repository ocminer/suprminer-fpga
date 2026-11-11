/* ftdi_mpsse.c - FTDI MPSSE JTAG over libusb-1.0.  See ftdi_mpsse.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>

#include "miner.h"
#include "ftdi_mpsse.h"

/* FTDI vendor requests */
#define SIO_RESET            0x00
#define SIO_SET_LATENCY      0x09
#define SIO_SET_BITMODE      0x0B
#define SIO_RESET_SIO        0
#define SIO_RESET_PURGE_RX   1
#define SIO_RESET_PURGE_TX   2
#define BITMODE_RESET        0x00
#define BITMODE_MPSSE        0x02
/* MPSSE opcodes */
#define MPSSE_WRITE_NEG      0x01
#define MPSSE_BITMODE        0x02
#define MPSSE_READ_NEG       0x04
#define MPSSE_LSB            0x08
#define MPSSE_DO_WRITE       0x10
#define MPSSE_DO_READ        0x20
#define MPSSE_WRITE_TMS      0x40
#define SET_BITS_LOW         0x80
#define SET_BITS_HIGH        0x82
#define TCK_DIVISOR          0x86
#define SEND_IMMEDIATE       0x87
#define DIS_DIV_5            0x8A
#define DIS_ADAPTIVE         0x97
#define DIS_3PHASE           0x8D
#define CLK_BYTES            0x8F

#define PIN_TCK 0x01
#define PIN_TDI 0x02
#define PIN_TDO 0x04
#define PIN_TMS 0x08

static const uint16_t FTDI_PIDS[] = { 0x6011, 0x6010, 0x6014, 0 };

static int ctrl(struct mpsse *m, uint8_t req, uint16_t val, uint16_t idx)
{
	return libusb_control_transfer(m->h, 0x40, req, val, idx, NULL, 0, 1000) < 0 ? -1 : 0;
}

static void queue(struct mpsse *m, const uint8_t *d, size_t n)
{
	if (m->olen + n > m->ocap) {
		size_t cap = m->ocap ? m->ocap * 2 : 65536;
		while (cap < m->olen + n) cap *= 2;
		m->obuf = (uint8_t *) realloc(m->obuf, cap);
		m->ocap = cap;
	}
	memcpy(m->obuf + m->olen, d, n);
	m->olen += n;
}

static int write_all(struct mpsse *m, const uint8_t *d, size_t n)
{
	while (n) {
		int xfer = 0, chunk = n > 65536 ? 65536 : (int) n;
		int rc = libusb_bulk_transfer(m->h, m->ep_out, (unsigned char *) d, chunk, &xfer, 5000);
		if (rc || xfer <= 0) { applog(LOG_ERR, "mpsse %s: usb write failed (%s)", m->serial, libusb_error_name(rc)); return -1; }
		d += xfer; n -= xfer;
	}
	return 0;
}

/* read n payload bytes; every USB packet starts with 2 modem-status bytes that are stripped */
static int read_all(struct mpsse *m, uint8_t *d, size_t n)
{
	uint8_t pkt[4096];
	int idle = 0;
	while (n) {
		int xfer = 0, want = (int)(n + 2 * ((n + m->max_packet - 3) / (m->max_packet - 2)));
		int rc;
		if (want > (int) sizeof(pkt)) want = sizeof(pkt);
		rc = libusb_bulk_transfer(m->h, m->ep_in, pkt, want, &xfer, 2000);
		if (rc && rc != LIBUSB_ERROR_TIMEOUT) { applog(LOG_ERR, "mpsse %s: usb read failed (%s)", m->serial, libusb_error_name(rc)); return -1; }
		if (xfer <= 2) { if (++idle > 50) { applog(LOG_ERR, "mpsse %s: usb read timeout (%zu bytes missing)", m->serial, n); return -1; } continue; }
		idle = 0;
		{
			int off = 0;
			while (off < xfer && n) {
				int seg = xfer - off; if (seg > m->max_packet) seg = m->max_packet;
				int payload = seg - 2; if (payload > (int) n) payload = (int) n;
				if (payload > 0) { memcpy(d, pkt + off + 2, payload); d += payload; n -= payload; }
				off += seg;
			}
		}
	}
	return 0;
}

int mpsse_flush(struct mpsse *m, uint8_t *in, size_t inlen)
{
	uint8_t si = SEND_IMMEDIATE;
	int rc;
	if (inlen) queue(m, &si, 1);
	rc = m->olen ? write_all(m, m->obuf, m->olen) : 0;
	m->olen = 0; m->expect_in = 0;
	if (rc) return -1;
	if (inlen && read_all(m, in, inlen)) return -1;
	return 0;
}

int mpsse_open(struct mpsse *m, const char *serial, int tck_hz)
{
	libusb_device **list = NULL;
	ssize_t n, i;
	int found = 0, iface = 0;
	char want[64];
	size_t wl;
	uint8_t init[32]; int k = 0; int div;

	memset(m, 0, sizeof(*m));
	snprintf(m->serial, sizeof(m->serial), "%s", serial);
	snprintf(want, sizeof(want), "%s", serial);
	wl = strlen(want);
	if (wl > 1 && want[wl - 1] >= 'A' && want[wl - 1] <= 'D') { iface = want[wl - 1] - 'A'; want[wl - 1] = 0; }
	if (libusb_init(&m->ctx)) { applog(LOG_ERR, "mpsse: libusb_init failed"); return -1; }
	n = libusb_get_device_list(m->ctx, &list);
	for (i = 0; i < n && !found; i++) {
		struct libusb_device_descriptor dd;
		libusb_device_handle *h;
		char s[64] = "";
		int p;
		if (libusb_get_device_descriptor(list[i], &dd) || dd.idVendor != 0x0403) continue;
		for (p = 0; FTDI_PIDS[p] && FTDI_PIDS[p] != dd.idProduct; p++) ;
		if (!FTDI_PIDS[p]) continue;
		if (libusb_open(list[i], &h)) continue;
		if (dd.iSerialNumber) libusb_get_string_descriptor_ascii(h, dd.iSerialNumber, (unsigned char *) s, sizeof(s));
		if (!strcmp(s, want) || !strcmp(s, serial)) { m->h = h; found = 1; break; }
		libusb_close(h);
	}
	libusb_free_device_list(list, 1);
	if (!found) { applog(LOG_ERR, "mpsse: no FTDI device with serial %s", want); libusb_exit(m->ctx); m->ctx = NULL; return -1; }
	m->iface = iface;
	m->ep_out = (uint8_t)(0x02 + 2 * iface);
	m->ep_in = (uint8_t)(0x81 + 2 * iface);
	m->max_packet = 512;
	libusb_set_auto_detach_kernel_driver(m->h, 1);
	{	/* another tool (Vivado hw_server) may hold the cable for a moment: retry for a few seconds */
		int tries = 0, rc;
		while ((rc = libusb_claim_interface(m->h, iface)) != 0 && ++tries < 20) usleep(250000);
		if (rc) {
		applog(LOG_ERR, "mpsse %s: cannot claim USB interface %d (another program holds the cable: Vivado hw_server?)", serial, iface);
		libusb_close(m->h); m->h = NULL; libusb_exit(m->ctx); m->ctx = NULL; return -1;
		}
	}
	if (ctrl(m, SIO_RESET, SIO_RESET_SIO, iface + 1) || ctrl(m, SIO_SET_LATENCY, 2, iface + 1) ||
	    ctrl(m, SIO_SET_BITMODE, 0x0000 | (BITMODE_RESET << 8), iface + 1) ||
	    ctrl(m, SIO_SET_BITMODE, (BITMODE_MPSSE << 8) | 0x0B, iface + 1) ||
	    ctrl(m, SIO_RESET, SIO_RESET_PURGE_RX, iface + 1) || ctrl(m, SIO_RESET, SIO_RESET_PURGE_TX, iface + 1)) {
		applog(LOG_ERR, "mpsse %s: FTDI setup failed", serial);
		mpsse_close(m); return -1;
	}
	/* MPSSE: 60 MHz base, no div-by-5, no adaptive clocking, no 3-phase; TCK = 60 MHz / (2 * (div + 1)) */
	if (tck_hz <= 0) tck_hz = 15000000;
	div = 30000000 / tck_hz - 1; if (div < 0) div = 0; if (div > 65535) div = 65535;
	m->tck_hz = 30000000 / (div + 1);
	init[k++] = DIS_DIV_5; init[k++] = DIS_ADAPTIVE; init[k++] = DIS_3PHASE;
	init[k++] = TCK_DIVISOR; init[k++] = (uint8_t) div; init[k++] = (uint8_t)(div >> 8);
	init[k++] = SET_BITS_LOW; init[k++] = PIN_TMS; init[k++] = PIN_TCK | PIN_TDI | PIN_TMS;   /* TMS high, TCK low */
	init[k++] = SET_BITS_HIGH; init[k++] = 0x00; init[k++] = 0x00;
	queue(m, init, k);
	if (mpsse_flush(m, NULL, 0)) { mpsse_close(m); return -1; }
	{	/* a bad opcode (0xAA) must be answered with 0xFA 0xAA: proves MPSSE mode */
		uint8_t bad = 0xAA, rep[2] = {0, 0};
		queue(m, &bad, 1);
		if (mpsse_flush(m, rep, 2) || rep[0] != 0xFA || rep[1] != 0xAA) {
			applog(LOG_ERR, "mpsse %s: MPSSE sync failed (%02x %02x)", serial, rep[0], rep[1]);
			mpsse_close(m); return -1;
		}
	}
	applog(LOG_INFO, "mpsse %s: channel %c open, TCK %.1f MHz", serial, 'A' + iface, m->tck_hz / 1e6);
	return 0;
}

void mpsse_close(struct mpsse *m)
{
	if (m->h) {
		uint8_t rst[3] = { SET_BITS_LOW, 0x00, 0x00 };
		queue(m, rst, 3); mpsse_flush(m, NULL, 0);
		ctrl(m, SIO_SET_BITMODE, 0x0000 | (BITMODE_RESET << 8), m->iface + 1);
		libusb_release_interface(m->h, m->iface);
		libusb_close(m->h); m->h = NULL;
	}
	if (m->ctx) { libusb_exit(m->ctx); m->ctx = NULL; }
	free(m->obuf); m->obuf = NULL; m->olen = m->ocap = 0;
}

/* ---- JTAG primitives ----------------------------------------------------- */
void mpsse_tms(struct mpsse *m, const uint8_t *bits, int nbits, int tdi)
{
	uint8_t c[3];
	c[0] = MPSSE_WRITE_TMS | MPSSE_LSB | MPSSE_BITMODE | MPSSE_WRITE_NEG;
	c[1] = (uint8_t)(nbits - 1);
	c[2] = (uint8_t)((bits[0] & 0x7F) | (tdi ? 0x80 : 0));
	queue(m, c, 3);
}

void mpsse_tms_seq(struct mpsse *m, uint32_t seq, int nbits)
{
	while (nbits > 0) {
		int n = nbits > 7 ? 7 : nbits;
		uint8_t b = (uint8_t)(seq & 0x7F);
		mpsse_tms(m, &b, n, 0);
		seq >>= n; nbits -= n;
	}
}

size_t mpsse_shift_reply_len(int nbits, bool last)
{
	int body = last ? nbits - 1 : nbits;
	size_t n = (size_t)(body / 8) + ((body % 8) ? 1 : 0);
	return n + (last ? 1 : 0);
}

void mpsse_shift(struct mpsse *m, const uint8_t *tdi, int nbits, bool last)
{
	int body = last ? nbits - 1 : nbits;
	int nbytes = body / 8, rem = body % 8;
	uint8_t c[3];
	if (nbytes) {
		c[0] = MPSSE_DO_WRITE | MPSSE_DO_READ | MPSSE_LSB | MPSSE_WRITE_NEG;
		c[1] = (uint8_t)((nbytes - 1) & 0xFF); c[2] = (uint8_t)((nbytes - 1) >> 8);
		queue(m, c, 3); queue(m, tdi, nbytes);
	}
	if (rem) {
		c[0] = MPSSE_DO_WRITE | MPSSE_DO_READ | MPSSE_LSB | MPSSE_BITMODE | MPSSE_WRITE_NEG;
		c[1] = (uint8_t)(rem - 1); c[2] = tdi[nbytes];
		queue(m, c, 3);
	}
	if (last) {
		int lastbit = (tdi[(nbits - 1) / 8] >> ((nbits - 1) % 8)) & 1;
		c[0] = MPSSE_WRITE_TMS | MPSSE_DO_READ | MPSSE_LSB | MPSSE_BITMODE | MPSSE_WRITE_NEG;
		c[1] = 0; c[2] = (uint8_t)(0x01 | (lastbit ? 0x80 : 0));      /* TMS=1 with the last TDI bit */
		queue(m, c, 3);
	}
}

void mpsse_shift_decode(const uint8_t *reply, uint8_t *tdo, int nbits, bool last)
{
	int body = last ? nbits - 1 : nbits;
	int nbytes = body / 8, rem = body % 8, i;
	memset(tdo, 0, (nbits + 7) / 8);
	for (i = 0; i < nbytes; i++) tdo[i] = reply[i];
	if (rem) tdo[nbytes] = reply[nbytes] >> (8 - rem);                 /* partial byte arrives left-aligned */
	if (last) {
		int lastbit = (reply[nbytes + (rem ? 1 : 0)] >> 7) & 1;
		tdo[(nbits - 1) / 8] |= (uint8_t)(lastbit << ((nbits - 1) % 8));
	}
}

void mpsse_clock(struct mpsse *m, int ncycles)
{
	uint8_t c[3];
	while (ncycles >= 8) {
		int nbytes = ncycles / 8; if (nbytes > 65536) nbytes = 65536;
		c[0] = CLK_BYTES; c[1] = (uint8_t)((nbytes - 1) & 0xFF); c[2] = (uint8_t)((nbytes - 1) >> 8);
		queue(m, c, 3); ncycles -= nbytes * 8;
	}
	if (ncycles > 0) { uint8_t z = 0; mpsse_tms(m, &z, ncycles, 0); }   /* TMS=0 cycles keep the TAP in RTI */
}

/* ---- TAP ----------------------------------------------------------------- */
int jtag_reset_to_idle(struct mpsse *m)
{
	mpsse_tms_seq(m, 0x1F, 5);      /* 5 x TMS=1: Test-Logic-Reset */
	mpsse_tms_seq(m, 0x00, 1);      /* -> Run-Test/Idle */
	return mpsse_flush(m, NULL, 0);
}

int jtag_scan_ir(struct mpsse *m, uint32_t ir, int irlen, uint32_t *captured)
{
	uint8_t tdi[4], tdo[4] = {0, 0, 0, 0}, reply[8];
	size_t rl = mpsse_shift_reply_len(irlen, true);
	int i;
	for (i = 0; i < 4; i++) tdi[i] = (uint8_t)(ir >> (8 * i));
	mpsse_tms_seq(m, 0x03, 4);      /* RTI -> SelDR -> SelIR -> CapIR -> ShiftIR (TMS 1,1,0,0) */
	mpsse_shift(m, tdi, irlen, true);
	mpsse_tms_seq(m, 0x01, 2);      /* Exit1-IR -> Update-IR -> RTI (TMS 1,0) */
	if (mpsse_flush(m, reply, rl)) return -1;
	mpsse_shift_decode(reply, tdo, irlen, true);
	if (captured) *captured = tdo[0] | (tdo[1] << 8) | (tdo[2] << 16) | ((uint32_t) tdo[3] << 24);
	return 0;
}

int jtag_scan_dr(struct mpsse *m, const uint8_t *tdi, uint8_t *tdo, int nbits)
{
	size_t rl = mpsse_shift_reply_len(nbits, true);
	uint8_t *reply = (uint8_t *) malloc(rl);
	if (!reply) return -1;
	mpsse_tms_seq(m, 0x01, 3);      /* RTI -> SelDR -> CapDR -> ShiftDR (TMS 1,0,0) */
	mpsse_shift(m, tdi, nbits, true);
	mpsse_tms_seq(m, 0x01, 2);      /* Exit1-DR -> Update-DR -> RTI */
	if (mpsse_flush(m, reply, rl)) { free(reply); return -1; }
	if (tdo) mpsse_shift_decode(reply, tdo, nbits, true);
	free(reply);
	return 0;
}
