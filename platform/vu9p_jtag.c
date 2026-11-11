/* vu9p_jtag.c - native JTAG transport (FTDI MPSSE) for the b2b_jtag_axi register bus.  See vu9p_jtag.h.
 *
 * One USER1 scan = 64 bits in / 64 bits out.  Request: [31:0] wdata, [43:32] address, [62] read, [63] write.
 * Response: [31:0] rdata, [39:32] ack counter, [40] busy, [41] error, [63:48] magic 0x4A54.
 * The response of scan N belongs to the request of scan N-1, so a read is "request, dummy" and a block
 * of n writes is "n requests, dummy" with the ack counter checked to have advanced by n.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "miner.h"
#include "ftdi_mpsse.h"
#include "vu9p_jtag.h"

#define IR_BITS      6                /* per SLR; an SSI device presents 6 bits per SLR (XCVU9P: 18) */
#define IR_IDCODE    0x09
#define IR_USER1     0x02
#define IR_JPROGRAM  0x0B
#define IR_CFG_IN    0x05
#define IR_JSTART    0x0C
#define IR_ISC_NOOP  0x14
#define IR_BYPASS    0x3F
#define IDCODE_VU9P  0x04B31093u      /* XCVU9P, revision bits masked */

#define SCAN_BITS    64
#define SCAN_IDLE    32               /* TCK cycles in Run-Test/Idle after each scan: lets the request complete */
#define RSP_MAGIC    0x4A54u

struct vu9p_jtag {
	struct mpsse m;
	int  user1_loaded;
	uint8_t ack;                      /* last seen ack counter */
	int  nslr;                        /* IR fields (SLRs) on the chain, from the IDCODE */
	int  bus_field;                   /* IR field whose USER1 answers with the register bus magic */
};

/* Measured on an XCVU9P (3 SLRs): the IR is 18 bits = 3 fields of 6, the field shifted in LAST (highest
 * bits) belongs to the configuration master SLR, and the data register is that SLR's register alone
 * (no extra bypass bits from the slaves).  The other fields get BYPASS. */
static int ir_len(struct vu9p_jtag *j) { return IR_BITS * (j->nslr > 0 ? j->nslr : 1); }
static uint32_t ir_word(struct vu9p_jtag *j, uint32_t op, int field)
{
	uint32_t w = 0; int f, n = j->nslr > 0 ? j->nslr : 1;
	for (f = 0; f < n; f++) w |= (f == field ? op : (uint32_t) IR_BYPASS) << (IR_BITS * f);
	return w;
}
static int master_field(struct vu9p_jtag *j) { return (j->nslr > 0 ? j->nslr : 1) - 1; }

static struct vu9p_jtag *J(struct vu9p_dev *d) { return (struct vu9p_jtag *) d->jtag; }

static void fail(struct vu9p_dev *d)
{
	/* the miner thread sees fd < 0 and reconnects (vu9p_connect reopens the cable) */
	if (d->fd >= 0) applog(LOG_ERR, "VU9P %d: JTAG transport failure, will reopen the cable", d->index);
	d->fd = -1;
	J(d)->user1_loaded = 0;
}

/* ---- scans ------------------------------------------------------------------- */
static size_t scan_reply_len(void) { return mpsse_shift_reply_len(SCAN_BITS, true); }

static void queue_scan(struct mpsse *m, uint64_t req)
{
	uint8_t tdi[8]; int i;
	for (i = 0; i < 8; i++) tdi[i] = (uint8_t)(req >> (8 * i));
	mpsse_tms_seq(m, 0x01, 3);                 /* RTI -> Select-DR -> Capture-DR -> Shift-DR */
	mpsse_shift(m, tdi, SCAN_BITS, true);
	mpsse_tms_seq(m, 0x01, 2);                 /* Exit1-DR -> Update-DR -> RTI */
	mpsse_clock(m, SCAN_IDLE);
}

static uint64_t decode_scan(const uint8_t *reply)
{
	uint8_t tdo[8]; uint64_t v = 0; int i;
	mpsse_shift_decode(reply, tdo, SCAN_BITS, true);
	for (i = 7; i >= 0; i--) v = (v << 8) | tdo[i];
	return v;
}

static inline uint64_t req_read(uint32_t addr) { return (1ULL << 62) | ((uint64_t)(addr & 0xFFF) << 32); }
static inline uint64_t req_write(uint32_t addr, uint32_t v) { return (1ULL << 63) | ((uint64_t)(addr & 0xFFF) << 32) | v; }
static inline int rsp_ok(uint64_t r) { return ((r >> 48) & 0xFFFF) == RSP_MAGIC && !((r >> 40) & 1) && !((r >> 41) & 1); }
static inline uint8_t rsp_ack(uint64_t r) { return (uint8_t)(r >> 32); }

static int ensure_user1(struct vu9p_dev *d)
{
	struct vu9p_jtag *j = J(d);
	uint32_t cap = 0;
	if (j->user1_loaded) return 0;
	if (jtag_scan_ir(&j->m, ir_word(j, IR_USER1, j->bus_field), ir_len(j), &cap)) { fail(d); return -1; }
	if ((cap & 0x3) != 0x1) { applog(LOG_ERR, "VU9P %d: unexpected IR capture %05x (no FPGA on the chain?)", d->index, cap); fail(d); return -1; }
	j->user1_loaded = 1;
	return 0;
}

/* n requests followed by one dummy scan; responses[i] (i = 1..n) answer requests[i-1] */
static int run_scans(struct vu9p_dev *d, const uint64_t *reqs, int n, uint64_t *rsps)
{
	struct vu9p_jtag *j = J(d);
	size_t rl = scan_reply_len();
	uint8_t *reply;
	int i;
	if (ensure_user1(d)) return -1;
	reply = (uint8_t *) malloc(rl * (n + 1));
	if (!reply) return -1;
	for (i = 0; i < n; i++) queue_scan(&j->m, reqs[i]);
	queue_scan(&j->m, 0);
	if (mpsse_flush(&j->m, reply, rl * (n + 1))) { free(reply); fail(d); return -1; }
	for (i = 0; i <= n; i++) rsps[i] = decode_scan(reply + rl * i);
	free(reply);
	for (i = 1; i <= n; i++) {
		if (((rsps[i] >> 48) & 0xFFFF) != RSP_MAGIC) {
			if (j->user1_loaded == 1 && d->fd >= 0 && rsps[i] != 0)
				applog(LOG_ERR, "VU9P %d: register bus lost (response %016llx)", d->index, (unsigned long long) rsps[i]);
			j->user1_loaded = 0;
			return -1;
		}
	}
	j->ack = rsp_ack(rsps[n]);
	return 0;
}

int vu9p_jtag_rb(struct vu9p_dev *d, uint32_t addr, uint32_t *vals, int n)
{
	uint64_t reqs[64], rsps[65];
	int i, tries;
	if (n < 1 || n > 64) return -1;
	for (tries = 0; tries < 3; tries++) {
		for (i = 0; i < n; i++) reqs[i] = req_read(addr + 4 * i);
		if (run_scans(d, reqs, n, rsps)) return -1;
		for (i = 1; i <= n; i++) if (!rsp_ok(rsps[i])) break;
		if (i > n) { for (i = 0; i < n; i++) vals[i] = (uint32_t) rsps[i + 1]; return 0; }
	}
	applog(LOG_ERR, "VU9P %d: read %03x..: bus busy/error after retries", d->index, addr);
	return -1;
}

int vu9p_jtag_rd(struct vu9p_dev *d, uint32_t addr, uint32_t *val) { return vu9p_jtag_rb(d, addr, val, 1); }

int vu9p_jtag_wb(struct vu9p_dev *d, uint32_t addr, const uint32_t *vals, int n)
{
	int off;
	for (off = 0; off < n; off += 32) {
		uint64_t reqs[32], rsps[33];
		int cnt = (n - off < 32) ? n - off : 32, i, tries;
		for (tries = 0; tries < 3; tries++) {
			uint8_t ack0;
			for (i = 0; i < cnt; i++) reqs[i] = req_write(addr + 4 * (off + i), vals[off + i]);
			if (run_scans(d, reqs, cnt, rsps)) return -1;
			ack0 = rsp_ack(rsps[0]);
			if (rsp_ok(rsps[cnt]) && (uint8_t)(ack0 + cnt) == rsp_ack(rsps[cnt])) break;
			/* some request was dropped (bus busy at its update): redo this block */
			applog(LOG_WARNING, "VU9P %d: write block %03x: ack %u -> %u (expected +%d), retrying", d->index,
			       addr + 4 * off, ack0, rsp_ack(rsps[cnt]), cnt);
		}
		if (tries == 3) return -1;
	}
	return 0;
}

int vu9p_jtag_wr(struct vu9p_dev *d, uint32_t addr, uint32_t val) { return vu9p_jtag_wb(d, addr, &val, 1); }

int vu9p_jtag_sensors(struct vu9p_dev *d)
{
	uint32_t v[4];
	if (vu9p_jtag_rb(d, VU9P_JTAG_REG_TEMP, v, 4)) return -1;
	/* UltraScale+ SYSMON transfer functions (on-chip reference) */
	d->temp_c   = (v[0] & 0xFFFF) * 509.3140064 / 65536.0 - 280.23087870;
	d->vccint_v = (v[1] & 0xFFFF) * 3.0 / 65536.0;
	d->vccaux_v = (v[2] & 0xFFFF) * 3.0 / 65536.0;
	d->vccbram_v = (v[3] & 0xFFFF) * 3.0 / 65536.0;
	return 0;
}

/* ---- cable / chain ------------------------------------------------------------ */
int vu9p_jtag_open_cable(struct vu9p_dev *d, int tck_hz)
{
	struct vu9p_jtag *j = J(d);
	uint32_t idcode = 0, cap = 0;
	uint8_t z[4] = {0, 0, 0, 0}, id[4];
	if (!j) { j = (struct vu9p_jtag *) calloc(1, sizeof(*j)); if (!j) return -1; d->jtag = j; }
	if (j->m.h) mpsse_close(&j->m);
	j->user1_loaded = 0;
	if (mpsse_open(&j->m, d->serial, tck_hz)) return -1;
	/* after Test-Logic-Reset the master SLR selects IDCODE by itself */
	if (jtag_reset_to_idle(&j->m) || jtag_scan_dr(&j->m, z, id, 32)) { mpsse_close(&j->m); return -1; }
	idcode = id[0] | (id[1] << 8) | (id[2] << 16) | ((uint32_t) id[3] << 24);
	j->nslr = ((idcode & 0x0FFFFFFF) == IDCODE_VU9P) ? 3 : 1;
	j->bus_field = master_field(j);
	if ((idcode & 0x0FFFFFFF) != IDCODE_VU9P)
		applog(LOG_WARNING, "VU9P %d: JTAG IDCODE %08x is not an XCVU9P (%08x); assuming a single-SLR 6-bit IR", d->index, idcode, IDCODE_VU9P);
	if (jtag_scan_ir(&j->m, ir_word(j, IR_IDCODE, master_field(j)), ir_len(j), &cap)) { mpsse_close(&j->m); return -1; }
	applog(LOG_INFO, "VU9P %d: JTAG cable %s: IDCODE %08x, %d SLR field%s, IR capture %05x", d->index, d->serial, idcode,
	       j->nslr, j->nslr == 1 ? "" : "s", cap);
	d->fd = 1000000 + d->index;       /* "connected" for the miner thread */
	return 0;
}

int vu9p_jtag_check_bus(struct vu9p_dev *d)
{
	struct vu9p_jtag *j = J(d);
	uint32_t magic = 0;
	int f, n = j->nslr > 0 ? j->nslr : 1;
	/* the BSCANE2 of the design may sit in any SLR: try the master field first, then the others */
	for (f = 0; f < n; f++) {
		int field = (master_field(j) + n - f) % n;
		j->bus_field = field; j->user1_loaded = 0;
		if (vu9p_jtag_rd(d, VU9P_JTAG_REG_MAGIC, &magic) == 0 && magic == VU9P_JTAG_MAGIC) {
			if (field != master_field(j)) applog(LOG_INFO, "VU9P %d: register bus found on IR field %d", d->index, field);
			return 0;
		}
		if (d->fd < 0) return -1;      /* transport failure, not a missing bus */
	}
	j->bus_field = master_field(j); j->user1_loaded = 0;
	applog(LOG_ERR, "VU9P %d: no register bus on USER1 (last read %08x, expected %08x): is a native-JTAG bitstream loaded? (--program)",
	       d->index, magic, VU9P_JTAG_MAGIC);
	return -1;
}

int vu9p_jtag_open(struct vu9p_dev *d, int tck_hz)
{
	if (vu9p_jtag_open_cable(d, tck_hz)) return -1;
	if (vu9p_jtag_check_bus(d)) { d->fd = -1; return -1; }
	if (vu9p_jtag_sensors(d) == 0)
		applog(LOG_INFO, "VU9P %d: register bus up, %.1f C, VCCINT %.3f V", d->index, d->temp_c, d->vccint_v);
	return 0;
}

void vu9p_jtag_close(struct vu9p_dev *d)
{
	struct vu9p_jtag *j = J(d);
	if (!j) return;
	if (j->m.h) {
		jtag_reset_to_idle(&j->m);
		mpsse_close(&j->m);
	}
	free(j); d->jtag = NULL; d->fd = -1;
}

/* ---- programming ----------------------------------------------------------------- */
static const uint8_t *bit_payload(const uint8_t *buf, size_t len, size_t *dlen, char *part, size_t partlen)
{
	/* Xilinx .bit: 2-byte length + 9-byte magic, 2-byte 0x0001, then records a,b,c,d (16-bit length), e (32-bit length) */
	size_t off = 0;
	if (len < 16) return NULL;
	off = 2 + ((buf[0] << 8) | buf[1]);
	if (off + 2 > len) return NULL;
	off += 2;
	while (off + 1 < len) {
		uint8_t key = buf[off++];
		if (key == 'e') {
			uint32_t n;
			if (off + 4 > len) return NULL;
			n = ((uint32_t) buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
			off += 4;
			if (off + n > len) return NULL;
			*dlen = n;
			return buf + off;
		} else {
			size_t n;
			if (off + 2 > len) return NULL;
			n = (buf[off] << 8) | buf[off + 1]; off += 2;
			if (off + n > len) return NULL;
			if (key == 'b' && part) snprintf(part, partlen, "%.*s", (int) n, (const char *) buf + off);
			off += n;
		}
	}
	return NULL;
}

static uint8_t bitrev8(uint8_t b)
{
	b = (uint8_t)((b & 0xF0) >> 4 | (b & 0x0F) << 4);
	b = (uint8_t)((b & 0xCC) >> 2 | (b & 0x33) << 2);
	b = (uint8_t)((b & 0xAA) >> 1 | (b & 0x55) << 1);
	return b;
}

int vu9p_jtag_program(struct vu9p_dev *d, const char *bitfile)
{
	struct vu9p_jtag *j = J(d);
	FILE *f;
	struct stat st;
	uint8_t *buf, *rev;
	const uint8_t *data;
	size_t dlen = 0, off;
	char part[64] = "";
	uint32_t cap = 0;

	if (!j || !j->m.h) { applog(LOG_ERR, "VU9P %d: cable not open", d->index); return -1; }
	if (stat(bitfile, &st) || !(f = fopen(bitfile, "rb"))) { applog(LOG_ERR, "VU9P %d: cannot read %s", d->index, bitfile); return -1; }
	buf = (uint8_t *) malloc(st.st_size);
	if (!buf || fread(buf, 1, st.st_size, f) != (size_t) st.st_size) { fclose(f); free(buf); return -1; }
	fclose(f);
	data = bit_payload(buf, st.st_size, &dlen, part, sizeof(part));
	if (!data) { applog(LOG_ERR, "VU9P %d: %s is not a Xilinx .bit file", d->index, bitfile); free(buf); return -1; }
	applog(LOG_INFO, "VU9P %d: programming %s (%zu bytes of configuration data, part %s) over JTAG at %.1f MHz",
	       d->index, bitfile, dlen, part, j->m.tck_hz / 1e6);
	/* the configuration logic wants each byte MSB first; JTAG shifts LSB first */
	rev = (uint8_t *) malloc(dlen);
	if (!rev) { free(buf); return -1; }
	for (off = 0; off < dlen; off++) rev[off] = bitrev8(data[off]);
	free(buf);

	j->user1_loaded = 0;
	if (jtag_reset_to_idle(&j->m) || jtag_scan_ir(&j->m, ir_word(j, IR_JPROGRAM, master_field(j)), ir_len(j), NULL) ||
	    jtag_scan_ir(&j->m, ir_word(j, IR_ISC_NOOP, master_field(j)), ir_len(j), NULL)) goto fail;
	mpsse_clock(&j->m, 100000);                      /* configuration memory clear */
	if (mpsse_flush(&j->m, NULL, 0)) goto fail;
	usleep(20000);
	if (jtag_scan_ir(&j->m, ir_word(j, IR_CFG_IN, master_field(j)), ir_len(j), NULL)) goto fail;
	mpsse_tms_seq(&j->m, 0x01, 3);                   /* -> Shift-DR */
	for (off = 0; off < dlen; ) {
		size_t chunk = dlen - off > 32768 ? 32768 : dlen - off;
		bool last = (off + chunk == dlen);
		uint8_t c[3];
		/* write-only shift (no TDO read) */
		{
			size_t body = last ? chunk - 1 : chunk;      /* bytes shifted fully; the final bit goes with TMS */
			if (body) {
				c[0] = 0x19 /* DO_WRITE|LSB|WRITE_NEG */; c[1] = (uint8_t)((body - 1) & 0xFF); c[2] = (uint8_t)((body - 1) >> 8);
				/* queue via the public shift API would read back; build the command directly */
				{
					uint8_t hdr[3] = { c[0], c[1], c[2] };
					size_t need = j->m.olen + 3 + body;
					if (need > j->m.ocap) { size_t cap2 = j->m.ocap ? j->m.ocap : 65536; while (cap2 < need) cap2 *= 2; j->m.obuf = (uint8_t *) realloc(j->m.obuf, cap2); j->m.ocap = cap2; }
					memcpy(j->m.obuf + j->m.olen, hdr, 3); j->m.olen += 3;
					memcpy(j->m.obuf + j->m.olen, rev + off, body); j->m.olen += body;
				}
			}
			if (last) {
				uint8_t lb = rev[dlen - 1];
				uint8_t bits[3] = { 0x1B /* DO_WRITE|LSB|BITMODE|WRITE_NEG */, 6, lb };   /* first 7 bits of the last byte */
				uint8_t tms[3] = { 0x4B, 0, (uint8_t)(0x01 | ((lb >> 7) << 7)) };        /* last bit with TMS=1 -> Exit1-DR */
				memcpy(j->m.obuf + j->m.olen, bits, 3); j->m.olen += 3;
				memcpy(j->m.obuf + j->m.olen, tms, 3); j->m.olen += 3;
			}
		}
		off += chunk;
		if (mpsse_flush(&j->m, NULL, 0)) goto fail;
	}
	mpsse_tms_seq(&j->m, 0x01, 2);                   /* Update-DR -> RTI */
	if (jtag_scan_ir(&j->m, ir_word(j, IR_JSTART, master_field(j)), ir_len(j), NULL)) goto fail;
	mpsse_clock(&j->m, 20000);                       /* startup sequence */
	if (mpsse_flush(&j->m, NULL, 0)) goto fail;
	usleep(50000);
	if (jtag_scan_ir(&j->m, ir_word(j, IR_BYPASS, master_field(j)), ir_len(j), &cap)) goto fail;
	free(rev);
	applog(LOG_INFO, "VU9P %d: configuration shifted, IR capture after startup %05x (bit 5 of the master field = DONE)", d->index, cap);
	if (!((cap >> (IR_BITS * master_field(j))) & 0x20)) applog(LOG_WARNING, "VU9P %d: IR capture suggests DONE low", d->index);
	j->user1_loaded = 0;
	if (vu9p_jtag_check_bus(d))
		applog(LOG_WARNING, "VU9P %d: programmed image has no USER1 register bus (fine for a blank image)", d->index);
	return 0;
fail:
	free(rev);
	applog(LOG_ERR, "VU9P %d: programming failed (JTAG transfer error)", d->index);
	fail(d);
	return -1;
}
