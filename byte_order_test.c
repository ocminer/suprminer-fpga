/*
 * byte_order_test.c - Determine correct byte ordering for ZTEX BLAKE3 FPGA
 *
 * Sends known CV + block2 data to FPGA, reads hash7, and compares with
 * software-computed hash7 under different byte orderings.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

/* BLAKE3 - inline minimal implementation for test */
static const uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t MSG_PERM[16] = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t swab32(uint32_t v) {
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v & 0xff0000) >> 8) | ((v >> 24) & 0xff);
}

static void g(uint32_t *s, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx; s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d]; s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my; s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d]; s[b] = rotr32(s[b] ^ s[c], 7);
}

static void blake3_compress(const uint32_t cv[8], const uint32_t bw[16],
                            uint64_t ctr, uint32_t blen, uint32_t flags, uint32_t out[8]) {
    uint32_t s[16], m[16], mt[16];
    for (int i = 0; i < 8; i++) s[i] = cv[i];
    s[8]=BLAKE3_IV[0]; s[9]=BLAKE3_IV[1]; s[10]=BLAKE3_IV[2]; s[11]=BLAKE3_IV[3];
    s[12]=(uint32_t)(ctr&0xFFFFFFFF); s[13]=(uint32_t)(ctr>>32); s[14]=blen; s[15]=flags;
    for (int i = 0; i < 16; i++) m[i] = bw[i];
    for (int r = 0; r < 7; r++) {
        g(s,0,4,8,12,m[0],m[1]); g(s,1,5,9,13,m[2],m[3]);
        g(s,2,6,10,14,m[4],m[5]); g(s,3,7,11,15,m[6],m[7]);
        g(s,0,5,10,15,m[8],m[9]); g(s,1,6,11,12,m[10],m[11]);
        g(s,2,7,8,13,m[12],m[13]); g(s,3,4,9,14,m[14],m[15]);
        for (int i = 0; i < 16; i++) mt[i] = m[MSG_PERM[i]];
        for (int i = 0; i < 16; i++) m[i] = mt[i];
    }
    for (int i = 0; i < 8; i++) out[i] = s[i] ^ s[i+8];
}

/* Send data to ZTEX FPGA */
static int ztex_send(libusb_device_handle *h, unsigned char *buf, int len) {
    int idx = 0;
    while (len > 0) {
        int chunk = len > 64 ? 64 : len;
        int r = libusb_control_transfer(h, 0x40, 0x80, 0, 0, buf + idx, chunk, 2000);
        if (r < 0) return r;
        len -= r; idx += r;
    }
    return idx;
}

/* Read 16 bytes from ZTEX FPGA */
static int ztex_read(libusb_device_handle *h, uint32_t *golden1, uint32_t *nonce,
                     uint32_t *hash7, uint32_t *golden2) {
    unsigned char rbuf[16];
    int ret = 16, len = 0;
    while (ret > 0) {
        int r = libusb_control_transfer(h, 0xc0, 0x81, 0, 0, rbuf + len, ret, 1000);
        if (r < 0) return r;
        ret -= r; len += r;
    }
    memcpy(golden1, rbuf, 4);
    memcpy(nonce, rbuf+4, 4);
    memcpy(hash7, rbuf+8, 4);
    memcpy(golden2, rbuf+12, 4);
    return len;
}

/* Set frequency */
static int ztex_setfreq(libusb_device_handle *h, int mhz) {
    int idx = (mhz / 4) - 1;
    return libusb_control_transfer(h, 0x40, 0x83, idx, 0, NULL, 0, 1000);
}

/* Select FPGA */
static int ztex_select(libusb_device_handle *h, int fpga) {
    return libusb_control_transfer(h, 0x40, 0x82, fpga, 0, NULL, 0, 1000);
}

int main() {
    /* Known test data: simple incrementing pattern for CV and block2 */
    uint32_t cv[8], b2[16], hash[8];
    for (int i = 0; i < 8; i++) cv[i] = 0x10000000 + i;
    for (int i = 0; i < 16; i++) b2[i] = 0;
    b2[0] = 0xAAAA0001;  /* m[0] height */
    b2[1] = 0xBBBB0002;  /* m[1] size */
    b2[2] = 0xCCCC0003;  /* m[2] timestamp */
    b2[3] = 0x00000000;  /* m[3] nonce - FPGA will set this */
    b2[4] = 0xDDDD0005;  /* m[4] */
    b2[5] = 0xEEEE0006;
    b2[6] = 0xFFFF0007;
    b2[7] = 0x11110008;
    b2[8] = 0x22220009;
    b2[9] = 0x3333000A;
    b2[10] = 0x4444000B;
    b2[11] = 0x5555000C;
    b2[12] = 0x6666000D;
    uint32_t target = 0xFFFFFFFF;  /* easy target - everything passes */

    /* Compute expected hash7 for nonce=0 (core 0) */
    b2[3] = 0;
    blake3_compress(cv, b2, 0, 52, 2|8, hash);
    printf("Software hash7 for nonce=0: %08X\n", hash[7]);
    printf("Software full hash: ");
    for (int i = 7; i >= 0; i--) printf("%08X", hash[i]);
    printf("\n");

    /* Also compute for nonce=4, 8, 12 */
    for (int n = 0; n <= 12; n += 4) {
        b2[3] = n;
        blake3_compress(cv, b2, 0, 52, 2|8, hash);
        printf("  nonce=%d hash7=%08X\n", n, hash[7]);
    }

    /* Pack 84-byte buffer - method A: raw (no manipulation) */
    unsigned char data_raw[84];
    memcpy(data_raw, cv, 32);           /* CV: bytes 0-31 */
    memcpy(data_raw + 32, &b2[0], 12);  /* m[0]-m[2]: bytes 32-43 */
    memcpy(data_raw + 44, &b2[4], 36);  /* m[4]-m[12]: bytes 44-79 */
    memcpy(data_raw + 80, &target, 4);  /* target: bytes 80-83 */

    /* Method B: swap_endian */
    unsigned char data_swap[84];
    uint32_t *src = (uint32_t*)data_raw, *dst = (uint32_t*)data_swap;
    for (int i = 0; i < 21; i++) dst[i] = swab32(src[i]);

    /* Method C: full byte reverse */
    unsigned char data_rev[84];
    for (int i = 0; i < 84; i++) data_rev[i] = data_raw[83 - i];

    /* Method D: swap_endian + full byte reverse */
    unsigned char data_both[84];
    for (int i = 0; i < 84; i++) data_both[i] = data_swap[83 - i];

    printf("\nFirst 16 bytes of each method:\n");
    printf("  RAW:  "); for (int i=0;i<16;i++) printf("%02X ",data_raw[i]); printf("\n");
    printf("  SWAP: "); for (int i=0;i<16;i++) printf("%02X ",data_swap[i]); printf("\n");
    printf("  REV:  "); for (int i=0;i<16;i++) printf("%02X ",data_rev[i]); printf("\n");
    printf("  BOTH: "); for (int i=0;i<16;i++) printf("%02X ",data_both[i]); printf("\n");

    /* Open USB device */
    libusb_context *ctx;
    libusb_init(&ctx);
    libusb_device_handle *h = libusb_open_device_with_vid_pid(ctx, 0x221a, 0x0100);
    if (!h) { fprintf(stderr, "Cannot open ZTEX device\n"); return 1; }
    libusb_claim_interface(h, 0);

    ztex_select(h, 0);
    ztex_setfreq(h, 72);

    unsigned char *methods[] = { data_raw, data_swap, data_rev, data_both };
    const char *names[] = { "RAW", "SWAP_ENDIAN", "FULL_REVERSE", "SWAP+REVERSE" };

    for (int m = 0; m < 4; m++) {
        printf("\n=== Method: %s ===\n", names[m]);

        /* Send work */
        ztex_send(h, methods[m], 84);

        /* Wait for FPGA to hash some nonces */
        usleep(500000);

        /* Read back */
        uint32_t g1, nonce, h7, g2;
        ztex_read(h, &g1, &nonce, &h7, &g2);
        printf("  FPGA: nonce=%08X hash7=%08X golden1=%08X golden2=%08X\n", nonce, h7, g1, g2);

        /* Compute software hash with same nonce */
        b2[3] = nonce;
        blake3_compress(cv, b2, 0, 52, 2|8, hash);
        printf("  SW:   hash7=%08X (for nonce %08X)\n", hash[7], nonce);
        printf("  Match: %s\n", hash[7] == h7 ? "YES <<<" : "no");

        /* Also try byte-swapped nonce */
        b2[3] = swab32(nonce);
        blake3_compress(cv, b2, 0, 52, 2|8, hash);
        printf("  SW(swapped nonce): hash7=%08X\n", hash[7]);
        printf("  Match: %s\n", hash[7] == h7 ? "YES <<<" : "no");
    }

    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_exit(ctx);
    return 0;
}
