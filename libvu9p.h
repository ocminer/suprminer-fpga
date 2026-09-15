/* VU9P BS1 proof-of-concept backend for suprminer-fpga.
 *
 * The TCP transport connects to a persistent Vivado Lab JTAG-AXI bridge,
 * with one bridge per card. ZTEX USB uses its existing separate backend.
 */
#ifndef LIBVU9P_H
#define LIBVU9P_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define VU9P_MAX_CARDS 8

struct vu9p_card {
    char  host[64];
    int   port;
    int   fd;            /* -1 = disconnected */
    bool  enabled;
    bool  address_ready; /* resolved before mining; reused on reconnect */
    uint32_t ipv4_addr_be;
    uint32_t build_id;   /* exact ID reported by the bridge PING */
    /* stats */
    uint64_t last_hashes;    /* hashes_done at last poll */
    uint64_t accepted, rejected, hw_errors;
    double   mhs;            /* rolling rate */
};

struct vu9p_poll_reply {
    bool found;
    uint32_t nonce;
    uint32_t hash7;
    uint64_t hashes_done;
    uint32_t last_hash7;
};

struct vu9p_temp_reply {
    double temp_c;
    double vccint_v;
    double vccaux_v;
    double vccbram_v;
};

extern struct vu9p_card g_vu9p_cards[VU9P_MAX_CARDS];
extern int  g_vu9p_card_count;

/* parse "--vu9p host:port[,host:port...]" spec; returns card count or -1 */
int  vu9p_parse_spec(const char *spec);
/* Set the total whole-line transaction deadline before vu9p_init(). */
int  vu9p_set_io_timeout_ms(uint32_t timeout_ms);
/* Connect and require an exact PONG build ID on every enabled card. */
int  vu9p_init(uint32_t expected_build_id);

/* Pure protocol helpers, exported for focused offline tests. */
int  vu9p_parse_pong_line(const char *line, uint32_t expected_build_id,
                          uint32_t *actual_build_id);
int  vu9p_parse_poll_line(const char *line, struct vu9p_poll_reply *reply);
int  vu9p_parse_temp_line(const char *line, struct vu9p_temp_reply *reply);
int  vu9p_parse_ok_line(const char *line);
int  vu9p_format_work_line(char *dst, size_t dst_size,
                           const unsigned char hdr76[76], uint32_t target,
                           uint32_t nonce_base);

/* transport ops (return 0 on success, -1 on comm error) */
int  vu9p_send_work(struct vu9p_card *c, const unsigned char hdr76[76],
                    uint32_t target, uint32_t nonce_base);
/* Both replies carry a rollover-checked counter and separately read last_hash7.
 * Return 1 = found, 0 = none, -1 = transport or exact-grammar failure. */
int  vu9p_poll(struct vu9p_card *c, uint32_t *nonce, uint32_t *hash7,
               uint64_t *hashes_done, uint32_t *last_hash7);
int  vu9p_stop(struct vu9p_card *c);
int  vu9p_temp(struct vu9p_card *c, struct vu9p_temp_reply *reply);

/* vu9p_miner_thread(userdata) lives in fpga-miner.c (needs static miner
 * helpers there); one thread per card, thr->vu9p_card = card index. */

#endif
