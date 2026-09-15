/* VU9P BS1 proof-of-concept transport for suprminer-fpga.
 *
 * Used only when the VU9P backend is selected. Each card has a separate
 * persistent JTAG-AXI bridge speaking this TCP line protocol:
 *   WORK <hdr152hex> <target8> <base8> -> OK
 *   POLL -> FOUND <nonce8> <hash7_8> <hashes_dec> <last8>
 *         | NONE <hashes_dec> <last8>
 *   STOP -> OK ; PING -> PONG <magic8>
 * Connections use bounded whole-line deadlines and exact response parsing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <math.h>

#include "miner.h"
#include "libvu9p.h"

struct vu9p_card g_vu9p_cards[VU9P_MAX_CARDS];
int g_vu9p_card_count = 0;

static uint32_t vu9p_io_timeout_ms;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int vu9p_set_io_timeout_ms(uint32_t timeout_ms)
{
    if (timeout_ms == 0)
        return -1;
    vu9p_io_timeout_ms = timeout_ms;
    return 0;
}

static int vu9p_monotonic_ms(uint64_t *now_ms)
{
    struct timespec now;

    if (!now_ms || clock_gettime(CLOCK_MONOTONIC, &now) < 0 ||
        now.tv_sec < 0)
        return -1;
    *now_ms = (uint64_t)now.tv_sec * UINT64_C(1000) +
              (uint64_t)now.tv_nsec / UINT64_C(1000000);
    return 0;
}

static int vu9p_hex_digit(unsigned char c, unsigned int *digit)
{
    if (c >= '0' && c <= '9')
        *digit = c - '0';
    else if (c >= 'a' && c <= 'f')
        *digit = (unsigned int)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
        *digit = (unsigned int)(c - 'A' + 10);
    else
        return -1;
    return 0;
}

static int vu9p_parse_hex8(const char *text, uint32_t *value)
{
    uint32_t parsed = 0;
    int i;

    if (!text || !value)
        return -1;
    for (i = 0; i < 8; i++) {
        unsigned int digit;

        if (vu9p_hex_digit((unsigned char)text[i], &digit) < 0)
            return -1;
        parsed = (parsed << 4) | digit;
    }
    *value = parsed;
    return 0;
}

int vu9p_parse_pong_line(const char *line, uint32_t expected_build_id,
                         uint32_t *actual_build_id)
{
    uint32_t value;

    if (!line || !actual_build_id || strlen(line) != 13 ||
        memcmp(line, "PONG ", 5) != 0 ||
        vu9p_parse_hex8(line + 5, &value) < 0 ||
        value != expected_build_id)
        return -1;
    *actual_build_id = value;
    return 0;
}

int vu9p_parse_ok_line(const char *line)
{
    return line && strcmp(line, "OK") == 0 ? 0 : -1;
}

int vu9p_parse_poll_line(const char *line, struct vu9p_poll_reply *reply)
{
    struct vu9p_poll_reply parsed;
    const char *cursor;
    char *end;
    unsigned long long hashes;
    size_t line_len;

    if (!line || !reply)
        return -1;
    memset(&parsed, 0, sizeof(parsed));
    line_len = strlen(line);

    if (line_len >= 6 && memcmp(line, "FOUND ", 6) == 0) {
        parsed.found = true;
        cursor = line + 6;
        if (strlen(cursor) < 8 ||
            vu9p_parse_hex8(cursor, &parsed.nonce) < 0 || cursor[8] != ' ')
            return -1;
        cursor += 9;
        if (strlen(cursor) < 8 ||
            vu9p_parse_hex8(cursor, &parsed.hash7) < 0 || cursor[8] != ' ')
            return -1;
        cursor += 9;
    } else if (line_len >= 5 && memcmp(line, "NONE ", 5) == 0) {
        parsed.found = false;
        cursor = line + 5;
    } else {
        return -1;
    }

    if (!isdigit((unsigned char)*cursor))
        return -1;
    errno = 0;
    hashes = strtoull(cursor, &end, 10);
    if (errno == ERANGE || end == cursor || *end != ' ')
        return -1;
    parsed.hashes_done = (uint64_t)hashes;
    cursor = end + 1;
    if (strlen(cursor) != 8 ||
        vu9p_parse_hex8(cursor, &parsed.last_hash7) < 0)
        return -1;

    *reply = parsed;
    return parsed.found ? 1 : 0;
}

static int vu9p_parse_decimal_field(const char **cursor, const char *prefix,
                                    double minimum, double maximum,
                                    double *value)
{
    char *end;
    const char *start;
    const char *scan;
    double parsed;
    size_t prefix_len;
    int dots = 0;

    if (!cursor || !*cursor || !prefix || !value)
        return -1;
    prefix_len = strlen(prefix);
    if (strncmp(*cursor, prefix, prefix_len) != 0)
        return -1;
    start = *cursor + prefix_len;
    if (!isdigit((unsigned char)*start) &&
        !(minimum < 0.0 && *start == '-' &&
          isdigit((unsigned char)start[1])))
        return -1;
    errno = 0;
    parsed = strtod(start, &end);
    if (errno == ERANGE || end == start || !isfinite(parsed) ||
        parsed < minimum || parsed > maximum)
        return -1;
    for (scan = start; scan < end; scan++) {
        if (*scan == '-' && scan == start)
            continue;
        if (*scan == '.') {
            if (++dots > 1 || scan + 1 == end)
                return -1;
            continue;
        }
        if (!isdigit((unsigned char)*scan))
            return -1;
    }
    *cursor = end;
    *value = parsed;
    return 0;
}

int vu9p_parse_temp_line(const char *line, struct vu9p_temp_reply *reply)
{
    struct vu9p_temp_reply parsed;
    const char *cursor;

    if (!line || !reply ||
        strncmp(line, "TEMP MASTER_SLR_ONLY", 20) != 0)
        return -1;
    cursor = line + 20;
    if (vu9p_parse_decimal_field(&cursor, " C=", -50.0, 150.0,
                                 &parsed.temp_c) < 0 ||
        vu9p_parse_decimal_field(&cursor, " VCCINT=", 0.0, 10.0,
                                 &parsed.vccint_v) < 0 ||
        vu9p_parse_decimal_field(&cursor, " VCCAUX=", 0.0, 10.0,
                                 &parsed.vccaux_v) < 0 ||
        vu9p_parse_decimal_field(&cursor, " VCCBRAM=", 0.0, 10.0,
                                 &parsed.vccbram_v) < 0 ||
        *cursor != '\0')
        return -1;
    *reply = parsed;
    return 0;
}

int vu9p_format_work_line(char *dst, size_t dst_size,
                          const unsigned char hdr76[76], uint32_t target,
                          uint32_t nonce_base)
{
    static const char hex[] = "0123456789abcdef";
    size_t k;
    int tail;

    /* 5 + 152 + 1 + 8 + 1 + 8 characters, plus the terminating NUL. */
    if (!dst || !hdr76 || dst_size < 176)
        return -1;
    memcpy(dst, "WORK ", 5);
    for (k = 0; k < 76; k++) {
        dst[5 + 2*k] = hex[hdr76[k] >> 4];
        dst[6 + 2*k] = hex[hdr76[k] & 0x0f];
    }
    tail = snprintf(dst + 157, dst_size - 157, " %08x %08x",
                    target, nonce_base);
    return tail == 18 ? 0 : -1;
}

static int vu9p_parse_port(const char *text, int *port)
{
    uint32_t value = 0;
    const unsigned char *p = (const unsigned char *)text;

    if (!text || !*text || !port)
        return -1;
    while (*p) {
        if (*p < '0' || *p > '9')
            return -1;
        value = value * UINT32_C(10) + (uint32_t)(*p - '0');
        if (value > UINT32_C(65535))
            return -1;
        p++;
    }
    if (value == 0)
        return -1;
    *port = (int)value;
    return 0;
}

static int vu9p_host_valid(const char *host)
{
    const unsigned char *p = (const unsigned char *)host;

    if (!host || !*host || strlen(host) >= sizeof(g_vu9p_cards[0].host))
        return 0;
    while (*p) {
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_')
            return 0;
        p++;
    }
    return 1;
}

int vu9p_parse_spec(const char *spec)
{
    struct vu9p_card parsed[VU9P_MAX_CARDS];
    char buf[512];
    char *cursor;
    int count = 0;
    size_t spec_len;

    if (!spec || !*spec)
        return -1;
    spec_len = strlen(spec);
    if (spec_len >= sizeof(buf))
        return -1;
    memcpy(buf, spec, spec_len + 1);
    memset(parsed, 0, sizeof(parsed));
    cursor = buf;

    for (;;) {
        struct vu9p_card *card;
        char *comma = strchr(cursor, ',');
        char *colon;
        const char *host;
        int port;
        int i;

        if (comma)
            *comma = '\0';
        if (!*cursor || count >= VU9P_MAX_CARDS)
            return -1;
        colon = strchr(cursor, ':');
        if (colon) {
            if (strchr(colon + 1, ':'))
                return -1;
            *colon = '\0';
            host = cursor;
            if (!vu9p_host_valid(host) ||
                vu9p_parse_port(colon + 1, &port) < 0)
                return -1;
        } else {
            host = "127.0.0.1";
            if (vu9p_parse_port(cursor, &port) < 0)
                return -1;
        }
        for (i = 0; i < count; i++) {
            if (parsed[i].port == port && strcasecmp(parsed[i].host, host) == 0)
                return -1;
        }
        card = &parsed[count++];
        memcpy(card->host, host, strlen(host) + 1);
        card->port = port;
        card->fd = -1;
        card->enabled = true;

        if (!comma)
            break;
        cursor = comma + 1;
        if (!*cursor)
            return -1;
    }

    memcpy(g_vu9p_cards, parsed, (size_t)count * sizeof(parsed[0]));
    g_vu9p_card_count = count;
    return count;
}

static void vu9p_disconnect(struct vu9p_card *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
}

static int vu9p_wait_fd(int fd, bool writing, uint64_t deadline_ms)
{
    for (;;) {
        fd_set fds;
        struct timeval tv;
        uint64_t now_ms;
        uint64_t remaining_ms;
        int selected;

        if (vu9p_monotonic_ms(&now_ms) < 0 || now_ms >= deadline_ms)
            return -1;
        remaining_ms = deadline_ms - now_ms;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = (time_t)(remaining_ms / UINT64_C(1000));
        tv.tv_usec = (suseconds_t)((remaining_ms % UINT64_C(1000)) *
                                   UINT64_C(1000));
        selected = select(fd + 1, writing ? NULL : &fds,
                          writing ? &fds : NULL, NULL, &tv);
        if (selected < 0 && errno == EINTR)
            continue;
        return selected > 0 ? 0 : -1;
    }
}

static int vu9p_resolve_card(struct vu9p_card *c)
{
    struct hostent *he;

    if (c->address_ready)
        return 0;
    he = gethostbyname(c->host);
    if (!he || he->h_addrtype != AF_INET ||
        he->h_length != (int)sizeof(c->ipv4_addr_be) ||
        !he->h_addr_list[0])
        return -1;
    memcpy(&c->ipv4_addr_be, he->h_addr_list[0],
           sizeof(c->ipv4_addr_be));
    c->address_ready = true;
    return 0;
}

static int vu9p_connect(struct vu9p_card *c, uint64_t deadline_ms)
{
    struct sockaddr_in sa;
    int fd, one = 1;
    int flags;
    int error;
    socklen_t error_len = sizeof(error);

    if (c->fd >= 0) return 0;
    if (vu9p_resolve_card(c) < 0)
        return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (fd >= FD_SETSIZE) {
        close(fd);
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c->port);
    sa.sin_addr.s_addr = c->ipv4_addr_be;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
        (errno != EINPROGRESS || vu9p_wait_fd(fd, true, deadline_ms) < 0 ||
         getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 ||
         error != 0)) {
        close(fd);
        return -1;
    }
    /* Keep the connected socket nonblocking.  select() readiness can race
     * with the following send/read; restoring blocking mode here would let
     * that race escape the transaction's one absolute deadline. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    c->fd = fd;
    return 0;
}

static int vu9p_send_until(struct vu9p_card *c, const char *data, size_t len,
                            uint64_t deadline_ms)
{
    size_t off = 0;

    while (off < len) {
        ssize_t sent;

        if (vu9p_wait_fd(c->fd, true, deadline_ms) < 0)
            return -1;
        sent = send(c->fd, data + off, len - off, MSG_NOSIGNAL);
        if (sent < 0 && (errno == EINTR || errno == EAGAIN ||
                         errno == EWOULDBLOCK))
            continue;
        if (sent <= 0)
            return -1;
        off += (size_t)sent;
    }
    return 0;
}

/* send one line, read one reply line (blocking with timeout) */
static int vu9p_txn(struct vu9p_card *c, const char *req, char *resp, size_t rsz)
{
    size_t len, off;
    uint64_t deadline_ms;
    uint64_t now_ms;

    if (!c || !req || !resp || rsz < 2 || strpbrk(req, "\r\n") ||
        vu9p_io_timeout_ms == 0 ||
        vu9p_monotonic_ms(&now_ms) < 0 ||
        now_ms > UINT64_MAX - vu9p_io_timeout_ms)
        return -1;
    deadline_ms = now_ms + vu9p_io_timeout_ms;
    if (vu9p_connect(c, deadline_ms) < 0)
        return -1;

    len = strlen(req);
    if (vu9p_send_until(c, req, len, deadline_ms) < 0 ||
        vu9p_send_until(c, "\n", 1, deadline_ms) < 0) {
        vu9p_disconnect(c);
        return -1;
    }

    off = 0;
    while (off < rsz - 1) {
        unsigned char byte;
        ssize_t n;

        if (vu9p_wait_fd(c->fd, false, deadline_ms) < 0) {
            vu9p_disconnect(c);
            return -1;
        }
        n = read(c->fd, &byte, 1);
        if (n < 0 && (errno == EINTR || errno == EAGAIN ||
                      errno == EWOULDBLOCK))
            continue;
        if (n <= 0) { vu9p_disconnect(c); return -1; }
        if (byte == '\0') {
            vu9p_disconnect(c);
            return -1;
        }
        if (byte == '\n') {
            if (off > 0 && resp[off - 1] == '\r')
                off--;
            if (memchr(resp, '\r', off) != NULL) {
                vu9p_disconnect(c);
                return -1;
            }
            resp[off] = 0;
            return 0;
        }
        resp[off++] = (char)byte;
    }
    vu9p_disconnect(c);
    return -1;
}

int vu9p_init(uint32_t expected_build_id)
{
    int i, ok = 0;
    char resp[256];
    for (i = 0; i < g_vu9p_card_count; i++) {
        struct vu9p_card *c = &g_vu9p_cards[i];
        resp[0] = 0;
        /* Resolve once before the first timed transaction and before any
         * WORK can exist on a card.  Reconnects then use only the cached
         * address, so every operational transaction obeys its deadline. */
        if (vu9p_resolve_card(c) == 0 &&
            vu9p_txn(c, "PING", resp, sizeof(resp)) == 0 &&
            vu9p_parse_pong_line(resp, expected_build_id, &c->build_id) == 0) {
            applog(LOG_INFO,
                   "VU9P %d: bridge %s:%d exact build_id=0x%08x",
                   i, c->host, c->port, expected_build_id);
            ok++;
        } else {
            applog(LOG_ERR, "VU9P %d: bridge %s:%d not responding (%s)",
                   i, c->host, c->port, resp[0] ? resp : "no reply");
            vu9p_disconnect(c);
            c->enabled = false;
        }
    }
    return ok;
}

int vu9p_send_work(struct vu9p_card *c, const unsigned char hdr76[76],
                   uint32_t target, uint32_t nonce_base)
{
    char req[256], resp[128];
    int rc;

    if (vu9p_format_work_line(req, sizeof(req), hdr76, target,
                              nonce_base) < 0)
        return -1;
    if (vu9p_txn(c, req, resp, sizeof(resp)) < 0) return -1;
    rc = vu9p_parse_ok_line(resp);
    if (rc < 0)
        vu9p_disconnect(c);
    return rc;
}

int vu9p_poll(struct vu9p_card *c, uint32_t *nonce, uint32_t *hash7,
              uint64_t *hashes_done, uint32_t *last_hash7)
{
    char resp[256];
    struct vu9p_poll_reply reply;
    int rc;

    if (vu9p_txn(c, "POLL", resp, sizeof(resp)) < 0) return -1;
    rc = vu9p_parse_poll_line(resp, &reply);
    if (rc < 0) {
        vu9p_disconnect(c);
        return -1;
    }
    *hashes_done = reply.hashes_done;
    *last_hash7 = reply.last_hash7;
    if (reply.found) {
        *nonce = reply.nonce;
        *hash7 = reply.hash7;
    }
    return rc;
}

int vu9p_stop(struct vu9p_card *c)
{
    char resp[128];
    int rc;

    if (vu9p_txn(c, "STOP", resp, sizeof(resp)) < 0) return -1;
    rc = vu9p_parse_ok_line(resp);
    if (rc < 0)
        vu9p_disconnect(c);
    return rc;
}

int vu9p_temp(struct vu9p_card *c, struct vu9p_temp_reply *reply)
{
    char resp[256];

    if (!reply || vu9p_txn(c, "TEMP", resp, sizeof(resp)) < 0)
        return -1;
    if (vu9p_parse_temp_line(resp, reply) < 0) {
        vu9p_disconnect(c);
        return -1;
    }
    return 0;
}
