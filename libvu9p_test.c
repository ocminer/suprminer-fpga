/* Real transport with an AF_UNIX socketpair bridge. No IP socket, DNS,
 * hardware or external service is used. Run with libvu9p.c and pthread. */
#define _POSIX_C_SOURCE 200809L
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "libvu9p.h"
#include "vu9p_bs1_policy.h"

void applog(int priority, const char *format, ...)
{
    (void)priority;
    (void)format;
}

/* An unexpected reconnect/retry must fail the test before it can access an
 * IP endpoint or resolver. Socketpair itself does not call these functions. */
int socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    assert(!"unexpected network socket or automatic reconnect");
    return -1;
}

struct hostent *gethostbyname(const char *name)
{
    (void)name;
    assert(!"unexpected DNS lookup");
    return NULL;
}

static uint64_t now_ms(void)
{
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static void pause_ms(unsigned int ms)
{
    struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
    while (nanosleep(&t, &t) < 0)
        assert(errno == EINTR);
}

struct exchange {
    const char *request;
    const char *reply;
    size_t reply_size;
    unsigned int byte_delay_ms;
};

struct bridge {
    int fd;
    const struct exchange *exchanges;
    size_t count;
    size_t requests_seen;
    bool allow_early_disconnect;
};

static void *bridge_main(void *arg)
{
    struct bridge *bridge = arg;
    size_t i;
    char request[512];
    for (i = 0; i < bridge->count; ++i) {
        const struct exchange *ex = &bridge->exchanges[i];
        size_t n = 0, j;
        do {
            assert(n < sizeof(request) - 1);
            assert(recv(bridge->fd, request + n, 1, 0) == 1);
        } while (request[n++] != '\n');
        request[n] = '\0';
        assert(strcmp(request, ex->request) == 0);
        ++bridge->requests_seen;
        for (j = 0; j < ex->reply_size; ++j) {
            ssize_t sent;
            if (ex->byte_delay_ms)
                pause_ms(ex->byte_delay_ms);
            sent = send(bridge->fd, ex->reply + j, 1, MSG_NOSIGNAL);
            if (sent != 1) {
                assert(bridge->allow_early_disconnect);
                assert(sent < 0 && (errno == EPIPE || errno == ECONNRESET));
                goto done;
            }
        }
    }
    /* EOF replies deliberately model a command that may have reached the
     * bridge but lost its acknowledgement. No request is replayed. */
    assert(shutdown(bridge->fd, SHUT_WR) == 0);
done:
    /* A failed operation must not append/replay a command on this connection. */
    {
        ssize_t received = recv(bridge->fd, request, sizeof(request), 0);
        /* Closing with an unread malformed reply can reset the socketpair.
         * Pending additional request bytes still produce a positive read. */
        assert(received == 0 || (bridge->allow_early_disconnect &&
                                 received < 0 && errno == ECONNRESET));
    }
    assert(close(bridge->fd) == 0);
    return NULL;
}

static pthread_t start_bridge(struct vu9p_card *card, struct bridge *bridge)
{
    int sockets[2], flags;
    struct timeval timeout = {3, 0};
    pthread_t thread;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    flags = fcntl(sockets[0], F_GETFL, 0);
    assert(flags >= 0);
    assert(fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == 0);
    assert(setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0);
    memset(card, 0, sizeof(*card));
    card->fd = sockets[0];
    card->enabled = true;
    card->address_ready = true; /* init cannot invoke DNS */
    bridge->fd = sockets[1];
    bridge->requests_seen = 0;
    assert(pthread_create(&thread, NULL, bridge_main, bridge) == 0);
    return thread;
}

static void join_bridge(struct vu9p_card *card, struct bridge *bridge,
                        pthread_t thread)
{
    if (card->fd >= 0) {
        assert(close(card->fd) == 0);
        card->fd = -1;
    }
    assert(pthread_join(thread, NULL) == 0);
    assert(bridge->requests_seen == bridge->count);
}

static void grammar(void)
{
    const char *bad_specs[] = {"", ",4001", "4001,", "4001,,4002", "0",
        "65536", "-1", "junk", "localhost:", ":4001", "localhost:1x",
        "localhost:1:2", "local host:4001", "localhost:1,LOCALHOST:1",
        "4001,127.0.0.1:4001", "1,2,3,4,5,6,7,8,9"};
    const char *bad_pongs[] = {"PONG 5a3d0000", "PONG 5a3d0002",
        "PONG 5a3d0001 trailing", "PONG 5a3d000g", " PONG 5a3d0001",
        "PONG 5a3d001", "pong 5a3d0001", "PONG 5a3d0001\n"};
    const char *bad_polls[] = {"", "FOUND 00000000 12345678",
        "FOUND 0000000 12345678 1 00000000", "FOUND 00000000 1234567g 1 00000000",
        "FOUND 00000000 12345678 1 00000000 extra", "NONE 1 00000000 ",
        "NONE +1 00000000", "NONE -1 00000000", "NONE 1.0 00000000",
        "NONE 18446744073709551616 00000000", "NONE 1  00000000",
        "NONE 1 0000000", "NONE 1 000000000", "none 1 00000000"};
    const char *bad_temps[] = {
        "TEMP MASTER_SLR_ONLY",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=1 VCCAUX=2",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=1 VCCAUX=2 VCCBRAM=1 extra",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=nan VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=inf VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=0x1p0 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=1e0 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42. VCCINT=1 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=+42 VCCINT=1 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=-51 VCCINT=1 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=151 VCCINT=1 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=-1 VCCAUX=2 VCCBRAM=1",
        "TEMP MASTER_SLR_ONLY C=42 VCCINT=11 VCCAUX=2 VCCBRAM=1"};
    struct vu9p_poll_reply poll, poll_before;
    struct vu9p_temp_reply temp, temp_before;
    struct vu9p_card before[VU9P_MAX_CARDS];
    unsigned char header[76];
    uint32_t actual;
    char work[176], hex[3], long_input[600];
    size_t i;

    assert(vu9p_parse_spec("4001") == 1);
    assert(g_vu9p_cards[0].fd == -1 && g_vu9p_cards[0].enabled);
    assert(strcmp(g_vu9p_cards[0].host, "127.0.0.1") == 0);
    memcpy(before, g_vu9p_cards, sizeof(before));
    assert(vu9p_parse_spec(NULL) < 0);
    for (i = 0; i < sizeof(bad_specs) / sizeof(bad_specs[0]); ++i) {
        assert(vu9p_parse_spec(bad_specs[i]) < 0);
        assert(g_vu9p_card_count == 1);
        assert(memcmp(before, g_vu9p_cards, sizeof(before)) == 0);
    }
    memset(long_input, 'a', 64);
    strcpy(long_input + 64, ":4001");
    assert(vu9p_parse_spec(long_input) < 0);
    memset(long_input, '1', sizeof(long_input) - 1);
    long_input[sizeof(long_input) - 1] = 0;
    assert(vu9p_parse_spec(long_input) < 0);
    assert(vu9p_parse_spec("localhost:1,127.0.0.1:65535") == 2);
    assert(g_vu9p_cards[1].port == 65535);
    assert(vu9p_parse_spec("1,2,3,4,5,6,7,8") == VU9P_MAX_CARDS);

    actual = 0;
    assert(vu9p_parse_pong_line("PONG 5A3D0001", VU9P_BUILD_ID_BC3_BS1,
                               &actual) == 0);
    assert(actual == VU9P_BUILD_ID_BC3_BS1);
    for (i = 0; i < sizeof(bad_pongs) / sizeof(bad_pongs[0]); ++i) {
        actual = 123;
        assert(vu9p_parse_pong_line(bad_pongs[i], VU9P_BUILD_ID_BC3_BS1,
                                   &actual) < 0);
        assert(actual == 123);
    }
    assert(vu9p_parse_ok_line("OK") == 0);
    assert(vu9p_parse_ok_line("OKAY") < 0);
    assert(vu9p_parse_ok_line("OK ") < 0);
    assert(vu9p_parse_ok_line(NULL) < 0);
    assert(vu9p_parse_poll_line("FOUND 00000000 89ABCDEF 4294967296 deadBEEF",
                               &poll) == 1);
    assert(poll.found && poll.nonce == 0 && poll.hash7 == UINT32_C(0x89abcdef));
    assert(poll.hashes_done == UINT64_C(4294967296));
    assert(poll.last_hash7 == UINT32_C(0xdeadbeef));
    assert(vu9p_parse_poll_line("NONE 18446744073709551615 00000000", &poll) == 0);
    assert(!poll.found && poll.hashes_done == UINT64_MAX && poll.last_hash7 == 0);
    memset(&poll_before, 0xa5, sizeof(poll_before));
    for (i = 0; i < sizeof(bad_polls) / sizeof(bad_polls[0]); ++i) {
        memcpy(&poll, &poll_before, sizeof(poll));
        assert(vu9p_parse_poll_line(bad_polls[i], &poll) < 0);
        assert(memcmp(&poll, &poll_before, sizeof(poll)) == 0);
    }
    assert(vu9p_parse_temp_line(
        "TEMP MASTER_SLR_ONLY C=-1.25 VCCINT=0.85 VCCAUX=1.8 VCCBRAM=0.849",
        &temp) == 0);
    assert(temp.temp_c == -1.25 && temp.vccint_v == 0.85);
    assert(temp.vccaux_v == 1.8 && temp.vccbram_v == 0.849);
    memset(&temp_before, 0xa5, sizeof(temp_before));
    for (i = 0; i < sizeof(bad_temps) / sizeof(bad_temps[0]); ++i) {
        memcpy(&temp, &temp_before, sizeof(temp));
        assert(vu9p_parse_temp_line(bad_temps[i], &temp) < 0);
        assert(memcmp(&temp, &temp_before, sizeof(temp)) == 0);
    }
    for (i = 0; i < sizeof(header); ++i)
        header[i] = (unsigned char)i;
    assert(vu9p_format_work_line(work, sizeof(work), header,
                                 UINT32_C(0x0123abcd), UINT32_C(0x89abcdef)) == 0);
    assert(strlen(work) == 175 && memcmp(work, "WORK ", 5) == 0);
    for (i = 0; i < sizeof(header); ++i) {
        assert(snprintf(hex, sizeof(hex), "%02x", header[i]) == 2);
        assert(memcmp(work + 5 + 2 * i, hex, 2) == 0);
    }
    assert(strcmp(work + 157, " 0123abcd 89abcdef") == 0);
    assert(vu9p_format_work_line(work, 175, header, 0, 0) < 0);
    assert(vu9p_format_work_line(NULL, 176, header, 0, 0) < 0);
    assert(vu9p_format_work_line(work, 176, NULL, 0, 0) < 0);
}

#define EXCHANGE(req, reply) {req, reply, sizeof(reply) - 1, 0}

static void successful_session(void)
{
    unsigned char header[76] = {0};
    char work[177];
    struct exchange exchanges[] = {
        EXCHANGE("PING\n", "PONG 5a3d0001\r\n"),
        {work, "OK\n", 3, 0},
        EXCHANGE("POLL\n", "FOUND 00000000 12345678 1 abcdef01\n"),
        EXCHANGE("POLL\n", "NONE 2 00000000\n"),
        EXCHANGE("TEMP\n", "TEMP MASTER_SLR_ONLY C=42 VCCINT=1 VCCAUX=2 VCCBRAM=1\n"),
        EXCHANGE("STOP\n", "OK\n")
    };
    struct bridge bridge = {0, exchanges, 6, 0, false};
    struct vu9p_card *card = &g_vu9p_cards[0];
    struct vu9p_temp_reply temp;
    uint32_t nonce = 99, hash7 = 88, last = 77;
    uint64_t hashes = 66;
    pthread_t thread;
    /* Independent wire expectation for the all-zero header. */
    memcpy(work, "WORK ", 5);
    memset(work + 5, '0', 152);
    strcpy(work + 157, " 00000000 ffffffff\n");
    thread = start_bridge(card, &bridge);
    g_vu9p_card_count = 1;
    assert(vu9p_set_io_timeout_ms(1000) == 0);
    assert(vu9p_init(VU9P_BUILD_ID_BC3_BS1) == 1);
    assert(card->enabled && card->build_id == VU9P_BUILD_ID_BC3_BS1);
    assert(vu9p_send_work(card, header, 0, UINT32_MAX) == 0);
    assert(vu9p_poll(card, &nonce, &hash7, &hashes, &last) == 1);
    assert(nonce == 0 && hash7 == UINT32_C(0x12345678));
    assert(hashes == 1 && last == UINT32_C(0xabcdef01));
    assert(vu9p_poll(card, &nonce, &hash7, &hashes, &last) == 0);
    assert(nonce == 0 && hash7 == UINT32_C(0x12345678));
    assert(hashes == 2 && last == 0);
    assert(vu9p_temp(card, &temp) == 0 && temp.temp_c == 42);
    assert(vu9p_stop(card) == 0);
    join_bridge(card, &bridge, thread);
}

static void rejected_reply(const char *reply, size_t size, unsigned int delay)
{
    struct exchange ex = {"POLL\n", reply, size, delay};
    struct bridge bridge = {0, &ex, 1, 0, true};
    struct vu9p_card card;
    pthread_t thread = start_bridge(&card, &bridge);
    uint32_t nonce = 1, hash7 = 2, last = 3;
    uint64_t hashes = 4, started, elapsed;
    assert(vu9p_set_io_timeout_ms(180) == 0);
    started = now_ms();
    assert(vu9p_poll(&card, &nonce, &hash7, &hashes, &last) < 0);
    elapsed = now_ms() - started;
    assert(card.fd == -1);
    assert(nonce == 1 && hash7 == 2 && last == 3 && hashes == 4);
    /* Each byte arrives within 180 ms, but the whole reply does not. A
     * per-byte timeout reset would exceed this generous scheduler margin. */
    if (delay) {
        assert(elapsed >= 100);
        assert(elapsed < 1000);
    }
    join_bridge(&card, &bridge, thread);
}

static void failed_acknowledgements(void)
{
    unsigned char header[76] = {0};
    char request[177];
    struct exchange ex = EXCHANGE("PING\n", "PONG 5a3d0002\n");
    struct bridge bridge = {0, &ex, 1, 0, true};
    struct vu9p_card *card = &g_vu9p_cards[0];
    pthread_t thread = start_bridge(card, &bridge);
    g_vu9p_card_count = 1;
    assert(vu9p_set_io_timeout_ms(1000) == 0);
    assert(vu9p_init(VU9P_BUILD_ID_BC3_BS1) == 0);
    assert(!card->enabled && card->fd == -1 && card->build_id == 0);
    join_bridge(card, &bridge, thread);

    memcpy(request, "WORK ", 5);
    memset(request + 5, '0', 152);
    strcpy(request + 157, " 00000000 00000000\n");
    ex.request = request;
    ex.reply = "O"; /* command received, acknowledgement lost at EOF */
    ex.reply_size = 1;
    thread = start_bridge(card, &bridge);
    assert(vu9p_send_work(card, header, 0, 0) < 0 && card->fd == -1);
    join_bridge(card, &bridge, thread);
    ex.request = "STOP\n";
    ex.reply = "OKAY\n";
    ex.reply_size = 5;
    thread = start_bridge(card, &bridge);
    assert(vu9p_stop(card) < 0 && card->fd == -1);
    join_bridge(card, &bridge, thread);
    ex.request = "TEMP\n";
    ex.reply = "TEMP MASTER_SLR_ONLY\n";
    ex.reply_size = strlen(ex.reply);
    thread = start_bridge(card, &bridge);
    assert(vu9p_temp(card, &(struct vu9p_temp_reply){0}) < 0 && card->fd == -1);
    join_bridge(card, &bridge, thread);
}

static void failed_sends(void)
{
    int sockets[2], flags;
    struct vu9p_card card = {0};
    char buffer[4096];
    ssize_t n;
    uint64_t started, elapsed;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    card.fd = sockets[0];
    card.address_ready = true;
    assert(close(sockets[1]) == 0);
    /* The test process keeps default SIGPIPE behavior. This must return an
     * error, not terminate or silently replay a possibly delivered command. */
    assert(vu9p_stop(&card) < 0 && card.fd == -1);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    flags = fcntl(sockets[0], F_GETFL, 0);
    assert(flags >= 0 && fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == 0);
    memset(buffer, 'x', sizeof(buffer));
    do {
        n = send(sockets[0], buffer, sizeof(buffer), MSG_NOSIGNAL);
    } while (n > 0);
    assert(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    card.fd = sockets[0];
    assert(vu9p_set_io_timeout_ms(180) == 0);
    started = now_ms();
    assert(vu9p_stop(&card) < 0 && card.fd == -1);
    elapsed = now_ms() - started;
    assert(elapsed >= 100 && elapsed < 1000);
    assert(close(sockets[1]) == 0);
}

int main(void)
{
    char oversized[300];
    alarm(10); /* Bounds the test itself if a deadline regression blocks. */
    assert(vu9p_set_io_timeout_ms(0) < 0);
    grammar();
    successful_session();
    failed_acknowledgements();
#define REJECT_REPLY(text) rejected_reply(text, sizeof(text) - 1, 0)
    REJECT_REPLY("NONE 1 00000000\0ignored\n");
    REJECT_REPLY("NONE\r 1 00000000\n");
    REJECT_REPLY("NONE 1 00000000 extra\n");
    REJECT_REPLY("NONE 1 0000");
    rejected_reply("", 0, 0);
    memset(oversized, 'x', sizeof(oversized));
    oversized[sizeof(oversized) - 1] = '\n';
    rejected_reply(oversized, sizeof(oversized), 0);
    rejected_reply("NONE 1 00000000\n", 16, 80);
    failed_sends();
    alarm(0);
    puts("PASS BS1 exact grammar and local socketpair transactions/deadlines");
    return 0;
}
