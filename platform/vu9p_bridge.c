/* vu9p_bridge.c - line-protocol client for platform/vu9p_bridge.tcl.
 *
 *   R <addr>                 -> OK <data>
 *   W <addr> <data>          -> OK
 *   RB <addr> <n>            -> OK <d0> <d1> ...
 *   WB <addr> <d0> <d1> ...  -> OK
 *   TEMP                     -> OK C=<temp> VCCINT=<v> VCCAUX=<v> VCCBRAM=<v>
 *   PING                     -> OK <build id>
 * Hex without 0x.  One client per bridge; on client EOF the bridge stops the
 * core (run=0) so a dead host never leaves a board searching.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "miner.h"
#include "vu9p_bridge.h"
#include "vu9p_jtag.h"

struct vu9p_dev g_vu9p_devs[VU9P_MAX_DEVICES];
int g_vu9p_count = 0;

static const char *tool_path(const char *p, const char *dflt) { return (p && *p) ? p : dflt; }

int vu9p_parse_devices(const char *spec)
{
	char *copy, *tok, *save = NULL;
	int n = 0;

	if (!spec || !*spec) return -1;
	copy = strdup(spec);
	for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		struct vu9p_dev *d;
		char *colon;
		while (*tok == ' ') tok++;
		if (n >= VU9P_MAX_DEVICES) { applog(LOG_ERR, "VU9P: more than %d devices", VU9P_MAX_DEVICES); free(copy); return -1; }
		d = &g_vu9p_devs[n];
		memset(d, 0, sizeof(*d));
		d->index = n; d->fd = -1; d->enabled = true;
		pthread_mutex_init(&d->lock, NULL);
		snprintf(d->spec, sizeof(d->spec), "%s", tok);
		if (!strncmp(tok, "ftdi:", 5)) {
			snprintf(d->serial, sizeof(d->serial), "%s", tok + 5);
			d->transport = VU9P_TRANSPORT_JTAG;
			d->port = 0;
			n++;
			continue;
		}
		if (!strncmp(tok, "jtag:", 5)) {
			char *s = tok + 5;
			colon = strchr(s, ':');
			if (colon) { *colon = 0; d->port = atoi(colon + 1); }
			else d->port = VU9P_BRIDGE_BASE_PORT + n;
			snprintf(d->serial, sizeof(d->serial), "%s", s);
			snprintf(d->host, sizeof(d->host), "127.0.0.1");
			d->own_bridge = true;
		} else {
			colon = strrchr(tok, ':');
			if (!colon || !colon[1]) { applog(LOG_ERR, "VU9P: bad device spec '%s' (host:port or jtag:SERIAL[:port])", tok); free(copy); return -1; }
			*colon = 0;
			snprintf(d->host, sizeof(d->host), "%s", tok);
			d->port = atoi(colon + 1);
		}
		if (d->port <= 0 || d->port > 65535) { applog(LOG_ERR, "VU9P: bad port in '%s'", d->spec); free(copy); return -1; }
		n++;
	}
	free(copy);
	g_vu9p_count = n;
	return n;
}

/* ---- vivado_lab helpers --------------------------------------------------- */

static int run_vivado_lab(const struct vu9p_tools *t, const char *tcl, const char *a1, const char *a2, const char *a3,
                          const char *logfile, pid_t *child)
{
	char tclpath[512];
	const char *exe = tool_path(t->vivado_lab, "vivado_lab");
	pid_t pid;

	snprintf(tclpath, sizeof(tclpath), "%s/%s", tool_path(t->tcl_dir, "platform"), tcl);
	if (access(tclpath, R_OK)) { applog(LOG_ERR, "VU9P: cannot read %s (use --tcl-dir)", tclpath); return -1; }
	pid = fork();
	if (pid < 0) return -1;
	if (pid == 0) {
		int fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
		setsid();
		execlp(exe, exe, "-mode", "batch", "-nojournal", "-nolog", "-source", tclpath, "-tclargs", a1, a2, a3, (char *) NULL);
		_exit(127);
	}
	*child = pid;
	return 0;
}

int vu9p_program(struct vu9p_dev *d, const char *bitstream, const struct vu9p_tools *t)
{
	char logfile[512], bitpath[1024];
	pid_t pid; int status;

	if (d->transport == VU9P_TRANSPORT_JTAG) {
		if (!d->jtag && vu9p_jtag_open_cable(d, t->tck_hz)) return -1;
		return vu9p_jtag_program(d, bitstream);
	}

	if (!d->serial[0]) { applog(LOG_ERR, "VU9P %d: --program needs a jtag:SERIAL device spec", d->index); return -1; }
	if (!realpath(bitstream, bitpath)) { applog(LOG_ERR, "VU9P %d: bitstream %s: %s", d->index, bitstream, strerror(errno)); return -1; }
	snprintf(logfile, sizeof(logfile), "%s/vu9p_program_%s.log", tool_path(t->log_dir, "."), d->serial);
	applog(LOG_INFO, "VU9P %d: programming %s with %s (JTAG, this takes about a minute)", d->index, d->serial, bitpath);
	if (run_vivado_lab(t, "vu9p_program.tcl", d->serial, bitpath, tool_path(t->hw_server, "127.0.0.1:3121"), logfile, &pid))
		return -1;
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		applog(LOG_ERR, "VU9P %d: programming failed (see %s)", d->index, logfile);
		return -1;
	}
	{	/* the tcl prints PROGRAM_DONE on success */
		FILE *f = fopen(logfile, "r"); char line[512]; int ok = 0;
		if (f) { while (fgets(line, sizeof(line), f)) if (strstr(line, "PROGRAM_DONE")) ok = 1; fclose(f); }
		if (!ok) { applog(LOG_ERR, "VU9P %d: no PROGRAM_DONE in %s", d->index, logfile); return -1; }
	}
	applog(LOG_INFO, "VU9P %d: programmed", d->index);
	return 0;
}

static int try_connect(struct vu9p_dev *d, int timeout_ms)
{
	struct addrinfo hints, *res = NULL, *ai;
	char portstr[16];
	int fd = -1, one = 1;
	struct timeval tv;

	memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof(portstr), "%d", d->port);
	if (getaddrinfo(d->host, portstr, &hints, &res)) return -1;
	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
		close(fd); fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) return -1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	return fd;
}

int vu9p_spawn_bridge(struct vu9p_dev *d, const struct vu9p_tools *t)
{
	char logfile[512], portstr[16];
	int i;

	if (d->transport == VU9P_TRANSPORT_JTAG || !d->own_bridge) return 0;
	/* a bridge that already answers on this port (left by a previous run or started by hand) is reused */
	{
		int fd = try_connect(d, 2000);
		if (fd >= 0) {
			close(fd);
			applog(LOG_INFO, "VU9P %d: a bridge already listens on %s:%d, reusing it", d->index, d->host, d->port);
			d->own_bridge = false;
			return 0;
		}
	}
	snprintf(logfile, sizeof(logfile), "%s/vu9p_bridge_%s.log", tool_path(t->log_dir, "."), d->serial);
	snprintf(portstr, sizeof(portstr), "%d", d->port);
	applog(LOG_INFO, "VU9P %d: starting JTAG-AXI bridge for %s on port %d (log %s)", d->index, d->serial, d->port, logfile);
	if (run_vivado_lab(t, "vu9p_bridge.tcl", d->serial, portstr, tool_path(t->hw_server, "127.0.0.1:3121"), logfile, &d->bridge_pid))
		return -1;
	/* the bridge needs 20-60 s to open the hardware target */
	for (i = 0; i < 180; i++) {
		int status, fd;
		if (waitpid(d->bridge_pid, &status, WNOHANG) == d->bridge_pid) {
			applog(LOG_ERR, "VU9P %d: bridge exited early (see %s; is the bitstream loaded? use --program)", d->index, logfile);
			d->bridge_pid = 0; return -1;
		}
		fd = try_connect(d, 2000);
		if (fd >= 0) { close(fd); return 0; }
		sleep(1);
	}
	applog(LOG_ERR, "VU9P %d: bridge did not come up within 180 s", d->index);
	return -1;
}

/* ---- line protocol ------------------------------------------------------- */

static int bridge_cmd(struct vu9p_dev *d, const char *cmd, char *resp, size_t rlen)
{
	size_t len = strlen(cmd), off = 0, got = 0;
	int rc = -1;

	pthread_mutex_lock(&d->lock);
	if (d->fd < 0) goto out;
	while (off < len) {
		ssize_t n = send(d->fd, cmd + off, len - off, MSG_NOSIGNAL);
		if (n <= 0) goto fail;
		off += (size_t) n;
	}
	if (send(d->fd, "\n", 1, MSG_NOSIGNAL) != 1) goto fail;
	while (got + 1 < rlen) {
		ssize_t n = recv(d->fd, resp + got, 1, 0);
		if (n <= 0) goto fail;
		if (resp[got] == '\n') break;
		got++;
	}
	resp[got] = 0;
	if (strncmp(resp, "OK", 2)) { applog(LOG_ERR, "VU9P %d: '%s' -> '%s'", d->index, cmd, resp); goto out; }
	rc = 0;
	goto out;
fail:
	applog(LOG_ERR, "VU9P %d: bridge connection lost (%s)", d->index, strerror(errno));
	close(d->fd); d->fd = -1;
out:
	pthread_mutex_unlock(&d->lock);
	return rc;
}

int vu9p_rd(struct vu9p_dev *d, uint32_t addr, uint32_t *val)
{
	char cmd[32], resp[64];
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_rd(d, addr, val);
	snprintf(cmd, sizeof(cmd), "R %03x", addr);
	if (bridge_cmd(d, cmd, resp, sizeof(resp))) return -1;
	*val = (uint32_t) strtoul(resp + 3, NULL, 16);
	return 0;
}

int vu9p_wr(struct vu9p_dev *d, uint32_t addr, uint32_t val)
{
	char cmd[48], resp[64];
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_wr(d, addr, val);
	snprintf(cmd, sizeof(cmd), "W %03x %08x", addr, val);
	return bridge_cmd(d, cmd, resp, sizeof(resp));
}

int vu9p_rb(struct vu9p_dev *d, uint32_t addr, uint32_t *vals, int n)
{
	char cmd[32], resp[64 * 9 + 16], *p;
	int i;
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_rb(d, addr, vals, n);
	if (n > 64) return -1;
	snprintf(cmd, sizeof(cmd), "RB %03x %d", addr, n);
	if (bridge_cmd(d, cmd, resp, sizeof(resp))) return -1;
	p = resp + 2;
	for (i = 0; i < n; i++) {
		char *end;
		vals[i] = (uint32_t) strtoul(p, &end, 16);
		if (end == p) return -1;
		p = end;
	}
	return 0;
}

int vu9p_wb(struct vu9p_dev *d, uint32_t addr, const uint32_t *vals, int n)
{
	int i, j;
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_wb(d, addr, vals, n);
	for (i = 0; i < n; i += 32) {        /* keep lines short */
		char cmd[32 * 9 + 16], resp[64];
		int m = (n - i < 32) ? n - i : 32, len;
		len = snprintf(cmd, sizeof(cmd), "WB %03x", addr + 4 * i);
		for (j = 0; j < m; j++) len += snprintf(cmd + len, sizeof(cmd) - len, " %08x", vals[i + j]);
		if (bridge_cmd(d, cmd, resp, sizeof(resp))) return -1;
	}
	return 0;
}

int vu9p_sensors(struct vu9p_dev *d)
{
	char resp[160], *p;
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_sensors(d);
	if (bridge_cmd(d, "TEMP", resp, sizeof(resp))) return -1;
	if ((p = strstr(resp, "C="))) d->temp_c = atof(p + 2);
	if ((p = strstr(resp, "VCCINT="))) d->vccint_v = atof(p + 7);
	if ((p = strstr(resp, "VCCAUX="))) d->vccaux_v = atof(p + 7);
	if ((p = strstr(resp, "VCCBRAM="))) d->vccbram_v = atof(p + 8);
	return 0;
}

int vu9p_ping(struct vu9p_dev *d, uint32_t *id)
{
	char resp[64];
	if (bridge_cmd(d, "PING", resp, sizeof(resp))) return -1;
	*id = (uint32_t) strtoul(resp + 3, NULL, 16);
	return 0;
}

int vu9p_connect(struct vu9p_dev *d, const struct vu9p_tools *t)
{
	int fd;
	if (d->transport == VU9P_TRANSPORT_JTAG) return vu9p_jtag_open(d, t->tck_hz);
	fd = try_connect(d, t->io_timeout_ms > 0 ? t->io_timeout_ms : 30000);
	if (fd < 0) { applog(LOG_ERR, "VU9P %d: cannot connect to bridge %s:%d", d->index, d->host, d->port); return -1; }
	pthread_mutex_lock(&d->lock); d->fd = fd; pthread_mutex_unlock(&d->lock);
	{ uint32_t naxi = 0; if (vu9p_ping(d, &naxi)) return -1; }
	if (vu9p_sensors(d)) return -1;
	applog(LOG_INFO, "VU9P %d: bridge %s:%d up, temp %.1f C vccint %.3f V", d->index, d->host, d->port, d->temp_c, d->vccint_v);
	return 0;
}

void vu9p_close(struct vu9p_dev *d)
{
	if (d->transport == VU9P_TRANSPORT_JTAG) { vu9p_jtag_close(d); return; }
	pthread_mutex_lock(&d->lock);
	if (d->fd >= 0) {
		char resp[64]; ssize_t n;
		n = send(d->fd, "QUIT\n", 5, MSG_NOSIGNAL); (void) n;
		n = recv(d->fd, resp, sizeof(resp), 0); (void) n;
		close(d->fd); d->fd = -1;
	}
	pthread_mutex_unlock(&d->lock);
	if (d->own_bridge && d->bridge_pid > 0) {
		kill(d->bridge_pid, SIGTERM);
		waitpid(d->bridge_pid, NULL, 0);
		d->bridge_pid = 0;
	}
}

void vu9p_shutdown_all(void)
{
	int i;
	for (i = 0; i < g_vu9p_count; i++) vu9p_close(&g_vu9p_devs[i]);
}
