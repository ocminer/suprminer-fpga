/* vu9p_voltage.c - VCCINT setpoint through NextJTAG (see vu9p_voltage.h).
 * NextJTAG talks to the board BMC over JTAG; it needs the cable exclusively, so in bridge mode the
 * Xilinx hw_server must not hold it (set the voltage in direct mode with hw_server stopped). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "vu9p_voltage.h"
#ifdef VU9P_VOLTAGE_TEST                     /* host unit test: no miner core */
#include <syslog.h>
void applog(int prio, const char *fmt, ...);
#else
#include "miner.h"
#endif

#define NEXTJTAG_TIMEOUT_S 180
#define NEXTJTAG_BUSY_TRIES 6

int vu9p_vccint_ftdi_serial(const char *serial, char *out, int outlen)
{
	int n;
	if (!serial || !*serial) return -1;
	n = snprintf(out, outlen, "%s", serial);
	if (n <= 0 || n >= outlen) return -1;
	if (n > 1 && out[n - 1] >= 'A' && out[n - 1] <= 'D') out[n - 1] = 0;   /* Vivado appends the channel */
	return 0;
}

bool vu9p_vccint_cable_busy(const char *out)
{
	return strstr(out, "LibFTDI Open Error") || strstr(out, "FTDI device busy") || strstr(out, "Unable to open");
}

static int phase_vout(const char *line, int ph, double *v)
{
	char key[24];
	const char *p;
	snprintf(key, sizeof(key), "vr_ph%d_vout = ", ph);
	if (!(p = strstr(line, key))) return -1;
	p += strlen(key);
	if (!strncmp(p, "N/A", 3)) return 1;
	*v = strtod(p, NULL);
	return 0;
}

/* confirmed = "Changing voltage to ...: SUCCESS" and, in the last "Extended Sensors:" line after it, phase 0
 * (and phase 1 unless N/A) within 5 mV of the setpoint */
int vu9p_vccint_parse(const char *out, double volts, double *ph0, double *ph1)
{
	const char *ok = strstr(out, "Changing voltage to "), *p, *last = NULL, *eol;
	char line[1024];
	int r0, r1;
	size_t n;
	*ph0 = *ph1 = NAN;
	if (!ok) return -1;
	eol = strchr(ok, '\n');
	if (!eol) eol = ok + strlen(ok);
	if (!memmem(ok, eol - ok, "SUCCESS", 7)) return -1;
	for (p = ok; (p = strstr(p, "Extended Sensors:")); p++) last = p;
	if (!last) return -1;
	eol = strchr(last, '\n');
	n = eol ? (size_t)(eol - last) : strlen(last);
	if (n >= sizeof(line)) n = sizeof(line) - 1;
	memcpy(line, last, n); line[n] = 0;
	r0 = phase_vout(line, 0, ph0);
	r1 = phase_vout(line, 1, ph1);
	if (r0 != 0 || fabs(*ph0 - volts) > 0.005) return -1;
	if (r1 == 0 && fabs(*ph1 - volts) > 0.005) return -1;
	if (r1 != 0) *ph1 = NAN;                     /* single-phase regulator or N/A */
	return 0;
}

static void boot_id(char *b, int len)
{
	FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
	b[0] = 0;
	if (f) { if (fgets(b, len, f)) b[strcspn(b, "\n")] = 0; fclose(f); }
}

static void state_path(const struct vu9p_voltage_tools *t, const char *ftdi, char *path, int len)
{
	char dir[512];
	const char *xdg = getenv("XDG_RUNTIME_DIR");
	char run[64];
	struct stat st;
	snprintf(run, sizeof(run), "/run/user/%u", (unsigned) getuid());
	if (t->state_dir) snprintf(dir, sizeof(dir), "%s", t->state_dir);
	else if (xdg && *xdg) snprintf(dir, sizeof(dir), "%s/suprminer-fpga", xdg);
	else if (!stat(run, &st) && S_ISDIR(st.st_mode)) snprintf(dir, sizeof(dir), "%s/suprminer-fpga", run);   /* cron: no XDG */
	else snprintf(dir, sizeof(dir), "/tmp/suprminer-fpga-%u", (unsigned) getuid());
	mkdir(dir, 0700);
	snprintf(path, len, "%s/vccint_%s", dir, ftdi);
}

static bool already_set(const char *path, const char *boot, double volts)
{
	char b[64] = "";
	double v = 0;
	FILE *f = fopen(path, "r");
	bool same;
	if (!f) return false;
	same = fscanf(f, "%63s %lf", b, &v) == 2 && *boot && !strcmp(b, boot) && fabs(v - volts) < 0.0005;
	fclose(f);
	return same;
}

/* run NextJTAG, output into buf (and the log file); returns exit status, 127 = not found, -1 = timeout */
static int run_nextjtag(const struct vu9p_voltage_tools *t, const char *ftdi, double volts, char *buf, size_t len, const char *log)
{
	int pfd[2], status = -1;
	size_t got = 0;
	ssize_t r;
	time_t t0 = time(NULL);
	pid_t pid;
	char vs[16];
	FILE *lf;

	snprintf(vs, sizeof(vs), "%.3f", volts);
	if (pipe(pfd)) return -1;
	pid = fork();
	if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
	if (pid == 0) {
		const char *exe = t->nextjtag ? t->nextjtag : "nextjtag";
		setsid();
		dup2(pfd[1], 1); dup2(pfd[1], 2);
		close(pfd[0]); close(pfd[1]);
		if (t->license) setenv("NEXTJTAG_LICENSE", t->license, 1);
		execlp(exe, exe, "-j", ftdi, "-B", "-e", "all", "--set-voltage", vs, "-v", "-e", "all", (char *) NULL);
		_exit(127);
	}
	close(pfd[1]);
	fcntl(pfd[0], F_SETFL, O_NONBLOCK);
	for (;;) {
		r = read(pfd[0], buf + got, len - 1 - got);
		if (r > 0) { got += r; if (got >= len - 1) got = len - 2; continue; }
		if (r == 0) break;
		if (errno != EAGAIN && errno != EINTR) break;
		if (time(NULL) - t0 > NEXTJTAG_TIMEOUT_S) { kill(-pid, SIGKILL); break; }
		usleep(100000);
	}
	buf[got] = 0;
	close(pfd[0]);
	if (waitpid(pid, &status, 0) == pid && WIFEXITED(status)) status = WEXITSTATUS(status);
	else status = -1;
	if ((lf = fopen(log, "a"))) { fprintf(lf, "=== nextjtag -j %s --set-voltage %s rc=%d\n%s\n", ftdi, vs, status, buf); fclose(lf); }
	return status;
}

bool vu9p_vccint_is_set(const struct vu9p_dev *d, double volts, const struct vu9p_voltage_tools *t)
{
	char ftdi[48], boot[64], path[600];
	if (vu9p_vccint_ftdi_serial(d->serial, ftdi, sizeof(ftdi))) return false;
	boot_id(boot, sizeof(boot));
	state_path(t, ftdi, path, sizeof(path));
	return already_set(path, boot, volts);
}

int vu9p_set_vccint(const struct vu9p_dev *d, double volts, const struct vu9p_voltage_tools *t)
{
	char ftdi[48], boot[64], path[600], log[600], *out;
	double ph0, ph1;
	int tries, rc = VU9P_VCCINT_FAILED, st;
	FILE *f;

	if (volts < VU9P_VCCINT_MIN || volts > VU9P_VCCINT_MAX) {
		applog(LOG_ERR, "VU9P %d: --vu9p-voltage %.3f outside %.3f-%.3f V", d->index, volts, VU9P_VCCINT_MIN, VU9P_VCCINT_MAX);
		return VU9P_VCCINT_FAILED;
	}
	if (vu9p_vccint_ftdi_serial(d->serial, ftdi, sizeof(ftdi))) {
		applog(LOG_ERR, "VU9P %d: VCCINT needs the board's cable serial (not available for an external bridge)", d->index);
		return VU9P_VCCINT_FAILED;
	}
	boot_id(boot, sizeof(boot));
	state_path(t, ftdi, path, sizeof(path));
	if (already_set(path, boot, volts)) {
		applog(LOG_INFO, "VU9P %d: VCCINT %.3f V already set since this boot", d->index, volts);
		return VU9P_VCCINT_ALREADY;
	}
	snprintf(log, sizeof(log), "%s/nextjtag_%s.log", t->log_dir ? t->log_dir : ".", ftdi);
	if (!(out = malloc(1 << 20))) return VU9P_VCCINT_FAILED;
	applog(LOG_INFO, "VU9P %d: setting VCCINT %.3f V through NextJTAG (cable %s, log %s)", d->index, volts, ftdi, log);
	for (tries = 0; tries < NEXTJTAG_BUSY_TRIES; tries++) {
		st = run_nextjtag(t, ftdi, volts, out, 1 << 20, log);
		if (st == 127) { rc = VU9P_VCCINT_NO_TOOL; break; }
		if (vu9p_vccint_cable_busy(out)) { rc = VU9P_VCCINT_BUSY; sleep(5); continue; }
		if (st == 0 && !vu9p_vccint_parse(out, volts, &ph0, &ph1)) {
			if (isnan(ph1)) applog(LOG_INFO, "VU9P %d: VCCINT set to %.3f V (phase 0 reads %.4f V)", d->index, volts, ph0);
			else applog(LOG_INFO, "VU9P %d: VCCINT set to %.3f V (phases read %.4f / %.4f V)", d->index, volts, ph0, ph1);
			if ((f = fopen(path, "w"))) { fprintf(f, "%s %.3f\n", boot, volts); fclose(f); }
			rc = VU9P_VCCINT_SET;
		} else {
			applog(LOG_ERR, "VU9P %d: NextJTAG did not confirm VCCINT %.3f V (rc %d, see %s)", d->index, volts, st, log);
			rc = VU9P_VCCINT_FAILED;
		}
		break;
	}
	if (rc == VU9P_VCCINT_NO_TOOL)
		applog(LOG_WARNING, "VU9P %d: NextJTAG (%s) not found: VCCINT not changed (--nextjtag <path>, or --vu9p-voltage 0)",
		       d->index, t->nextjtag ? t->nextjtag : "nextjtag");
	else if (rc == VU9P_VCCINT_BUSY)
		applog(LOG_WARNING, "VU9P %d: cable %s held by another program (Vivado hw_server?): VCCINT not changed. "
		       "Set it in --vu9p-mode direct with hw_server stopped, or pass --vu9p-voltage 0", d->index, ftdi);
	free(out);
	return rc;
}
