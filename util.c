/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2014 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <errno.h>
#include <unistd.h>
#include <jansson.h>
#include <curl/curl.h>
#include <time.h>
#include <sys/stat.h>

#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#include "compat/winansi.h"
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

static bool stratum_socket_set_nonblocking(curl_socket_t sock)
{
#ifdef WIN32
	u_long enabled = 1;
	return ioctlsocket(sock, FIONBIO, &enabled) == 0;
#else
	int flags = fcntl(sock, F_GETFL, 0);
	return flags >= 0 && fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

#ifndef _MSC_VER
#include <libgen.h>
#endif

#include "miner.h"
#include "tui.h"
#include "elist.h"
#include "stratum_job_guard.h"

extern pthread_mutex_t stats_lock;

struct data_buffer {
	void		*buf;
	size_t		len;
};

struct upload_buffer {
	const void	*buf;
	size_t		len;
	size_t		pos;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	
	if (!opt_debug && prio == LOG_DEBUG)
		return;

	if (opt_quiet && prio == LOG_INFO)
		return;
	
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;

		/* custom colors to syslog prio */
		if (prio > LOG_DEBUG) {
			switch (prio) {
				case LOG_BLUE: prio = LOG_NOTICE; break;
			}
		}

		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		const char* color = "";
		char *f;
		int len;
		time_t now;
		struct tm tm, *tm_p;

		time(&now);

		pthread_mutex_lock(&applog_lock);
		tm_p = localtime(&now);
		memcpy(&tm, tm_p, sizeof(struct tm));
		pthread_mutex_unlock(&applog_lock);

		switch (prio) {
			case LOG_ERR:     color = CL_RED; break;
			case LOG_WARNING: color = CL_YLW; break;
			case LOG_NOTICE:  color = CL_WHT; break;
			case LOG_INFO:    color = ""; break;
			case LOG_DEBUG:   color = CL_GRY; break;

			case LOG_BLUE:
				prio = LOG_NOTICE;
				color = CL_CYN;
				break;
		}
		if (!use_colors)
			color = "";

		if (opt_tui) {
			/* Route into the TUI log ring buffer (+ --log-file) instead of the
			 * terminal, which ncurses owns. Expand the message with no color. */
			char msg[512];
			va_list ap2;
			va_copy(ap2, ap);
			vsnprintf(msg, sizeof(msg), fmt, ap2);
			va_end(ap2);
			tui_log(prio, msg);
		} else {
			len = 64 + (int) strlen(fmt) + 2;
			f = (char*) malloc(len);
			sprintf(f, "[%02d:%02d:%02d]%s %s%s\n",
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec,
				color,
				fmt,
				use_colors ? CL_N : ""
			);
			pthread_mutex_lock(&applog_lock);
			vfprintf(stdout, f, ap);	/* atomic write to stdout */
			fflush(stdout);
			free(f);
			pthread_mutex_unlock(&applog_lock);
		}
	}
	va_end(ap);
}

/* Get default config.json path (will be system specific) */
void get_defconfig_path(char *out, size_t bufsize, char *argv0)
{
	char *cmd = strdup(argv0);
	char *dir = dirname(cmd);
	const char *sep = strstr(dir, "\\") ? "\\" : "/";
	struct stat info = { 0 };
#ifdef WIN32
	snprintf(out, bufsize, "%s\\fpga_miner\\fpga-miner-conf.json", getenv("APPDATA"));
#else
	snprintf(out, bufsize, "%s\\.fpga_miner\\fpga-miner-conf.json", getenv("HOME"));
#endif
	if (dir && stat(out, &info) != 0) {
		snprintf(out, bufsize, "%s%sfpga-miner-conf.json", dir, sep);
	}
	if (stat(out, &info) != 0) {
		out[0] = '\0';
		return;
	}
	out[bufsize - 1] = '\0';
	free(cmd);
}


void format_hashrate(double hashrate, char *output)
{
	char prefix = '\0';

	if (hashrate < 10000) {
		// nop
	}
	else if (hashrate < 1e7) {
		prefix = 'k';
		hashrate *= 1e-3;
	}
	else if (hashrate < 1e10) {
		prefix = 'M';
		hashrate *= 1e-6;
	}
	else if (hashrate < 1e13) {
		prefix = 'G';
		hashrate *= 1e-9;
	}
	else {
		prefix = 'T';
		hashrate *= 1e-12;
	}

	sprintf(
		output,
		prefix ? "%.2f %cH/s" : "%.2f H/s%c",
		hashrate, prefix
	);
}

/* Modify the representation of integer numbers which would cause an overflow
 * so that they are treated as floating-point numbers.
 * This is a hack to overcome the limitations of some versions of Jansson. */
static char *hack_json_numbers(const char *in)
{
	char *out;
	int i, off, intoff;
	bool in_str, in_int;

	out = (char*) calloc(2 * strlen(in) + 1, 1);
	if (!out)
		return NULL;
	off = intoff = 0;
	in_str = in_int = false;
	for (i = 0; in[i]; i++) {
		char c = in[i];
		if (c == '"') {
			in_str = !in_str;
		} else if (c == '\\') {
			out[off++] = c;
			if (!in[++i])
				break;
		} else if (!in_str && !in_int && isdigit(c)) {
			intoff = off;
			in_int = true;
		} else if (in_int && !isdigit(c)) {
			if (c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-') {
				in_int = false;
				if (off - intoff > 4) {
					char *end;
#if JSON_INTEGER_IS_LONG_LONG
					errno = 0;
					strtoll(out + intoff, &end, 10);
					if (!*end && errno == ERANGE) {
#else
					long l;
					errno = 0;
					l = strtol(out + intoff, &end, 10);
					if (!*end && (errno == ERANGE || l > INT_MAX)) {
#endif
						out[off++] = '.';
						out[off++] = '0';
					}
				}
			}
		}
		out[off++] = in[i];
	}
	return out;
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = (struct data_buffer *) user_data;
	size_t len = size * nmemb;
	size_t oldlen, newlen;
	void *newmem;
	static const unsigned char zero = 0;

	oldlen = db->len;
	newlen = oldlen + len;

	newmem = realloc(db->buf, newlen + 1);
	if (!newmem)
		return 0;

	db->buf = newmem;
	db->len = newlen;
	memcpy((uchar*) db->buf + oldlen, ptr, len);
	memcpy((uchar*) db->buf + newlen, &zero, 1);	/* null terminate */

	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct upload_buffer *ub = (struct upload_buffer *) user_data;
	size_t len = size * nmemb;

	if (len > ub->len - ub->pos)
		len = ub->len - ub->pos;

	if (len) {
		memcpy(ptr, ((uchar*)ub->buf) + ub->pos, len);
		ub->pos += len;
	}

	return len;
}

#if LIBCURL_VERSION_NUM >= 0x071200
static int seek_data_cb(void *user_data, curl_off_t offset, int origin)
{
	struct upload_buffer *ub = (struct upload_buffer *) user_data;
	
	switch (origin) {
	case SEEK_SET:
		ub->pos = (size_t) offset;
		break;
	case SEEK_CUR:
		ub->pos += (size_t) offset;
		break;
	case SEEK_END:
		ub->pos = ub->len + (size_t) offset;
		break;
	default:
		return 1; /* CURL_SEEKFUNC_FAIL */
	}

	return 0; /* CURL_SEEKFUNC_OK */
}
#endif

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = (struct header_info *) user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = (char*) calloc(1, ptrlen);
	key = (char*) calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = (char*)tmp - (char*)ptr;
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = (char*)ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

out:
	free(key);
	free(val);
	return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,
	curlsocktype purpose)
{
#ifdef __linux
	int tcp_keepcnt = 3;
#endif
	int tcp_keepintvl = 50;
	int tcp_keepidle = 50;
#ifndef WIN32
	int keepalive = 1;
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;
	DWORD outputBytes;
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* WIN32 */

	return 0;
}
#endif

json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req,
		      int *curl_err, int flags)
{
	json_t *val, *err_val, *res_val;
	int rc;
	long http_rc;
	struct data_buffer all_data = {0};
	struct upload_buffer upload_data;
	char *json_buf;
	json_error_t err;
	struct curl_slist *headers = NULL;
	char len_hdr[64];
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	long timeout = (flags & JSON_RPC_LONGPOLL) ? opt_timeout : 30;
	struct header_info hi = {0};

	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (opt_cert)
		curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
#if LIBCURL_VERSION_NUM >= 0x071200
	curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, &seek_data_cb);
	curl_easy_setopt(curl, CURLOPT_SEEKDATA, &upload_data);
#endif
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	if (opt_redirect)
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	if (flags & JSON_RPC_LONGPOLL)
		curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
	curl_easy_setopt(curl, CURLOPT_POST, 1);

	if (opt_protocol)
		applog(LOG_DEBUG, "JSON protocol request:\n%s\n", rpc_req);

	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	upload_data.pos = 0;
	sprintf(len_hdr, "Content-Length: %lu",
		(unsigned long) upload_data.len);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, len_hdr);
	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll reject-reason");
	//headers = curl_slist_append(headers, "Accept:"); /* disable Accept hdr*/
	//headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (curl_err != NULL)
		*curl_err = rc;
	if (rc) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
		if (!((flags & JSON_RPC_LONGPOLL) && rc == CURLE_OPERATION_TIMEDOUT) &&
		    !((flags & JSON_RPC_QUIET_404) && http_rc == 404))
			applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
		if (curl_err && (flags & JSON_RPC_QUIET_404) && http_rc == 404)
			*curl_err = CURLE_OK;
		goto err_out;
	}

	/* If X-Stratum was found, activate Stratum */
	if (want_stratum && hi.stratum_url &&
	    !strncasecmp(hi.stratum_url, "stratum+tcp://", 14)) {
		have_stratum = true;
		tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
		hi.stratum_url = NULL;
	}

	/* If X-Long-Polling was found, activate long polling */
	if (!have_longpoll && want_longpoll && hi.lp_path && !have_gbt &&
	    allow_getwork && !have_stratum) {
		have_longpoll = true;
		tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
		hi.lp_path = NULL;
	}

	if (!all_data.buf) {
		applog(LOG_ERR, "Empty data received in json_rpc_call.");
		goto err_out;
	}

	json_buf = hack_json_numbers((char*) all_data.buf);
	errno = 0; /* needed for Jansson < 2.1 */
	val = JSON_LOADS(json_buf, &err);
	free(json_buf);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}

	if (opt_protocol) {
		char *s = json_dumps(val, JSON_INDENT(3));
		applog(LOG_DEBUG, "JSON protocol response:\n%s", s);
		free(s);
	}

	/* JSON-RPC valid response returns a 'result' and a null 'error'. */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || (err_val && !json_is_null(err_val)
		&& !(flags & JSON_RPC_IGNOREERR))) {

		char *s = NULL;

		if (err_val) {
			s = json_dumps(err_val, 0);
			json_t *msg = json_object_get(err_val, "message");
			json_t *err_code = json_object_get(err_val, "code");
			if (curl_err && json_integer_value(err_code))
				*curl_err = (int)json_integer_value(err_code);

			if (msg && json_is_string(msg)) {
				free(s);
				s = strdup(json_string_value(msg));
				if (have_longpoll && s && !strcmp(s, "method not getwork")) {
					json_decref(err_val);
					free(s);
					goto err_out;
				}
			}
			json_decref(err_val);
		}
		else
			s = strdup("(unknown reason)");

		if (!curl_err || opt_debug)
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);

		free(s);

		goto err_out;
	}

	if (hi.reason)
		json_object_set_new(val, "reject-reason", json_string(hi.reason));

	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	free(hi.lp_path);
	free(hi.reason);
	free(hi.stratum_url);
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	size_t i;

	if (!s)
		return;
	s[0] = '\0';
	if (!p && len != 0)
		return;
	for (i = 0; i < len; i++)
//	for (size_t i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
	s[len * 2] = '\0';
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s;

	if ((!p && len != 0) || len > (SIZE_MAX - 1) / 2)
		return NULL;
	s = (char*) malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			applog(LOG_ERR, "hex2bin failed on '%s'", hex_byte);
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return(!len) ? true : false;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}

int varint_encode(unsigned char *p, uint64_t n)
{
	int i;
	if (n < 0xfd) {
		p[0] = (uchar) n;
		return 1;
	}
	if (n <= 0xffff) {
		p[0] = 0xfd;
		p[1] = n & 0xff;
		p[2] = (uchar) (n >> 8);
		return 3;
	}
	if (n <= 0xffffffff) {
		p[0] = 0xfe;
		for (i = 1; i < 5; i++) {
			p[i] = n & 0xff;
			n >>= 8;
		}
		return 5;
	}
	p[0] = 0xff;
	for (i = 1; i < 9; i++) {
		p[i] = n & 0xff;
		n >>= 8;
	}
	return 9;
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = (uint32_t *) calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--; ) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
		case 3:
			*(bin++) = (outi[0] >> 16) & 0xff;
		case 2:
			*(bin++) = (outi[0] >> 8) & 0xff;
		case 1:
			*(bin++) = outi[0] & 0xff;
			++j;
		default:
			break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, (int) (binsz - 4));
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	 * (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin((uchar*) buf, hexstr, buflen))
		return false;

	return true;
}

size_t address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
	unsigned char addrbin[25];
	int addrver;
	size_t rv;

	if (!b58dec(addrbin, sizeof(addrbin), addr))
		return 0;
	addrver = b58check(addrbin, sizeof(addrbin), addr);
	if (addrver < 0)
		return 0;
	switch (addrver) {
		case 5:    /* Bitcoin script hash */
		case 196:  /* Testnet script hash */
			if (outsz < (rv = 23))
				return rv;
			out[ 0] = 0xa9;  /* OP_HASH160 */
			out[ 1] = 0x14;  /* push 20 bytes */
			memcpy(&out[2], &addrbin[1], 20);
			out[22] = 0x87;  /* OP_EQUAL */
			return rv;
		default:
			if (outsz < (rv = 25))
				return rv;
			out[ 0] = 0x76;  /* OP_DUP */
			out[ 1] = 0xa9;  /* OP_HASH160 */
			out[ 2] = 0x14;  /* push 20 bytes */
			memcpy(&out[3], &addrbin[1], 20);
			out[23] = 0x88;  /* OP_EQUALVERIFY */
			out[24] = 0xac;  /* OP_CHECKSIG */
			return rv;
	}
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;
	
	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uint32_t hash_be[8], target_be[8];
		char hash_str[65], target_str[65];
		
		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		bin2hex(hash_str, (unsigned char *)hash_be, 32);
		bin2hex(target_str, (unsigned char *)target_be, 32);

		applog(LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target"
			   : "hash > target (false positive)",
			hash_str,
			target_str);
	}

	return rc;
}

bool diff_to_target_checked(uint32_t *target, double diff)
{
	return stratum_diff_to_target(target, diff);
}

void diff_to_target(uint32_t *target, double diff)
{
	(void)diff_to_target_checked(target, diff);
}

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#define socket_interrupted() (WSAGetLastError() == WSAEINTR)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#define socket_interrupted() (errno == EINTR)
#endif

enum stratum_wire_result {
	STRATUM_WIRE_NONE = 0,
	STRATUM_WIRE_COMPLETE,
	STRATUM_WIRE_PARTIAL
};

#define STRATUM_LINE_MAX (STRATUM_COINBASE_MAX * (size_t)2 + (size_t)65536)
#define STRATUM_BUFFER_MAX (STRATUM_LINE_MAX + (size_t)2048)
#define STRATUM_SEND_TIMEOUT_MS UINT64_C(10000)
#define STRATUM_LINE_ASSEMBLY_TIMEOUT_MS UINT64_C(10000)
#define STRATUM_AUTH_TIMEOUT_MS UINT64_C(60000)
#define STRATUM_AUTH_INTERLEAVE_MAX 64u

static bool stratum_now_ms(uint64_t *milliseconds)
{
	if (!milliseconds)
		return false;
#ifdef WIN32
	*milliseconds = (uint64_t)GetTickCount64();
	return true;
#else
	{
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return false;
		*milliseconds = (uint64_t)now.tv_sec * UINT64_C(1000) +
			(uint64_t)now.tv_nsec / UINT64_C(1000000);
		return true;
	}
#endif
}

static bool send_bytes(curl_socket_t sock, const char *s, size_t len,
	size_t *total_written, uint64_t deadline_ms)
{
	size_t sent = 0;

	if (!s || !total_written)
		return false;
#ifndef WIN32
	if (sock < 0 || sock >= FD_SETSIZE)
		return false;
#endif
	while (len > 0) {
		struct timeval timeout;
		uint64_t now_ms, remaining_ms;
		int chunk = len > (size_t)INT_MAX ? INT_MAX : (int)len;
		int n;
		int selected;
		int send_flags = 0;
		fd_set wd;

		if (!stratum_now_ms(&now_ms) || now_ms >= deadline_ms)
			return false;
		remaining_ms = deadline_ms - now_ms;
		timeout.tv_sec = (long)(remaining_ms / UINT64_C(1000));
		timeout.tv_usec = (long)((remaining_ms % UINT64_C(1000)) *
			UINT64_C(1000));
		FD_ZERO(&wd);
		FD_SET(sock, &wd);
		selected = select((int) (sock + 1), NULL, &wd, NULL, &timeout);
		if (selected < 0 && socket_interrupted())
			continue;
		if (selected < 1)
			return false;
#ifdef MSG_NOSIGNAL
		send_flags = MSG_NOSIGNAL;
#endif
		n = send(sock, s + sent, chunk, send_flags);
		if (n < 0) {
			if (socket_blocks() || socket_interrupted())
				continue;
			else
				return false;
		}
		if (n == 0)
			return false;
		sent += n;
		*total_written += (size_t)n;
		len -= (size_t)n;
	}

	return true;
}

static enum stratum_wire_result send_line(curl_socket_t sock, const char *s)
{
	uint64_t now_ms, deadline_ms;
	size_t len;
	size_t written = 0;

	if (!s)
		return STRATUM_WIRE_NONE;
	len = strnlen(s, STRATUM_LINE_MAX + 1);
	if (len > STRATUM_LINE_MAX)
		return STRATUM_WIRE_NONE;
	if (!stratum_now_ms(&now_ms) ||
	    now_ms > UINT64_MAX - STRATUM_SEND_TIMEOUT_MS)
		return STRATUM_WIRE_NONE;
	deadline_ms = now_ms + STRATUM_SEND_TIMEOUT_MS;
	if (!send_bytes(sock, s, len, &written, deadline_ms) ||
	    !send_bytes(sock, "\n", 1, &written, deadline_ms))
		return written == 0 ? STRATUM_WIRE_NONE : STRATUM_WIRE_PARTIAL;
	return STRATUM_WIRE_COMPLETE;
}

static bool stratum_send_line_mode(struct stratum_ctx *sctx, const char *s,
	bool share, uint64_t connection_generation, uint64_t job_epoch)
{
	enum stratum_wire_result wire_result;
	bool ret = false;
	bool permitted = false;
	bool work_locked = false;

	if (!sctx || !s)
		return false;
	if (opt_protocol)
		applog(LOG_DEBUG, "> Stratum %s line (%zu bytes)",
			share ? "share" : "control",
			strnlen(s, STRATUM_LINE_MAX + 1));

	pthread_mutex_lock(&sctx->sock_lock);
	if (share && stratum_transport_job_usable(&sctx->transport,
		connection_generation) && sctx->sock != CURL_SOCKET_BAD) {
		pthread_mutex_lock(&sctx->work_lock);
		work_locked = true;
		permitted = sctx->minimum_valid_job_epoch != 0 &&
			job_epoch >= sctx->minimum_valid_job_epoch &&
			job_epoch <= sctx->job_epoch_counter;
	} else if (!share && connection_generation != 0 &&
	    stratum_transport_can_control(&sctx->transport) &&
	    sctx->transport.generation == connection_generation &&
	    sctx->sock != CURL_SOCKET_BAD) {
		permitted = true;
	}
	if (permitted) {
		wire_result = send_line(sctx->sock, s);
		ret = wire_result == STRATUM_WIRE_COMPLETE;
		if (!ret) {
			/* Wake the receive owner immediately.  libcurl still owns the
			 * descriptor and closes it during stratum_disconnect(). */
#ifdef WIN32
			shutdown(sctx->sock, SD_BOTH);
#else
			shutdown(sctx->sock, SHUT_RDWR);
#endif
			stratum_transport_poison(&sctx->transport);
			sctx->sock = CURL_SOCKET_BAD;
			applog(LOG_ERR,
				wire_result == STRATUM_WIRE_PARTIAL ?
				"partial Stratum write poisoned connection" :
				"failed Stratum write poisoned connection");
		}
	}
	if (work_locked)
		pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);

	return ret;
}

bool stratum_send_line(struct stratum_ctx *sctx, const char *s,
	uint64_t connection_generation, uint64_t job_epoch)
{
	return stratum_send_line_mode(sctx, s, true, connection_generation,
		job_epoch);
}

static bool stratum_send_control_line(struct stratum_ctx *sctx,
	const char *s, uint64_t connection_generation)
{
	return stratum_send_line_mode(sctx, s, false, connection_generation, 0);
}

enum stratum_wait_result {
	STRATUM_WAIT_ERROR = -1,
	STRATUM_WAIT_TIMEOUT = 0,
	STRATUM_WAIT_READY = 1
};

static enum stratum_wait_result socket_full_ms(curl_socket_t sock,
	uint64_t timeout_ms)
{
	uint64_t now_ms, deadline_ms;
	bool first = true;

	if (sock == CURL_SOCKET_BAD)
		return STRATUM_WAIT_ERROR;
#ifndef WIN32
	if (sock < 0 || sock >= FD_SETSIZE)
		return STRATUM_WAIT_ERROR;
#endif
	if (!stratum_now_ms(&now_ms) || timeout_ms > UINT64_MAX - now_ms)
		return STRATUM_WAIT_ERROR;
	deadline_ms = now_ms + timeout_ms;
	for (;;) {
		struct timeval tv;
		fd_set rd;
		uint64_t remaining_ms;
		int selected;

		if (!stratum_now_ms(&now_ms) || (!first && now_ms >= deadline_ms))
			return STRATUM_WAIT_TIMEOUT;
		first = false;
		remaining_ms = now_ms < deadline_ms ? deadline_ms - now_ms : 0;
		tv.tv_sec = (long)(remaining_ms / UINT64_C(1000));
		tv.tv_usec = (long)((remaining_ms % UINT64_C(1000)) *
			UINT64_C(1000));
		FD_ZERO(&rd);
		FD_SET(sock, &rd);
		selected = select((int)(sock + 1), &rd, NULL, NULL, &tv);
		if (selected < 0 && socket_interrupted())
			continue;
		if (selected < 0)
			return STRATUM_WAIT_ERROR;
		return selected > 0 ? STRATUM_WAIT_READY : STRATUM_WAIT_TIMEOUT;
	}
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	if (timeout < 0 ||
	    (uint64_t)timeout > UINT64_MAX / UINT64_C(1000))
		return false;
	return socket_full_ms(sock, (uint64_t)timeout * UINT64_C(1000)) ==
		STRATUM_WAIT_READY;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	curl_socket_t sock;
	bool buffered, connected;

	if (!sctx)
		return false;
	pthread_mutex_lock(&sctx->sock_lock);
	buffered = sctx->sockbuf && memchr(sctx->sockbuf, '\n',
		sctx->sockbuf_used) != NULL;
	connected = stratum_transport_can_control(&sctx->transport) &&
		sctx->sock != CURL_SOCKET_BAD;
	sock = sctx->sock;
	pthread_mutex_unlock(&sctx->sock_lock);
	return connected && (buffered || socket_full(sock, timeout));
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_job_release(struct stratum_job *job)
{
	size_t i;

	if (!job)
		return;
	free(job->job_id);
	free(job->coinbase);
	if (job->merkle)
		for (i = 0; i < job->merkle_count; ++i)
			free(job->merkle[i]);
	free(job->merkle);
	memset(job, 0, sizeof(*job));
}

static void stratum_job_detach_locked(struct stratum_ctx *sctx,
	struct stratum_job *detached)
{
	if (!sctx || !detached)
		return;
	*detached = sctx->job;
	memset(&sctx->job, 0, sizeof(sctx->job));
	sctx->bloc_height = 0;
}

static uint64_t stratum_next_job_epoch_locked(struct stratum_ctx *sctx)
{
	sctx->job_epoch_counter++;
	if (sctx->job_epoch_counter == 0) {
		sctx->job_epoch_counter = 1;
		sctx->minimum_valid_job_epoch = 1;
	}
	return sctx->job_epoch_counter;
}

static bool stratum_buffer_append(struct stratum_ctx *sctx, const char *s,
	size_t length)
{
	char *resized;
	size_t required, capacity;

	if (!sctx || !s || (length != 0 && memchr(s, '\0', length)))
		return false;
	if (sctx->sockbuf_used > STRATUM_BUFFER_MAX ||
	    length > STRATUM_BUFFER_MAX - sctx->sockbuf_used)
		return false;
	required = sctx->sockbuf_used + length;
	if (required > STRATUM_BUFFER_MAX)
		return false;
	if (required + 1 > sctx->sockbuf_size) {
		capacity = sctx->sockbuf_size ? sctx->sockbuf_size : RBUFSIZE;
		while (capacity < required + 1) {
			if (capacity > (STRATUM_BUFFER_MAX + 1) / 2) {
				capacity = STRATUM_BUFFER_MAX + 1;
				break;
			}
			capacity *= 2;
		}
		resized = (char *)realloc(sctx->sockbuf, capacity);
		if (!resized)
			return false;
		sctx->sockbuf = resized;
		sctx->sockbuf_size = capacity;
	}
	if (length != 0)
		memcpy(sctx->sockbuf + sctx->sockbuf_used, s, length);
	sctx->sockbuf_used = required;
	sctx->sockbuf[required] = '\0';
	return true;
}

void stratum_request_reconnect(struct stratum_ctx *sctx,
	uint64_t generation)
{
	if (!sctx || !generation)
		return;
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->transport.generation == generation &&
	    sctx->transport.phase != STRATUM_TRANSPORT_DISCONNECTED) {
		if (sctx->sock != CURL_SOCKET_BAD) {
#ifdef WIN32
			shutdown(sctx->sock, SD_BOTH);
#else
			shutdown(sctx->sock, SHUT_RDWR);
#endif
		}
		stratum_transport_poison(&sctx->transport);
		sctx->sock = CURL_SOCKET_BAD;
	}
	pthread_mutex_unlock(&sctx->sock_lock);
}

static char *stratum_recv_line_timeout(struct stratum_ctx *sctx,
	uint64_t timeout_ms, bool allow_idle_timeout, bool *idle_timed_out,
	uint64_t *received_generation)
{
	char received[RBUFSIZE];
	char *newline, *sret = NULL;
	uint64_t generation = 0;
	uint64_t deadline_ms = 0;
	curl_socket_t sock = CURL_SOCKET_BAD;

	if (idle_timed_out)
		*idle_timed_out = false;
	if (received_generation)
		*received_generation = 0;
	if (!sctx)
		goto out;
	pthread_mutex_lock(&sctx->sock_lock);
	if (stratum_transport_can_control(&sctx->transport) &&
	    sctx->sock != CURL_SOCKET_BAD && sctx->sockbuf) {
		generation = sctx->transport.generation;
		sock = sctx->sock;
	}
	pthread_mutex_unlock(&sctx->sock_lock);
	if (!generation)
		goto out;

	while (!(newline = (char *)memchr(sctx->sockbuf, '\n',
			sctx->sockbuf_used))) {
		ssize_t n;
		uint64_t now_ms, remaining_ms;
		enum stratum_wait_result wait_result;

		if (!stratum_now_ms(&now_ms))
			goto failed;
		if (!deadline_ms) {
			if (timeout_ms > UINT64_MAX - now_ms)
				goto failed;
			deadline_ms = now_ms + timeout_ms;
		}
		if (now_ms >= deadline_ms) {
			if (allow_idle_timeout && sctx->sockbuf_used == 0) {
				if (idle_timed_out)
					*idle_timed_out = true;
				goto out;
			}
			applog(LOG_ERR, "stratum_recv_line timed out");
			goto failed;
		}
		remaining_ms = deadline_ms - now_ms;
		wait_result = socket_full_ms(sock, remaining_ms);
		if (wait_result != STRATUM_WAIT_READY) {
			if (wait_result == STRATUM_WAIT_TIMEOUT &&
			    allow_idle_timeout && sctx->sockbuf_used == 0) {
				if (idle_timed_out)
					*idle_timed_out = true;
				goto out;
			}
			applog(LOG_ERR, wait_result == STRATUM_WAIT_TIMEOUT ?
				"stratum_recv_line timed out" :
				"stratum_recv_line socket wait failed");
			goto failed;
		}
		n = recv(sock, received, RECVSIZE, 0);
		if (n == 0) {
			applog(LOG_ERR, "stratum_recv_line connection closed");
			goto failed;
		}
		if (n < 0) {
			if (socket_interrupted() || socket_blocks())
				continue;
			applog(LOG_ERR, "stratum_recv_line failed");
			goto failed;
		}
		pthread_mutex_lock(&sctx->sock_lock);
		if (!stratum_transport_can_control(&sctx->transport) ||
		    sctx->transport.generation != generation ||
		    sctx->sock != sock) {
			pthread_mutex_unlock(&sctx->sock_lock);
			goto failed;
		}
		pthread_mutex_unlock(&sctx->sock_lock);
		if (!stratum_buffer_append(sctx, received, (size_t)n)) {
			applog(LOG_ERR,
				"stratum_recv_line rejected oversized, binary, or OOM input");
			goto failed;
		}
		newline = (char *)memchr(sctx->sockbuf, '\n',
			sctx->sockbuf_used);
		if ((newline && (size_t)(newline - sctx->sockbuf) >
			STRATUM_LINE_MAX) ||
		    (!newline && sctx->sockbuf_used > STRATUM_LINE_MAX)) {
			applog(LOG_ERR, "stratum_recv_line rejected oversized line");
			goto failed;
		}
	}

	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_control(&sctx->transport) ||
	    sctx->transport.generation != generation || sctx->sock != sock) {
		pthread_mutex_unlock(&sctx->sock_lock);
		goto failed;
	}
	newline = (char *)memchr(sctx->sockbuf, '\n', sctx->sockbuf_used);
	if (!newline) {
		pthread_mutex_unlock(&sctx->sock_lock);
		goto failed;
	}
	{
		size_t consumed = (size_t)(newline - sctx->sockbuf) + 1;
		size_t line_length = consumed - 1;
		size_t remaining = sctx->sockbuf_used - consumed;

		if (line_length > STRATUM_LINE_MAX) {
			pthread_mutex_unlock(&sctx->sock_lock);
			goto failed;
		}
		if (line_length != 0 && sctx->sockbuf[line_length - 1] == '\r')
			line_length--;
		if (line_length == 0) {
			applog(LOG_ERR, "stratum_recv_line rejected empty input");
			pthread_mutex_unlock(&sctx->sock_lock);
			goto failed;
		}
		sret = (char *)malloc(line_length + 1);
		if (!sret) {
			pthread_mutex_unlock(&sctx->sock_lock);
			goto failed;
		}
		memcpy(sret, sctx->sockbuf, line_length);
		sret[line_length] = '\0';
		if (remaining != 0)
			memmove(sctx->sockbuf, sctx->sockbuf + consumed,
				remaining);
		sctx->sockbuf_used = remaining;
		sctx->sockbuf[remaining] = '\0';
	}
	pthread_mutex_unlock(&sctx->sock_lock);
	goto out;

failed:
	free(sret);
	sret = NULL;
	stratum_request_reconnect(sctx, generation);

out:
	if (sret && received_generation)
		*received_generation = generation;
	if (sret && opt_protocol)
		applog(LOG_DEBUG, "< %s", sret);
	return sret;
}

char *stratum_recv_line(struct stratum_ctx *sctx,
	uint64_t *received_generation)
{
	return stratum_recv_line_timeout(sctx,
		STRATUM_LINE_ASSEMBLY_TIMEOUT_MS, false, NULL,
		received_generation);
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = (curl_socket_t*) clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl = NULL;
	char *new_url = NULL;
	char *new_curl_url = NULL;
	char *new_sockbuf = NULL;
	char *old_url = NULL;
	char *old_curl_url = NULL;
	char *old_sockbuf = NULL;
	const char *scheme;
	curl_socket_t connected_sock = CURL_SOCKET_BAD;
	uint64_t generation = 0;
	size_t url_length, scheme_length;
	int rc;

	if (!sctx || !url)
		return false;
	url_length = strnlen(url, STRATUM_URL_MAX + 1);
	if (url_length == 0 || url_length > STRATUM_URL_MAX) {
		applog(LOG_ERR, "Invalid Stratum URL");
		return false;
	}
	scheme = strstr(url, "://");
	if (!scheme) {
		applog(LOG_ERR, "Invalid Stratum URL");
		return false;
	}
	scheme_length = strlen(scheme);
	if (scheme_length > SIZE_MAX - 5)
		return false;
	new_url = strdup(url);
	new_curl_url = (char *)malloc(scheme_length + 5);
	new_sockbuf = (char *)calloc(RBUFSIZE, 1);
	curl = curl_easy_init();
	if (!new_url || !new_curl_url || !new_sockbuf || !curl) {
		applog(LOG_ERR, "CURL/Stratum connection allocation failed");
		goto failed;
	}
	snprintf(new_curl_url, scheme_length + 5, "http%s", scheme);

	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl ||
	    sctx->transport.phase != STRATUM_TRANSPORT_DISCONNECTED ||
	    !stratum_transport_begin_connect(&sctx->transport, &generation)) {
		pthread_mutex_unlock(&sctx->sock_lock);
		applog(LOG_ERR, "Stratum connection attempted from invalid state");
		goto failed;
	}
	sctx->sock = CURL_SOCKET_BAD;
	sctx->curl_err_str[0] = '\0';
	pthread_mutex_unlock(&sctx->sock_lock);

#define STRATUM_CURL_SETOPT_OR_FAIL(option, value) do { \
	CURLcode setopt_rc = curl_easy_setopt(curl, (option), (value)); \
	if (setopt_rc != CURLE_OK) { \
		applog(LOG_ERR, "Stratum CURL option %s failed: %s", #option, \
			curl_easy_strerror(setopt_rc)); \
		goto failed; \
	} \
} while (0)
	if (opt_protocol)
		STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_VERBOSE, 1L);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_URL, new_curl_url);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_FRESH_CONNECT, 1L);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_CONNECTTIMEOUT, 30L);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_NOSIGNAL, 1L);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_TCP_NODELAY, 1L);
	if (opt_proxy) {
		STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_PROXY, opt_proxy);
		STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_HTTPPROXYTUNNEL, 1L);
#if LIBCURL_VERSION_NUM >= 0x070f06
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_SOCKOPTFUNCTION,
		sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_OPENSOCKETFUNCTION,
		opensocket_grab_cb);
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_OPENSOCKETDATA, &connected_sock);
#endif
	STRATUM_CURL_SETOPT_OR_FAIL(CURLOPT_CONNECT_ONLY, 1L);
#undef STRATUM_CURL_SETOPT_OR_FAIL

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		goto failed;
	}

#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	{
		long legacy_socket = -1;
		if (curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &legacy_socket) !=
		    CURLE_OK)
			goto failed;
		connected_sock = (curl_socket_t)legacy_socket;
	}
#endif
	if (connected_sock == CURL_SOCKET_BAD ||
	    !stratum_socket_set_nonblocking(connected_sock))
		goto failed;

	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl || sctx->transport.generation != generation ||
	    !stratum_transport_mark_connected(&sctx->transport, generation)) {
		pthread_mutex_unlock(&sctx->sock_lock);
		goto failed;
	}
	old_url = sctx->url;
	old_curl_url = sctx->curl_url;
	old_sockbuf = sctx->sockbuf;
	sctx->url = new_url;
	sctx->curl_url = new_curl_url;
	sctx->sockbuf = new_sockbuf;
	sctx->sockbuf_size = RBUFSIZE;
	sctx->sockbuf_used = 0;
	sctx->curl = curl;
	sctx->sock = connected_sock;
	new_url = NULL;
	new_curl_url = NULL;
	new_sockbuf = NULL;
	curl = NULL;
	pthread_mutex_unlock(&sctx->sock_lock);
	free(old_url);
	free(old_curl_url);
	free(old_sockbuf);

	return true;

failed:
	pthread_mutex_lock(&sctx->sock_lock);
	if (generation != 0 && sctx->transport.generation == generation &&
	    sctx->transport.phase == STRATUM_TRANSPORT_CONNECTING) {
		stratum_transport_poison(&sctx->transport);
		sctx->sock = CURL_SOCKET_BAD;
	}
	pthread_mutex_unlock(&sctx->sock_lock);
	if (curl)
		curl_easy_cleanup(curl);
	free(new_url);
	free(new_curl_url);
	free(new_sockbuf);
	return false;
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	CURL *retired_curl;
	struct stratum_job retired_job = { 0 };
	bool invalidate;

	if (!sctx)
		return;
	pthread_mutex_lock(&sctx->sock_lock);
	retired_curl = sctx->curl;
	invalidate = retired_curl != NULL ||
		sctx->transport.phase != STRATUM_TRANSPORT_DISCONNECTED;
	sctx->curl = NULL;
	sctx->sock = CURL_SOCKET_BAD;
	stratum_transport_poison(&sctx->transport);
	sctx->sockbuf_used = 0;
	if (sctx->sockbuf)
		sctx->sockbuf[0] = '\0';
	pthread_mutex_lock(&sctx->work_lock);
	if (sctx->job.job_id || sctx->job.coinbase || sctx->job.merkle_count ||
	    sctx->job.connection_generation) {
		stratum_job_detach_locked(sctx, &retired_job);
		invalidate = true;
	}
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);
	if (retired_curl)
		curl_easy_cleanup(retired_curl);
	stratum_job_release(&retired_job);
	if (invalidate)
		stratum_work_invalidated();
}

bool stratum_is_authenticated(struct stratum_ctx *sctx)
{
	bool authenticated;

	if (!sctx)
		return false;
	pthread_mutex_lock(&sctx->sock_lock);
	authenticated = sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
		stratum_transport_can_share(&sctx->transport);
	pthread_mutex_unlock(&sctx->sock_lock);
	return authenticated;
}

bool stratum_is_work_current(struct stratum_ctx *sctx,
	uint64_t connection_generation)
{
	bool current;

	if (!sctx)
		return false;
	pthread_mutex_lock(&sctx->sock_lock);
	current = sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
		stratum_transport_job_usable(&sctx->transport,
			connection_generation);
	pthread_mutex_unlock(&sctx->sock_lock);
	return current;
}

bool stratum_is_share_current(struct stratum_ctx *sctx,
	uint64_t connection_generation, uint64_t job_epoch)
{
	bool current = false;

	if (!sctx || !job_epoch)
		return false;
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
	    stratum_transport_job_usable(&sctx->transport,
		connection_generation)) {
		pthread_mutex_lock(&sctx->work_lock);
		current = sctx->minimum_valid_job_epoch != 0 &&
			job_epoch >= sctx->minimum_valid_job_epoch &&
			job_epoch <= sctx->job_epoch_counter;
		pthread_mutex_unlock(&sctx->work_lock);
	}
	pthread_mutex_unlock(&sctx->sock_lock);
	return current;
}

static const char *get_stratum_session_id(json_t *val)
{
	json_t *arr_val;
	size_t i, n;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;
	n = json_array_size(arr_val);
	for (i = 0; i < n; i++) {
		const char *notify;
		json_t *arr = json_array_get(arr_val, i);

		if (!arr || !json_is_array(arr))
			break;
		notify = json_string_value(json_array_get(arr, 0));
		if (!notify)
			continue;
		if (!strcasecmp(notify, "mining.notify"))
			return json_string_value(json_array_get(arr, 1));
	}
	return NULL;
}

static bool stratum_decode_extranonce(json_t *params, size_t pndx,
	uchar **decoded_xnonce1, size_t *decoded_xnonce1_size,
	size_t *decoded_xnonce2_size)
{
	const char *xnonce1;
	json_t *xn2_value;
	uchar *new_xnonce1 = NULL;
	size_t xnonce1_size;
	int64_t xn2_size;

	if (decoded_xnonce1)
		*decoded_xnonce1 = NULL;
	if (decoded_xnonce1_size)
		*decoded_xnonce1_size = 0;
	if (decoded_xnonce2_size)
		*decoded_xnonce2_size = 0;
	if (!json_is_array(params) || !decoded_xnonce1 ||
	    !decoded_xnonce1_size || !decoded_xnonce2_size ||
	    pndx > json_array_size(params) ||
	    json_array_size(params) - pndx < 2)
		goto out;
	xnonce1 = json_string_value(json_array_get(params, pndx));
	if (!xnonce1 || !stratum_hex_bounded(xnonce1,
		    STRATUM_XNONCE1_MAX, &xnonce1_size)) {
		applog(LOG_ERR, "Failed to get extranonce1");
		goto out;
	}
	xn2_value = json_array_get(params, pndx + 1);
	if (!json_is_integer(xn2_value)) {
		applog(LOG_ERR, "Failed to get extranonce2_size");
		goto out;
	}
	xn2_size = json_integer_value(xn2_value);
	if (xn2_size < 2 || xn2_size > (int64_t)STRATUM_XNONCE2_MAX) {
		applog(LOG_INFO, "Failed to get valid n2size in parse_extranonce");
		goto out;
	}
	if (xnonce1_size != 0) {
		new_xnonce1 = (uchar *)malloc(xnonce1_size);
		if (!new_xnonce1 ||
		    !hex2bin(new_xnonce1, xnonce1, xnonce1_size)) {
			applog(LOG_ERR, "Failed to decode extranonce1");
			goto out;
		}
	}
	*decoded_xnonce1 = new_xnonce1;
	*decoded_xnonce1_size = xnonce1_size;
	*decoded_xnonce2_size = (size_t)xn2_size;
	return true;

out:
	free(new_xnonce1);
	return false;
}

static bool stratum_parse_extranonce(struct stratum_ctx *sctx,
	json_t *params, size_t pndx)
{
	const char *xnonce1;
	uchar *new_xnonce1 = NULL;
	uchar *old_xnonce1;
	struct stratum_job retired_job = { 0 };
	size_t xnonce1_size = 0;
	size_t xn2_size = 0;
	uint64_t connection_generation = 0;

	if (!sctx)
		goto out;
	pthread_mutex_lock(&sctx->sock_lock);
	if (stratum_transport_can_control(&sctx->transport) &&
	    sctx->sock != CURL_SOCKET_BAD)
		connection_generation = sctx->transport.generation;
	pthread_mutex_unlock(&sctx->sock_lock);
	if (!connection_generation ||
	    !stratum_decode_extranonce(params, pndx,
		&new_xnonce1, &xnonce1_size, &xn2_size))
		goto out;
	xnonce1 = json_string_value(json_array_get(params, pndx));

	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_control(&sctx->transport) ||
	    sctx->transport.generation != connection_generation ||
	    sctx->sock == CURL_SOCKET_BAD) {
		pthread_mutex_unlock(&sctx->sock_lock);
		goto out;
	}
	pthread_mutex_lock(&sctx->work_lock);
	old_xnonce1 = sctx->xnonce1;
	sctx->xnonce1 = new_xnonce1;
	sctx->xnonce1_size = xnonce1_size;
	sctx->xnonce2_size = xn2_size;
	sctx->minimum_valid_job_epoch =
		stratum_next_job_epoch_locked(sctx);
	new_xnonce1 = NULL;
	stratum_job_detach_locked(sctx, &retired_job);
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);
	free(old_xnonce1);
	stratum_job_release(&retired_job);
	stratum_work_invalidated();

	if (pndx == 0 && opt_debug) /* pool dynamic change */
		applog(LOG_DEBUG, "Stratum set nonce %s with extranonce2 size=%zu",
			xnonce1, xn2_size);

	return true;
out:
	free(new_xnonce1);
	return false;
}

static json_t *stratum_subscribe_request(const char *session_id,
	bool retry)
{
	json_t *request = json_object();
	json_t *params = json_array();
	int failed = 0;

	if (!request || !params)
		goto fail;
	if (!retry) {
		failed |= json_array_append_new(params, json_string(USER_AGENT));
		if (session_id)
			failed |= json_array_append_new(params,
				json_string(session_id));
	}
	failed |= json_object_set_new(request, "id", json_integer(1));
	failed |= json_object_set_new(request, "method",
		json_string("mining.subscribe"));
	if (json_object_set_new(request, "params", params))
		failed = 1;
	params = NULL;
	if (failed)
		goto fail;
	return request;

fail:
	if (params)
		json_decref(params);
	if (request)
		json_decref(request);
	return NULL;
}

static json_t *stratum_authorize_request(const char *user,
	const char *pass)
{
	json_t *request = json_object();
	json_t *params = NULL;
	int failed = 0;

	if (!request || !user || !pass)
		goto fail;
	if (jsonrpc_2) {
		params = json_object();
		if (!params)
			goto fail;
		failed |= json_object_set_new(params, "login", json_string(user));
		failed |= json_object_set_new(params, "pass", json_string(pass));
		failed |= json_object_set_new(params, "agent",
			json_string(USER_AGENT));
		failed |= json_object_set_new(request, "method",
			json_string("login"));
		failed |= json_object_set_new(request, "id", json_integer(1));
	} else {
		params = json_array();
		if (!params)
			goto fail;
		failed |= json_array_append_new(params, json_string(user));
		failed |= json_array_append_new(params, json_string(pass));
		failed |= json_object_set_new(request, "method",
			json_string("mining.authorize"));
		failed |= json_object_set_new(request, "id", json_integer(2));
	}
	if (json_object_set_new(request, "params", params))
		failed = 1;
	params = NULL;
	if (failed)
		goto fail;
	return request;

fail:
	if (params)
		json_decref(params);
	if (request)
		json_decref(request);
	return NULL;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
	unsigned attempt;
	uint64_t connection_generation = 0;

	if (jsonrpc_2)
		return true;
	if (!sctx)
		return false;
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
	    sctx->transport.phase == STRATUM_TRANSPORT_CONNECTED_UNAUTH)
		connection_generation = sctx->transport.generation;
	pthread_mutex_unlock(&sctx->sock_lock);
	if (!connection_generation)
		return false;

	for (attempt = 0; attempt < 2; ++attempt) {
		char *prior_sid = NULL;
		char *new_sid = NULL;
		char *line = NULL;
		char *response = NULL;
		uchar *new_xnonce1 = NULL;
		uchar *old_xnonce1;
		char *old_sid;
		size_t new_xnonce1_size = 0, new_xnonce2_size = 0;
		size_t sid_size = 0;
		json_t *request = NULL;
		json_t *val = NULL, *res_val, *err_val;
		json_error_t err;
		struct stratum_job retired_job = { 0 };
		const char *sid;
		bool rejected;

		if (attempt == 0) {
			bool had_sid;
			pthread_mutex_lock(&sctx->work_lock);
			had_sid = sctx->session_id != NULL;
			if (had_sid)
				prior_sid = strdup(sctx->session_id);
			pthread_mutex_unlock(&sctx->work_lock);
			if (had_sid && !prior_sid)
				goto attempt_failed;
		}
		request = stratum_subscribe_request(prior_sid, attempt != 0);
		if (!request)
			goto attempt_failed;
		line = json_dumps(request, JSON_COMPACT);
		json_decref(request);
		request = NULL;
		if (!line || !stratum_send_control_line(sctx, line,
			connection_generation)) {
			applog(LOG_ERR, "stratum_subscribe send failed");
			goto attempt_failed;
		}
		response = stratum_recv_line_timeout(sctx, UINT64_C(30000),
			false, NULL, NULL);
		if (!response)
			goto attempt_failed;
		val = JSON_LOADS(response, &err);
		if (!val) {
			applog(LOG_ERR, "JSON decode failed(%d): %s", err.line,
				err.text);
			goto attempt_failed;
		}
		if (!json_is_object(val)) {
			applog(LOG_ERR,
				"Stratum subscribe response is not a JSON object");
			goto attempt_failed;
		}
		if (!json_is_integer(json_object_get(val, "id")) ||
		    json_integer_value(json_object_get(val, "id")) != 1)
			goto attempt_failed;
		res_val = json_object_get(val, "result");
		err_val = json_object_get(val, "error");
		rejected = !json_is_array(res_val) ||
			(err_val && !json_is_null(err_val));
		if (rejected) {
			if (opt_debug || attempt != 0) {
				char *reason = err_val ? json_dumps(err_val,
					JSON_COMPACT) : NULL;
				applog(LOG_ERR, "JSON-RPC subscribe failed: %s",
					reason ? reason : "(unknown reason)");
				free(reason);
			}
			free(prior_sid);
			free(line);
			free(response);
			json_decref(val);
			if (attempt == 0)
				continue;
			return false;
		}
		if (!stratum_decode_extranonce(res_val, 1, &new_xnonce1,
			&new_xnonce1_size, &new_xnonce2_size))
			goto attempt_failed;
		sid = get_stratum_session_id(res_val);
		if (sid) {
			if (!stratum_string_bounded(sid, STRATUM_SESSION_ID_MAX,
				&sid_size))
				goto attempt_failed;
			new_sid = (char *)malloc(sid_size + 1);
			if (!new_sid)
				goto attempt_failed;
			memcpy(new_sid, sid, sid_size + 1);
		}

		pthread_mutex_lock(&sctx->sock_lock);
		if (sctx->transport.phase != STRATUM_TRANSPORT_CONNECTED_UNAUTH ||
		    sctx->transport.generation != connection_generation ||
		    sctx->sock == CURL_SOCKET_BAD) {
			pthread_mutex_unlock(&sctx->sock_lock);
			goto attempt_failed;
		}
		pthread_mutex_lock(&sctx->work_lock);
		old_sid = sctx->session_id;
		old_xnonce1 = sctx->xnonce1;
		sctx->session_id = new_sid;
		sctx->xnonce1 = new_xnonce1;
		sctx->xnonce1_size = new_xnonce1_size;
		sctx->xnonce2_size = new_xnonce2_size;
		sctx->next_diff = 1.0;
		sctx->minimum_valid_job_epoch =
			stratum_next_job_epoch_locked(sctx);
		new_sid = NULL;
		new_xnonce1 = NULL;
		stratum_job_detach_locked(sctx, &retired_job);
		pthread_mutex_unlock(&sctx->work_lock);
		pthread_mutex_unlock(&sctx->sock_lock);
		free(old_sid);
		free(old_xnonce1);
		stratum_job_release(&retired_job);
		stratum_work_invalidated();
		if (opt_debug && sid)
			applog(LOG_DEBUG, "Stratum session id: %s", sid);
		free(prior_sid);
		free(line);
		free(response);
		json_decref(val);
		return true;

attempt_failed:
		free(prior_sid);
		free(new_sid);
		free(new_xnonce1);
		free(line);
		free(response);
		if (request)
			json_decref(request);
		if (val)
			json_decref(val);
		return false;
	}
	return false;
}

extern bool opt_extranonce;

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
	json_t *val = NULL, *res_val, *err_val;
	json_t *request = NULL;
	char *s = NULL, *sret = NULL;
	json_error_t err;
	bool ret = false;
	uint64_t connection_generation = 0;
	uint64_t auth_deadline_ms = 0;
	unsigned interleaved = 0;

	if (!sctx || !user || !pass)
		goto out;
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
	    sctx->transport.phase == STRATUM_TRANSPORT_CONNECTED_UNAUTH)
		connection_generation = sctx->transport.generation;
	pthread_mutex_unlock(&sctx->sock_lock);
	if (!connection_generation)
		goto out;

	request = stratum_authorize_request(user, pass);
	if (!request)
		goto out;
	s = json_dumps(request, JSON_COMPACT);
	json_decref(request);
	request = NULL;
	if (!s)
		goto out;

	if (!stratum_send_control_line(sctx, s, connection_generation))
		goto out;
	if (!stratum_now_ms(&auth_deadline_ms) ||
	    auth_deadline_ms > UINT64_MAX - STRATUM_AUTH_TIMEOUT_MS)
		goto out;
	auth_deadline_ms += STRATUM_AUTH_TIMEOUT_MS;

	while (interleaved++ < STRATUM_AUTH_INTERLEAVE_MAX) {
		enum stratum_method_result method_result;
		uint64_t now_ms;

		if (!stratum_now_ms(&now_ms) || now_ms >= auth_deadline_ms)
			goto out;
		sret = stratum_recv_line_timeout(sctx,
			auth_deadline_ms - now_ms, false, NULL, NULL);
		if (!sret)
			goto out;
		method_result = stratum_handle_method(sctx, sret);
		if (method_result == STRATUM_METHOD_FATAL) {
			free(sret);
			goto out;
		}
		if (method_result == STRATUM_METHOD_UNHANDLED)
			break;
		free(sret);
		sret = NULL;
	}
	if (interleaved > STRATUM_AUTH_INTERLEAVE_MAX)
		goto out;

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}
	if (!json_is_object(val) ||
	    !json_is_integer(json_object_get(val, "id")) ||
	    json_integer_value(json_object_get(val, "id")) !=
		(jsonrpc_2 ? 1 : 2)) {
		applog(LOG_ERR, "Stratum authentication response id/type mismatch");
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if ((jsonrpc_2 ? !json_is_object(res_val) : !json_is_true(res_val)) ||
	    (err_val && !json_is_null(err_val)))  {
		applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

	if (jsonrpc_2) {
		json_t *job_val = json_object_get(res_val, "job");
		bool decoded;

		pthread_mutex_lock(&rpc2_login_lock);
		decoded = rpc2_login_decode(val);
		pthread_mutex_unlock(&rpc2_login_lock);
		if (!decoded)
			goto out;
		if (!job_val) {
			applog(LOG_ERR, "RPC2 authentication omitted initial job");
			goto out;
		}
		pthread_mutex_lock(&sctx->work_lock);
		decoded = rpc2_job_decode(job_val, &sctx->work);
		if (decoded) {
			sctx->work.connection_generation = connection_generation;
			sctx->work.job_epoch = stratum_next_job_epoch_locked(sctx);
			sctx->minimum_valid_job_epoch = sctx->work.job_epoch;
		}
		pthread_mutex_unlock(&sctx->work_lock);
		if (!decoded)
			goto out;
	}

	ret = true;

	if (!opt_extranonce)
		goto out;

	// subscribe to extranonce (optional)
	if (!stratum_send_control_line(sctx,
	    "{\"id\":3,\"method\":\"mining.extranonce.subscribe\",\"params\":[]}",
	    connection_generation)) {
		ret = false;
		goto out;
	}

	{
		bool idle_timeout = false;
		sret = stratum_recv_line_timeout(sctx, UINT64_C(3000), true,
			&idle_timeout, NULL);
		if (!sret && idle_timeout) {
			if (opt_debug)
				applog(LOG_DEBUG,
					"stratum extranonce subscribe timed out");
			goto out;
		}
	}
	if (!sret) {
		ret = false;
		goto out;
	}
	{
		json_t *extra = JSON_LOADS(sret, &err);
		if (!extra) {
			applog(LOG_WARNING, "JSON decode failed(%d): %s", err.line, err.text);
			ret = false;
		} else {
			if (json_integer_value(json_object_get(extra, "id")) != 3) {
				enum stratum_method_result method_result;

				// we receive a standard method if extranonce is ignored
				method_result = stratum_handle_method(sctx, sret);
				if (method_result == STRATUM_METHOD_FATAL) {
					json_decref(extra);
					free(sret);
					ret = false;
					goto out;
				}
				if (method_result == STRATUM_METHOD_UNHANDLED)
					ret = false;
			}
			res_val = json_object_get(extra, "result");
			if (opt_debug && (!res_val || json_is_false(res_val)))
				applog(LOG_DEBUG, "extranonce subscribe not supported");
			json_decref(extra);
		}
		free(sret);
	}

out:
	if (ret) {
		pthread_mutex_lock(&sctx->sock_lock);
		ret = sctx->curl && sctx->sock != CURL_SOCKET_BAD &&
			stratum_transport_mark_authenticated(&sctx->transport,
				connection_generation);
		pthread_mutex_unlock(&sctx->sock_lock);
	}
	if (request)
		json_decref(request);
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

// -------------------- RPC 2.0 (XMR/AEON) -------------------------

extern pthread_mutex_t rpc2_login_lock;
extern pthread_mutex_t rpc2_job_lock;

bool rpc2_login_decode(const json_t *val)
{
	const char *id;
	const char *s;
	size_t id_len;

	json_t *res = json_object_get(val, "result");
	if(!res) {
		applog(LOG_ERR, "JSON invalid result");
		goto err_out;
	}

	json_t *tmp;
	tmp = json_object_get(res, "id");
	if(!tmp) {
		applog(LOG_ERR, "JSON inval id");
		goto err_out;
	}
	id = json_string_value(tmp);
	if(!id) {
		applog(LOG_ERR, "JSON id is not a string");
		goto err_out;
	}

	tmp = json_object_get(res, "status");
	if(!tmp) {
		applog(LOG_ERR, "JSON inval status");
		goto err_out;
	}
	s = json_string_value(tmp);
	if(!s) {
		applog(LOG_ERR, "JSON status is not a string");
		goto err_out;
	}
	if(strcmp(s, "OK")) {
		applog(LOG_ERR, "JSON returned status \"%s\"", s);
		return false;
	}
	id_len = strlen(id);
	if (id_len >= sizeof(rpc2_id)) {
		applog(LOG_ERR, "JSON authentication id is too long");
		return false;
	}
	memcpy(rpc2_id, id, id_len + 1);

	if(opt_debug)
		applog(LOG_DEBUG, "Auth id: %s", id);

	return true;

err_out:
	applog(LOG_WARNING,"%s: fail", __func__);
	return false;
}

json_t* json_rpc2_call_recur(CURL *curl, const char *url, const char *userpass,
	json_t *rpc_req, int *curl_err, int flags, int recur)
{
	char auth_id_value[sizeof(rpc2_id)];

	if(recur >= 5) {
		if(opt_debug)
			applog(LOG_DEBUG, "Failed to call rpc command after %i tries", recur);
		return NULL;
	}
	if(!rpc2_id_copy(auth_id_value, sizeof(auth_id_value))) {
		if(opt_debug)
			applog(LOG_DEBUG, "Tried to call rpc2 command before authentication");
		return NULL;
	}
	json_t *params = json_object_get(rpc_req, "params");
	if (params) {
		json_t *auth_id = json_object_get(params, "id");
		if (auth_id) {
			json_string_set(auth_id, auth_id_value);
		}
	}
	json_t *res = json_rpc_call(curl, url, userpass, json_dumps(rpc_req, 0),
			curl_err, flags | JSON_RPC_IGNOREERR);
	if(!res) goto end;
	json_t *error = json_object_get(res, "error");
	if(!error) goto end;
	json_t *message;
	if(json_is_string(error))
		message = error;
	else
		message = json_object_get(error, "message");
	if(!message || !json_is_string(message)) goto end;
	const char *mes = json_string_value(message);
	if(!strcmp(mes, "Unauthenticated")) {
		pthread_mutex_lock(&rpc2_login_lock);
		rpc2_login(curl);
		sleep(1);
		pthread_mutex_unlock(&rpc2_login_lock);
		return json_rpc2_call_recur(curl, url, userpass, rpc_req,
				curl_err, flags, recur + 1);
	} else if(!strcmp(mes, "Low difficulty share") || !strcmp(mes, "Block expired") || !strcmp(mes, "Invalid job id") || !strcmp(mes, "Duplicate share")) {
		json_t *result = json_object_get(res, "result");
		if(!result) {
			goto end;
		}
		json_object_set(result, "reject-reason", json_string(mes));
	} else {
		applog(LOG_ERR, "json_rpc2.0 error: %s", mes);
		return NULL;
	}
	end:
	return res;
}

json_t *json_rpc2_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req, int *curl_err, int flags)
{
	json_t* req_json = JSON_LOADS(rpc_req, NULL);
	json_t* res = json_rpc2_call_recur(curl, url, userpass, req_json, curl_err, flags, 0);
	json_decref(req_json);
	return res;
}

bool rpc2_job_decode(const json_t *job, struct work *work)
{
	json_t *tmp;
	const char *job_id;
	const char *hexblob;
	size_t blob_len;
	uchar *new_blob = NULL;
	char *new_job_id = NULL;
	char *work_job_id = NULL;
	uint32_t new_target = 0;
	bool target_changed = false;

	if (!jsonrpc_2) {
		applog(LOG_ERR, "Tried to decode job without JSON-RPC 2.0");
		return false;
	}
	if (!job || !json_is_object(job)) {
		applog(LOG_ERR, "JSON invalid job");
		goto err_out;
	}
	tmp = json_object_get(job, "job_id");
	job_id = json_string_value(tmp);
	if (!job_id) {
		applog(LOG_ERR, "JSON invalid job id");
		goto err_out;
	}
	tmp = json_object_get(job, "blob");
	hexblob = json_string_value(tmp);
	if (!hexblob) {
		applog(LOG_ERR, "JSON invalid blob");
		goto err_out;
	}
	blob_len = strlen(hexblob);
	if (blob_len % 2 != 0 ||
	    ((blob_len / 2) < 40 && blob_len != 0) ||
	    (blob_len / 2) > 128) {
		applog(LOG_ERR, "JSON invalid blob length");
		goto err_out;
	}
	if (blob_len != 0) {
		new_blob = (uchar *)malloc(blob_len / 2);
		if (!new_blob) {
			applog(LOG_ERR, "RPC2 blob allocation failed");
			goto err_out;
		}
		if (!hex2bin(new_blob, hexblob, blob_len / 2)) {
			applog(LOG_ERR, "JSON invalid blob");
			goto err_out;
		}
		if (!jobj_binary(job, "target", &new_target, 4) ||
		    new_target == 0) {
			applog(LOG_ERR, "JSON invalid target");
			goto err_out;
		}
		new_job_id = strdup(job_id);
		if (!new_job_id) {
			applog(LOG_ERR, "RPC2 job id allocation failed");
			goto err_out;
		}

		/* Commit the complete cache as one locked ownership transfer. */
		pthread_mutex_lock(&rpc2_job_lock);
		free(rpc2_blob);
		free(rpc2_job_id);
		rpc2_blob = (char *)new_blob;
		rpc2_bloblen = blob_len / 2;
		rpc2_job_id = new_job_id;
		new_blob = NULL;
		new_job_id = NULL;
		target_changed = rpc2_target != new_target;
		rpc2_target = new_target;
		stratum_diff = ((double)UINT32_MAX) / new_target;
		pthread_mutex_unlock(&rpc2_job_lock);

		if (target_changed && !opt_quiet)
			applog(LOG_WARNING, "Stratum difficulty set to %g",
				stratum_diff);
	}
	if (work) {
		pthread_mutex_lock(&rpc2_job_lock);
		if (!rpc2_blob || !rpc2_job_id) {
			pthread_mutex_unlock(&rpc2_job_lock);
			applog(LOG_WARNING, "Work requested before it was received");
			goto err_out;
		}
		work_job_id = strdup(rpc2_job_id);
		if (!work_job_id) {
			pthread_mutex_unlock(&rpc2_job_lock);
			applog(LOG_ERR, "RPC2 work job id allocation failed");
			goto err_out;
		}
		memcpy(work->data, rpc2_blob, rpc2_bloblen);
		memset(work->target, 0xff, sizeof(work->target));
		work->target[7] = rpc2_target;
		pthread_mutex_unlock(&rpc2_job_lock);
		free(work->job_id);
		work->job_id = work_job_id;
		work_job_id = NULL;
	}
	return true;

err_out:
	free(new_blob);
	free(new_job_id);
	free(work_job_id);
	applog(LOG_WARNING, "%s", __func__);
	return false;
}

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *ntime;
	struct stratum_job staged = { 0 };
	struct stratum_job retired = { 0 };
	uchar *coinb1_data = NULL;
	uchar *coinb2_data = NULL;
	size_t job_id_size;
	size_t coinb1_size, coinb2_size;
	size_t xnonce2_offset, coinbase_size;
	size_t merkle_count, i;
	uint32_t block_height;
	bool clean, ret = false;
	json_t *merkle_arr, *clean_value;

	if (!sctx || !json_is_array(params) || json_array_size(params) < 9)
		goto out;
	job_id = json_string_value(json_array_get(params, 0));
	prevhash = json_string_value(json_array_get(params, 1));
	coinb1 = json_string_value(json_array_get(params, 2));
	coinb2 = json_string_value(json_array_get(params, 3));
	merkle_arr = json_array_get(params, 4);
	if (!merkle_arr || !json_is_array(merkle_arr))
		goto out;
	merkle_count = (size_t)json_array_size(merkle_arr);
	version = json_string_value(json_array_get(params, 5));
	nbits = json_string_value(json_array_get(params, 6));
	ntime = json_string_value(json_array_get(params, 7));
	clean_value = json_array_get(params, 8);
	clean = json_is_true(clean_value);

	if (!job_id || !stratum_string_bounded(job_id, STRATUM_JOB_ID_MAX,
		    &job_id_size) || job_id_size == 0 ||
	    !prevhash || !coinb1 || !coinb2 || !version || !nbits || !ntime ||
	    !json_is_boolean(clean_value) ||
	    !stratum_hex_exact(prevhash, 32) ||
	    !stratum_hex_exact(version, 4) ||
	    !stratum_hex_exact(nbits, 4) ||
	    !stratum_hex_exact(ntime, 4) ||
	    !stratum_hex_bounded(coinb1, STRATUM_COINBASE_MAX, &coinb1_size) ||
	    !stratum_hex_bounded(coinb2, STRATUM_COINBASE_MAX, &coinb2_size) ||
	    merkle_count > STRATUM_MERKLE_MAX) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}
	staged.job_id = (char *)malloc(job_id_size + 1);
	if (!staged.job_id)
		goto allocation_failed;
	memcpy(staged.job_id, job_id, job_id_size + 1);
	staged.merkle_count = merkle_count;
	if (merkle_count != 0) {
		staged.merkle = (uchar **)calloc(merkle_count,
			sizeof(*staged.merkle));
		if (!staged.merkle)
			goto allocation_failed;
	}
	for (i = 0; i < merkle_count; ++i) {
		const char *s = json_string_value(json_array_get(merkle_arr, i));
		if (!s || !stratum_hex_exact(s, 32)) {
			applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
			goto out;
		}
		staged.merkle[i] = (uchar *)malloc(32);
		if (!staged.merkle[i])
			goto allocation_failed;
		if (!hex2bin(staged.merkle[i], s, 32))
			goto invalid_hex;
	}
	if (coinb1_size != 0) {
		coinb1_data = (uchar *)malloc(coinb1_size);
		if (!coinb1_data)
			goto allocation_failed;
		if (!hex2bin(coinb1_data, coinb1, coinb1_size))
			goto invalid_hex;
	}
	if (coinb2_size != 0) {
		coinb2_data = (uchar *)malloc(coinb2_size);
		if (!coinb2_data)
			goto allocation_failed;
		if (!hex2bin(coinb2_data, coinb2, coinb2_size))
			goto invalid_hex;
	}
	if (!hex2bin(staged.prevhash, prevhash, 32) ||
	    !hex2bin(staged.version, version, 4) ||
	    !hex2bin(staged.nbits, nbits, 4) ||
	    !hex2bin(staged.ntime, ntime, 4))
		goto invalid_hex;
	staged.clean = clean;

	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_control(&sctx->transport) ||
	    sctx->sock == CURL_SOCKET_BAD) {
		pthread_mutex_unlock(&sctx->sock_lock);
		applog(LOG_ERR, "Stratum notify: inactive connection");
		goto out;
	}
	pthread_mutex_lock(&sctx->work_lock);
	if ((sctx->xnonce1_size != 0 && !sctx->xnonce1) ||
	    sctx->xnonce1_size > STRATUM_XNONCE1_MAX ||
	    sctx->xnonce2_size < 2 ||
	    sctx->xnonce2_size > STRATUM_XNONCE2_MAX ||
	    !isfinite(sctx->next_diff) || sctx->next_diff <= 0.0 ||
	    !stratum_coinbase_layout(coinb1_size, sctx->xnonce1_size,
		sctx->xnonce2_size, coinb2_size, &xnonce2_offset,
		&coinbase_size)) {
		pthread_mutex_unlock(&sctx->work_lock);
		pthread_mutex_unlock(&sctx->sock_lock);
		applog(LOG_ERR,
			"Stratum notify: invalid live extranonce/difficulty state");
		goto out;
	}
	staged.coinbase = (uchar *)malloc(coinbase_size);
	if (!staged.coinbase) {
		pthread_mutex_unlock(&sctx->work_lock);
		pthread_mutex_unlock(&sctx->sock_lock);
		goto allocation_failed;
	}
	staged.coinbase_size = coinbase_size;
	staged.xnonce2_offset = xnonce2_offset;
	staged.xnonce2_size = sctx->xnonce2_size;
	if (coinb1_size != 0)
		memcpy(staged.coinbase, coinb1_data, coinb1_size);
	if (sctx->xnonce1_size != 0)
		memcpy(staged.coinbase + coinb1_size, sctx->xnonce1,
			sctx->xnonce1_size);
	if (sctx->job.job_id && sctx->job.coinbase &&
	    !strcmp(sctx->job.job_id, staged.job_id) &&
	    sctx->job.connection_generation == sctx->transport.generation &&
	    sctx->job.xnonce2_size == staged.xnonce2_size &&
	    stratum_xnonce_layout_valid(sctx->job.coinbase_size,
		sctx->job.xnonce2_offset, sctx->job.xnonce2_size))
		memcpy(staged.coinbase + staged.xnonce2_offset,
			sctx->job.coinbase + sctx->job.xnonce2_offset,
			staged.xnonce2_size);
	else
		memset(staged.coinbase + staged.xnonce2_offset, 0,
			staged.xnonce2_size);
	if (coinb2_size != 0)
		memcpy(staged.coinbase + staged.xnonce2_offset +
			staged.xnonce2_size, coinb2_data, coinb2_size);
	staged.diff = sctx->next_diff;
	staged.connection_generation = sctx->transport.generation;
	staged.job_epoch = stratum_next_job_epoch_locked(sctx);
	if (sctx->minimum_valid_job_epoch == 0 || staged.clean)
		sctx->minimum_valid_job_epoch = staged.job_epoch;
	block_height = stratum_coinbase_height(staged.coinbase,
		staged.coinbase_size);
	stratum_job_detach_locked(sctx, &retired);
	sctx->job = staged;
	memset(&staged, 0, sizeof(staged));
	sctx->bloc_height = block_height;
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);
	stratum_job_release(&retired);
	/* A pool may legally refresh ntime/coinbase under the same textual job
	 * id.  The publication timestamp, not only job-id comparison, must force
	 * the next generation pass. */
	stratum_work_invalidated();

	ret = true;
	goto out;

allocation_failed:
	applog(LOG_ERR, "Stratum notify: allocation failed");
	goto out;
invalid_hex:
	applog(LOG_ERR, "Stratum notify: invalid hexadecimal data");

out:
	free(coinb1_data);
	free(coinb2_data);
	stratum_job_release(&staged);
	return ret;
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
	double diff;
	uint32_t target_probe[8];

	if (!sctx || !json_is_array(params) ||
	    !json_is_number(json_array_get(params, 0)))
		return false;
	diff = json_number_value(json_array_get(params, 0));
	if (!diff_to_target_checked(target_probe, diff))
		return false;

	pthread_mutex_lock(&sctx->sock_lock);
	if (!stratum_transport_can_control(&sctx->transport) ||
	    sctx->sock == CURL_SOCKET_BAD) {
		pthread_mutex_unlock(&sctx->sock_lock);
		return false;
	}
	pthread_mutex_lock(&sctx->work_lock);
	sctx->next_diff = diff;
	pthread_mutex_unlock(&sctx->work_lock);
	pthread_mutex_unlock(&sctx->sock_lock);

	/* store for api stats */
	pthread_mutex_lock(&stats_lock);
	stratum_diff = diff;
	pthread_mutex_unlock(&stats_lock);

	applog(LOG_WARNING, "Stratum difficulty set to %g", diff);

	return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	char *url = NULL;
	const char *host;
	char *end = NULL;
	long parsed_port;
	size_t host_length;
	size_t url_size;

	if (!sctx || !json_is_array(params) || json_array_size(params) < 2)
		return false;
	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (!host || !stratum_string_bounded(host, 1024, &host_length) ||
	    host_length == 0)
		return false;
	if (json_is_integer(port_val)) {
		parsed_port = json_integer_value(port_val);
	} else if (json_is_string(port_val)) {
		const char *port_text = json_string_value(port_val);
		errno = 0;
		parsed_port = strtol(port_text, &end, 10);
		if (errno || !end || *end != '\0')
			return false;
	} else {
		return false;
	}
	if (parsed_port < 1 || parsed_port > 65535 ||
	    host_length > SIZE_MAX - 32)
		return false;
	url_size = host_length + 32;
	url = (char *)malloc(url_size);
	if (!url)
		return false;
	if (snprintf(url, url_size, "stratum+tcp://%s:%ld", host,
		parsed_port) < 0) {
		free(url);
		return false;
	}

	if (!opt_redirect) {
		applog(LOG_INFO, "Ignoring request to reconnect to %s", url);
		free(url);
		return true;
	}

	applog(LOG_NOTICE, "Server requested reconnection to %s", url);

	free(sctx->url);
	sctx->url = url;
	stratum_disconnect(sctx);

	return true;
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id,
	uint64_t connection_generation)
{
	char *s = NULL;
	json_t *val = NULL;
	bool ret = false;
	
	if (!id || json_is_null(id))
		return false;

	val = json_object();
	if (val && !json_object_set(val, "id", id) &&
	    !json_object_set_new(val, "error", json_null()) &&
	    !json_object_set_new(val, "result", json_string(USER_AGENT))) {
		s = json_dumps(val, 0);
		if (s)
			ret = stratum_send_control_line(sctx, s,
				connection_generation);
	}
	if (val)
		json_decref(val);
	free(s);

	return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id,
	json_t *params, uint64_t connection_generation)
{
	char *s = NULL;
	json_t *val = NULL;
	json_t *message;
	bool ret = false;

	if (!json_is_array(params))
		return false;
	message = json_array_get(params, 0);
	if (message && !json_is_string(message))
		return false;
	if (message)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s",
			json_string_value(message));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	if (val && !json_object_set(val, "id", id) &&
	    !json_object_set_new(val, "error", json_null()) &&
	    !json_object_set_new(val, "result", json_true())) {
		s = json_dumps(val, 0);
		if (s)
			ret = stratum_send_control_line(sctx, s,
				connection_generation);
	}
	if (val)
		json_decref(val);
	free(s);

	return ret;
}

enum stratum_method_result stratum_handle_method(struct stratum_ctx *sctx,
	const char *s)
{
	json_t *val, *id, *params;
	json_error_t err;
	const char *method;
	uint64_t connection_generation = 0;
	enum stratum_method_result result = STRATUM_METHOD_UNHANDLED;
	bool ok;

	if (!sctx || !s)
		return STRATUM_METHOD_FATAL;
	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		result = STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!json_is_object(val)) {
		result = STRATUM_METHOD_FATAL;
		goto out;
	}

	method = json_string_value(json_object_get(val, "method"));
	if (!method)
		goto out;
	pthread_mutex_lock(&sctx->sock_lock);
	if (stratum_transport_can_control(&sctx->transport) &&
	    sctx->sock != CURL_SOCKET_BAD)
		connection_generation = sctx->transport.generation;
	pthread_mutex_unlock(&sctx->sock_lock);
	if (!connection_generation) {
		result = STRATUM_METHOD_FATAL;
		goto out;
	}

	params = json_object_get(val, "params");

	if (jsonrpc_2) {
		if (!strcasecmp(method, "job")) {
			result = rpc2_stratum_job(sctx, params) ?
				STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		} else {
			result = STRATUM_METHOD_HANDLED;
		}
		goto out;
	}

	id = json_object_get(val, "id");

	if (!strcasecmp(method, "mining.notify")) {
		result = stratum_notify(sctx, params) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!strcasecmp(method, "mining.set_difficulty")) {
		result = stratum_set_difficulty(sctx, params) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!strcasecmp(method, "mining.set_extranonce")) {
		result = stratum_parse_extranonce(sctx, params, 0) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!strcasecmp(method, "client.reconnect")) {
		result = stratum_reconnect(sctx, params) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!strcasecmp(method, "client.get_version")) {
		result = stratum_get_version(sctx, id, connection_generation) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	if (!strcasecmp(method, "client.show_message")) {
		result = stratum_show_message(sctx, id, params,
			connection_generation) ?
			STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;
		goto out;
	}
	/* Unknown extension notifications are intentionally ignored. */
	ok = method[0] != '\0';
	result = ok ? STRATUM_METHOD_HANDLED : STRATUM_METHOD_FATAL;

out:
	if (val)
		json_decref(val);

	return result;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;
	int rc;

	tq = (struct thread_q*) calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	rc = pthread_mutex_init(&tq->mutex, NULL);
	if (rc != 0) {
		free(tq);
		return NULL;
	}
	rc = pthread_cond_init(&tq->cond, NULL);
	if (rc != 0) {
		pthread_mutex_destroy(&tq->mutex);
		free(tq);
		return NULL;
	}

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = (struct tq_ent*) calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}

/* sprintf can be used in applog */
static char* format_hash(char* buf, uint8_t *hash)
{
	int i, len = 0;
	for (i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void applog_hash(void *hash)
{
	char s[128] = {'\0'};
	applog(LOG_DEBUG, "%s", format_hash(s, (uchar*) hash));
}

/* Provide a ms based sleep that uses nanosleep to avoid poor usleep accuracy
 * on SMP machines */
void nmsleep(unsigned int msecs)
{
	struct timespec twait, tleft;
	int ret;
	ldiv_t d;

	d = ldiv(msecs, 1000);
	tleft.tv_sec = d.quot;
	tleft.tv_nsec = d.rem * 1000000;
	do {
		twait.tv_sec = tleft.tv_sec;
		twait.tv_nsec = tleft.tv_nsec;
		ret = nanosleep(&twait, &tleft);
	} while (ret == -1 && errno == EINTR);
}
