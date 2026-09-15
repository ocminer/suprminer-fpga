#!/usr/bin/env python3
"""Compile and run the production BS1 worker with no sockets or hardware.

Usage: python3 test_vu9p_worker.py CHECKOUT [WORKER_SOURCE]
WORKER_SOURCE defaults to CHECKOUT/fpga-miner.c. The actual work structure,
work_free, deep-clone, full-target comparator, publication retry and BS1
nonce policy are reused.
The Stratum generator/submit boundary and device operations are controlled
mocks. This does not claim a real pool, bridge, signal-drain or hash KAT.
"""
import pathlib
import re
import resource
import subprocess
import sys
import tempfile


def function(text, name):
    match = re.search(r"(?m)^(?:static )?[^\n]*\b" + name + r"\([^;]*?\n\{", text)
    if not match:
        raise AssertionError(f"missing production function {name}")
    end = text.index("\n}", match.end()) + 2
    return text[match.start():end]


C = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include "libvu9p.h"
#include "vu9p_bs1_policy.h"
#include "work_publish_guard.h"
#include "work_type.inc"
#include "work_clone_checked.h"
#include "work_free.inc"

struct thr_info { int id; int vu9p_card; };
struct { int restart; } work_restart[8];
struct vu9p_card g_vu9p_cards[VU9P_MAX_CARDS];
int g_vu9p_card_count = 1;
static bool have_stratum = true, jsonrpc_2 = false;
static int stratum;
static uint32_t opt_vu9p_active_lanes = 1, opt_vu9p_poll_work_ms = 300;
static uint64_t opt_vu9p_rate_hps = 300000000;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static double thr_hashrates[8];
#define VU9P_TEMP_INTERVAL_S 10
#define VU9P_POLL_INTERVAL_MS VU9P_POLL_PERIOD_MS
#define LOG_INFO 1
#define LOG_ERR 2
#define LOG_WARNING 3
#define LOG_DEBUG 4
static bool opt_debug = false;
static void applog(int level, const char *format, ...) { (void)level; (void)format; }

enum stratum_gen_result { STRATUM_GEN_FATAL=-1, STRATUM_GEN_WAIT=0, STRATUM_GEN_READY=1 };
enum scenario {
    READY_SHARE, WAIT_READY, FATAL_READY, GEN_RACE, JOB_STALE_BEFORE,
    JOB_STALE_POLL, GEN_RACE_POLL, EXPIRED_POLL, SEND_FAIL, POLL_FAIL,
    TEMP_FAIL, RETRY_OK, RETRY_FAIL, RETRY_STOP_FAIL, COUNTER_OVERRUN,
    COUNTER_REGRESSION, THRESHOLD_SHARE, BAD_HASH, FULLTARGET_FAIL,
    TEMP_STALES_JOB, STOP_FAIL, ZERO_NONCE_EQUALITY, COUNT
};
static const char *labels[] = {
    "ready-owned-share", "wait-no-work", "fatal-no-work", "restart-generation-race",
    "job-expired-before-work", "job-expired-during-poll", "generation-during-poll",
    "age-expired-during-poll", "ambiguous-work", "poll-disconnect", "temp-fails-stopped",
    "queue-retry-stopped", "queue-retries-exhausted", "queue-stop-failure",
    "counter-overrun-after-stall", "counter-regression", "threshold-found-accounted",
    "cpu-mismatch", "full-target-rejection", "job-expired-during-temp", "stop-failure", "nonce-zero-full-target-equality"
};
static enum scenario sc;
static int gens, sends, polls, stops, temps, submits, closes, sleeps, cpu_checks;
static bool active, share_current = true, copied;
static uint64_t generation = 1;
static uint64_t ms = 1000000;
static time_t work_time = 1000;
static struct work queued;
static uint32_t good_nonce = 0x12345678;
static const uint32_t good_hash7 = 0x182;
static time_t fake_time(time_t *p) { time_t t=(time_t)(ms/1000); if(p)*p=t; return t; }
static int fake_gettimeofday(struct timeval *t, void *z) { (void)z; t->tv_sec=ms/1000; t->tv_usec=(ms%1000)*1000; return 0; }
static int fake_close(int fd) { assert(fd==42); closes++; return 0; }
static void nmsleep(unsigned n) { assert(++sleeps<10); assert(!active || n==50); ms+=n; }
static uint64_t current_work_generation(void) { return generation; }
static time_t current_work_time(void) { return work_time; }
static bool stratum_is_share_current(void *s, uint64_t cg, uint64_t je) {
    assert(s==&stratum); assert(cg==77 && je==900); return share_current;
}
static void be32enc(void *p, uint32_t v) {
    unsigned char *b=p; b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;
}
static void swap_endian(void *out, const void *in, size_t len) {
    const uint32_t *w=in; unsigned char *b=out;
    for(size_t i=0;i<len/4;i++)be32enc(b+4*i,w[i]);
}
static void sha3256t_hash(void *out, const void *in) {
    const unsigned char *b=in; uint32_t *h=out; cpu_checks++;
    for(int i=0;i<19;i++) { unsigned char exp[4]; be32enc(exp,0x100u+(unsigned)i); assert(!memcmp(b+4*i,exp,4)); }
    unsigned char exp[4]; be32enc(exp,good_nonce); assert(!memcmp(b+76,exp,4));
    memset(h,0,32); h[7]=(sc==BAD_HASH)?good_hash7+1:good_hash7;
    if(sc==FULLTARGET_FAIL)h[0]=1; /* Equal high word, hash one above target. */
}
static void bin2hex(char *out, const unsigned char *in, size_t len) {
    (void)out;(void)in;(void)len;assert(!"unexpected debug conversion");
}
#include "fulltest.inc"
static enum stratum_gen_result stratum_gen_work_result(void *s,struct work *w) {
    assert(s==&stratum && !active); assert(++gens<4); assert(!w->job_id&&!w->xnonce2);
    if(sc==WAIT_READY&&gens==1)return STRATUM_GEN_WAIT;
    w->job_id=strdup("owned-job"); w->xnonce2=malloc(4); assert(w->job_id&&w->xnonce2);
    memset(w->xnonce2,0xab,4); w->xnonce2_len=4;
    w->connection_generation=77; w->job_epoch=900;
    if(sc==FATAL_READY&&gens==1)return STRATUM_GEN_FATAL;
    for(int i=0;i<19;i++)w->data[i]=0x100u+(unsigned)i;
    w->target[7]=good_hash7;
    share_current=true;
    if(sc==GEN_RACE&&gens==1)generation++;
    if(sc==JOB_STALE_BEFORE&&gens==1)share_current=false;
    return STRATUM_GEN_READY;
}
int vu9p_temp(struct vu9p_card *c,struct vu9p_temp_reply *r) {
    assert(c==&g_vu9p_cards[0]&&!active); temps++; memset(r,0,sizeof(*r));
    if(sc==TEMP_STALES_JOB&&temps==1)share_current=false;
    return sc==TEMP_FAIL?-1:0;
}
int vu9p_send_work(struct vu9p_card *c,const unsigned char h[76],uint32_t target,uint32_t base) {
    assert(c==&g_vu9p_cards[0]&&!active&&share_current); assert(++sends==1);
    assert(temps==1&&target==good_hash7&&base==0);
    for(int i=0;i<19;i++){ unsigned char exp[4];be32enc(exp,0x100u+(unsigned)i);assert(!memcmp(h+4*i,exp,4));}
    active=true; return sc==SEND_FAIL?-1:0;
}
int vu9p_poll(struct vu9p_card *c,uint32_t *n,uint32_t *h,uint64_t *count,uint32_t *last) {
    assert(c==&g_vu9p_cards[0]&&active); assert(++polls<3); ms+=1000;
    *n=good_nonce; *h=*last=good_hash7; *count=100000000;
    if(sc==POLL_FAIL){c->fd=-1;return -1;}
    if(sc==JOB_STALE_POLL)share_current=false;
    if(sc==GEN_RACE_POLL)generation++;
    if(sc==EXPIRED_POLL)work_time=0;
    if(sc==COUNTER_OVERRUN){ms+=60000;*count=VU9P_NONCE_SPACE_HASHES+1;}
    if(sc==COUNTER_REGRESSION){if(polls==2)*count=99;return 0;}
    if(sc==THRESHOLD_SHARE)*count=VU9P_NONCE_SPACE_HASHES;
    if(sc==BAD_HASH||sc==FULLTARGET_FAIL||sc==STOP_FAIL)c->enabled=false;
    return 1;
}
int vu9p_stop(struct vu9p_card *c) {
    assert(c==&g_vu9p_cards[0]&&active); assert(++stops==1); active=false;
    c->enabled=false;
    return sc==RETRY_STOP_FAIL||sc==STOP_FAIL?-1:0;
}
static void guarded_work_free(struct work *w) { assert(!active); work_free(w); }
static bool submit_work(struct thr_info *thr,const struct work *w) {
    assert(thr->id==4); submits++;
    assert(w->connection_generation==77&&w->job_epoch==900);
    assert(w->dev_board==-1&&w->dev_fpga==-1&&w->data[19]==good_nonce);
    assert(!strcmp(w->job_id,"owned-job")&&w->xnonce2_len==4);
    if(sc==RETRY_FAIL||sc==RETRY_STOP_FAIL||(sc==RETRY_OK&&submits==1)) {
        if(submits>1)assert(!active); return false;
    }
    if(submits>1)assert(!active);
    assert(work_clone_checked(&queued,w)); copied=true;
    assert(queued.job_id!=w->job_id&&queued.xnonce2!=w->xnonce2);
    g_vu9p_cards[0].enabled=false;
    return true;
}
static bool work_publish_submit_work(void *t,const void *w) { return submit_work(t,w); }
static void work_publish_retry_pause(void *t,unsigned attempt) { (void)t;(void)attempt;assert(!active);nmsleep(10); }
#define time fake_time
#define gettimeofday fake_gettimeofday
#define close fake_close
#define work_free guarded_work_free
#include "worker.inc"
#undef work_free
int main(int argc,char **argv) {
    assert(argc==2); sc=(enum scenario)atoi(argv[1]); assert(sc>=0&&sc<COUNT);
    if(sc==ZERO_NONCE_EQUALITY)good_nonce=0;
    struct thr_info thread={.id=4,.vu9p_card=0};
    g_vu9p_cards[0].enabled=true;g_vu9p_cards[0].fd=42;
    assert(vu9p_miner_thread(&thread)==NULL);
    assert(!active&&!g_vu9p_cards[0].enabled);
    assert(thr_hashrates[4]==0&&g_vu9p_cards[0].mhs==0);
    assert(g_vu9p_cards[0].fd==-1);
    assert(closes==(sc==POLL_FAIL?0:1));
    assert(sends==(sc==TEMP_FAIL?0:1));
    assert(stops==(sc==TEMP_FAIL?0:1));
    assert(temps==1);
    assert(gens==((sc==WAIT_READY||sc==FATAL_READY||sc==GEN_RACE||sc==JOB_STALE_BEFORE||sc==TEMP_STALES_JOB)?2:1));
    bool share=(sc==READY_SHARE||sc==WAIT_READY||sc==FATAL_READY||sc==GEN_RACE||sc==JOB_STALE_BEFORE||sc==RETRY_OK||sc==THRESHOLD_SHARE||sc==TEMP_STALES_JOB||sc==STOP_FAIL||sc==ZERO_NONCE_EQUALITY);
    assert(copied==share);
    assert(submits==(sc==RETRY_FAIL?3:sc==RETRY_OK?2:sc==RETRY_STOP_FAIL?1:share?1:0));
    assert(cpu_checks==((share||sc==RETRY_FAIL||sc==RETRY_STOP_FAIL||sc==BAD_HASH||sc==FULLTARGET_FAIL||sc==STOP_FAIL)?1:0));
    assert(g_vu9p_cards[0].hw_errors==(sc==BAD_HASH?1u:0u));
    if(copied){assert(!strcmp(queued.job_id,"owned-job")&&queued.xnonce2[0]==0xab);work_free(&queued);}
    printf("PASS %s\n",labels[sc]);
    return 0;
}
'''

def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = pathlib.Path(sys.argv[1]).resolve()
    worker_path = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv)>2 else root/'fpga-miner.c'
    main_source=(root/'fpga-miner.c').read_text()
    worker_source=worker_path.read_text()
    worker='\n\n'.join(function(worker_source,n) for n in ('vu9p_work_is_current','vu9p_miner_thread'))
    work_struct=re.search(r'(?ms)^struct work \{.*?^};',(root/'miner.h').read_text()).group(0)
    with tempfile.TemporaryDirectory(prefix='suprminer-vu9p-worker-test-') as td:
        out=pathlib.Path(td)
        (out/'work_type.inc').write_text(work_struct)
        (out/'work_free.inc').write_text(function(main_source,'work_free'))
        (out/'fulltest.inc').write_text(function((root/'util.c').read_text(),'fulltest'))
        (out/'worker.inc').write_text(worker)
        (out/'test.c').write_text(C)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-misleading-indentation','-I',str(root),str(out/'test.c'),'-pthread','-o',str(out/'test')],check=True,timeout=30)
        for case in range(22):
            subprocess.run([str(out/'test'),str(case)],check=True,timeout=3)
    print('22 production-worker mock cases passed; no network/hardware operations')

if __name__=='__main__':
    main()
