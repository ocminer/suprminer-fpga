#ifndef SUPRMINER_SHA3_VARIANT_RECONFIG_H
#define SUPRMINER_SHA3_VARIANT_RECONFIG_H

#include <stdbool.h>
#include <stdint.h>

/* A fixed-image transition is not committed merely because configuration
 * returned success.  The newly loaded image must produce a CPU-verified
 * diagnostic samples within this monotonic deadline.  Thirty seconds is long
 * enough to tolerate transient shared-USB readback delays while remaining
 * short enough to avoid knowingly leaving a ZTEX lane idle until it wedges. */
#define SHA3_VARIANT_RECONFIG_TIMEOUT_US UINT64_C(30000000)
#define SHA3_VARIANT_RECONFIG_MIN_CLEAN_CHECKS 20U

enum sha3_variant_reconfig_action {
	SHA3_VARIANT_RECONFIG_WAIT = 0,
	SHA3_VARIANT_RECONFIG_PROVEN,
	SHA3_VARIANT_RECONFIG_ROLLBACK
};

/* Pure policy used by the USB-owning board worker.  checks/errors are reset
 * when an image is loaded, and the deadline starts only after work has been
 * published to that image.  A mismatch, corrupt counters, a regressing clock,
 * or failure to prove enough distinct clean progress by the deadline all fail
 * closed. */
static inline enum sha3_variant_reconfig_action
sha3_variant_reconfig_decide(bool pending, uint64_t work_started_us,
		uint64_t now_us, unsigned checks, unsigned errors)
{
	if (!pending)
		return SHA3_VARIANT_RECONFIG_WAIT;
	if (errors > checks || errors > 0)
		return SHA3_VARIANT_RECONFIG_ROLLBACK;
	if (work_started_us == 0)
		return SHA3_VARIANT_RECONFIG_WAIT;
	if (now_us < work_started_us ||
	    now_us - work_started_us >= SHA3_VARIANT_RECONFIG_TIMEOUT_US)
		return SHA3_VARIANT_RECONFIG_ROLLBACK;
	if (checks >= SHA3_VARIANT_RECONFIG_MIN_CLEAN_CHECKS)
		return SHA3_VARIANT_RECONFIG_PROVEN;
	return SHA3_VARIANT_RECONFIG_WAIT;
}

#endif
