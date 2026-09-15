#ifndef SUPRMINER_SHA3_VARIANT_CATALOG_H
#define SUPRMINER_SHA3_VARIANT_CATALOG_H

#include "sha3_variant_family.h"

/* Synthetic descriptor for offline tests only. No real image is selected.
 * --auto-freq remains disabled until an operator supplies a validated family. */
#define SHA3_VARIANT_CATALOG_BOUND false
#define SHA3_VARIANT_CATALOG_COUNT 1U
#define SHA3_VARIANT_CATALOG_DEFAULT_RUNG 0
#define SHA3_VARIANT_CATALOG_FAMILY_ID "example-unbound-v1"

static const struct sha3_variant_spec sha3_variant_catalog[
		SHA3_VARIANT_CATALOG_COUNT] = {
	{
		.state_id = "example-unbound",
		.bitfile = "example-unbound.bit",
		.sha256_hex =
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.engines = 1,
		.clock_hz_numerator = UINT64_C(72000000),
		.clock_hz_denominator = UINT64_C(1),
		.expected_rate_hps_floor = UINT64_C(1000000),
	},
};

#endif
