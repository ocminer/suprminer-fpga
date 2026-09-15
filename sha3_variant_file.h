#ifndef SUPRMINER_SHA3_VARIANT_FILE_H
#define SUPRMINER_SHA3_VARIANT_FILE_H

#include <stddef.h>

#define SHA3_VARIANT_FILE_SHA256_HEX_SIZE 65U

enum sha3_variant_file_status {
	SHA3_VARIANT_FILE_OK = 0,
	SHA3_VARIANT_FILE_MISSING,
	SHA3_VARIANT_FILE_INVALID,
	SHA3_VARIANT_FILE_IO_ERROR,
	SHA3_VARIANT_FILE_DIGEST_MISMATCH
};

/* Hash one regular pathname and compare it with the descriptor digest. The
 * caller receives the observed lowercase digest on OK or mismatch. */
enum sha3_variant_file_status sha3_variant_file_check(const char *path,
		const char *expected_sha256,
		char actual_sha256[SHA3_VARIANT_FILE_SHA256_HEX_SIZE]);

#endif
