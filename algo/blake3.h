#ifndef BLAKE3_H
#define BLAKE3_H

#include <stdint.h>

/* Hash a 180-byte Decred block header with BLAKE3 */
void blake3_hash_180(const void *input, void *output);

/* Public BLAKE3 compression function for host-side precompute */
void blake3_compress_host(const uint32_t cv[8], const uint32_t block_words[16],
                          uint64_t counter, uint32_t block_len, uint32_t flags,
                          uint32_t out[8]);

#endif /* BLAKE3_H */
