#ifndef BLAKE256_8_H
#define BLAKE256_8_H

#include <stdint.h>

void blake256_8_midstate(unsigned char *midstate, unsigned char *data);
void blake256_8_hash(unsigned char *hash, unsigned char *data);
int scanhash_blakecoin(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done);

#endif
