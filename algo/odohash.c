// odohash.c - OdoCrypt + Keccak800 hash wrapper for fpga_miner
// Calls into odocrypt.cpp (C++) and KeccakP-800 (C)

#include <string.h>
#include <stdint.h>

// Declared in odocrypt_wrapper.cpp
extern void odocrypt_hash(const void *input, void *output, uint32_t odo_key);

void odohash(void *output, const void *input, uint32_t odo_key)
{
    odocrypt_hash(input, output, odo_key);
}
