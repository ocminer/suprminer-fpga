// odo_verify.c - Verify hash computation matches FPGA
// Compile: gcc -o odo_verify odo_verify.c build/CMakeFiles/fpga_miner.dir/algo/odohash.c.o build/CMakeFiles/fpga_miner.dir/algo/odocrypt_wrapper.cpp.o build/CMakeFiles/fpga_miner.dir/algo/odocrypt.cpp.o build/CMakeFiles/fpga_miner.dir/algo/KeccakP-800-reference.c.o -lstdc++ -lm
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void odohash(void *output, const void *input, uint32_t odo_key);

int main() {
    // Simulate the exact bytes from the miner debug output
    // work_bytes: 20000e02 3676257d ... nonce: 3f181700
    // This means work.data[0] = 0x020e0020 (LE), work.data[1] = 0x7d257636 (LE)
    
    // Let's use a simple test: all zeros header with nonce=1
    uint8_t header[80];
    memset(header, 0, 80);
    header[76] = 1; // nonce = 1 (LE byte 0)
    
    uint32_t odo_key = 1774656000;
    uint8_t hash[32];
    
    odohash(hash, header, odo_key);
    
    uint32_t *h32 = (uint32_t*)hash;
    printf("Hash for zeros+nonce1: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\nhash[7] = %08X\n", h32[7]);
    
    // Now test: what if the bytes are byte-swapped per word?
    uint32_t *hdr32 = (uint32_t*)header;
    // Byte-reverse each word (simulate swap_endian)
    for (int i = 0; i < 20; i++) {
        uint32_t v = hdr32[i];
        hdr32[i] = ((v>>24)&0xFF) | ((v>>8)&0xFF00) | ((v<<8)&0xFF0000) | ((v<<24)&0xFF000000);
    }
    
    odohash(hash, header, odo_key);
    printf("Hash for swapped zeros+nonce1: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\nhash[7] = %08X\n", h32[7]);
    
    return 0;
}
