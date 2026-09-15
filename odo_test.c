/*
 * odo_test.c - Standalone OdoCrypt hash test
 *
 * Compile against the existing build objects:
 *
 *   gcc -o odo_test odo_test.c \
 *       build/CMakeFiles/fpga_miner.dir/algo/odohash.c.o \
 *       build/CMakeFiles/fpga_miner.dir/algo/odocrypt_wrapper.cpp.o \
 *       build/CMakeFiles/fpga_miner.dir/algo/odocrypt.cpp.o \
 *       build/CMakeFiles/fpga_miner.dir/algo/KeccakP-800-reference.c.o \
 *       -lstdc++ -lm
 *
 * Then run:  ./odo_test
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void odohash(void *output, const void *input, uint32_t odo_key);

int main(void)
{
    uint8_t header[80];
    uint8_t hash[32];
    uint32_t odo_key = 1774656000;

    /* First 76 bytes: simple 0x01..0x4C pattern */
    for (int i = 0; i < 76; i++)
        header[i] = (uint8_t)(i + 1);

    /* Last 4 bytes: nonce = 0 */
    header[76] = 0x00;
    header[77] = 0x00;
    header[78] = 0x00;
    header[79] = 0x00;

    odohash(hash, header, odo_key);

    printf("odo_key  : %u\n", odo_key);
    printf("nonce    : 00000000\n");
    printf("hash     : ");
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    /* hash[7] = most significant uint32 word (bytes 28..31, little-endian) */
    uint32_t hash7;
    memcpy(&hash7, hash + 28, 4);
    printf("hash[7]  : 0x%08x\n", hash7);

    return 0;
}
