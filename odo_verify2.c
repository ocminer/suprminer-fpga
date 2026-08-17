#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void odohash(void *output, const void *input, uint32_t odo_key);

int main() {
    // Exact send buffer from FPGA debug (swap_endian'd work.data)
    uint8_t send_buf[76];
    const char *hex = 
        "020e00204d19d0dad6c0d02775d1bb1b1d9b688c6e27c70183f31254fc15445dd23840b9d9a82974"
        "3bb91ee9eba37b034e83e0cd826fd551a3cc59b4650351abce9edc9d1656cd698b3d3e1a";
    
    for (int i = 0; i < 76; i++) {
        unsigned int b;
        sscanf(hex + i*2, "%02x", &b);
        send_buf[i] = b;
    }
    
    // Golden nonce = 0x0009A0CD
    uint32_t golden_nonce = 0x0009A0CD;
    
    // Build 80-byte header = send_buf (76 bytes) + nonce (4 bytes LE)
    uint8_t header[80];
    memcpy(header, send_buf, 76);
    header[76] = golden_nonce & 0xFF;        // 0xCD
    header[77] = (golden_nonce >> 8) & 0xFF;  // 0xA0
    header[78] = (golden_nonce >> 16) & 0xFF; // 0x09
    header[79] = (golden_nonce >> 24) & 0xFF; // 0x00
    
    uint32_t odo_key = 1774656000;
    uint8_t hash[32];
    
    // Method 1: Hash the send_buf + nonce (what FPGA hashes)
    odohash(hash, header, odo_key);
    uint32_t *h32 = (uint32_t*)hash;
    printf("FPGA-style hash (send_buf + LE nonce):\n");
    printf("  hash[7] = %08X\n", h32[7]);
    printf("  full: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");
    
    // Method 2: Hash work.data directly (what old calc_hash did with raw bytes)
    // work.data bytes = swap_endian(send_buf) since send_buf = swap_endian(work.data)
    uint8_t workdata[80];
    uint32_t *wd32 = (uint32_t*)workdata;
    uint32_t *sb32 = (uint32_t*)send_buf;
    for (int i = 0; i < 19; i++) {
        uint32_t v = sb32[i];
        wd32[i] = ((v>>24)&0xFF) | ((v>>8)&0xFF00) | ((v<<8)&0xFF0000) | ((v<<24)&0xFF000000);
    }
    wd32[19] = golden_nonce; // raw nonce
    
    odohash(hash, workdata, odo_key);
    printf("\nwork.data-style hash (raw bytes + nonce):\n");
    printf("  hash[7] = %08X\n", h32[7]);
    
    // Method 3: What calc_hash does (swap_endian + nonce override)
    uint32_t endian_data[20];
    for (int i = 0; i < 20; i++) {
        uint32_t v = wd32[i];
        endian_data[i] = ((v>>24)&0xFF) | ((v>>8)&0xFF00) | ((v<<8)&0xFF0000) | ((v<<24)&0xFF000000);
    }
    endian_data[19] = golden_nonce; // override nonce
    
    // ntime from endian_data[17]
    uint32_t ntime = endian_data[17];
    uint32_t key2 = ntime - ntime % 864000;
    printf("  calc_hash ntime=%08X key=%u\n", ntime, key2);
    
    odohash(hash, endian_data, key2);
    printf("\ncalc_hash style (swap_endian + nonce override):\n");
    printf("  hash[7] = %08X\n", h32[7]);
    
    return 0;
}
