// odocrypt_wrapper.cpp - C++ wrapper that calls OdoCrypt + Keccak800
#include "odocrypt.h"
#include <cstring>

// KeccakP-800 from reference implementation
extern "C" {
    void KeccakP800_Permute_12rounds(void *state);
}

extern "C" void odocrypt_hash(const void *input, void *output, uint32_t odo_key)
{
    // Buffer: 100 bytes (Keccak-800 state = 800 bits)
    char cipher[100] = {};

    // Copy 80-byte header
    memcpy(cipher, input, 80);
    // Padding byte (same as DigiByte reference hashodo.h)
    cipher[80] = 1;

    // OdoCrypt encrypt (80 bytes in-place)
    OdoCrypt(odo_key).Encrypt(cipher, cipher);

    // Keccak-p[800, 12 rounds]
    KeccakP800_Permute_12rounds(cipher);

    // Output first 32 bytes as hash
    memcpy(output, cipher, 32);
}
