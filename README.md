# suprminer-fpga — SHA3-256t (BC3) / Groestl / BLAKE3 Decred FPGA miner

FPGA mining software for ZTEX USB-FPGA Module 1.15y boards.
Supports Groestl, Myriad-Groestl, Blake256-8, and **BLAKE3 (Decred DCP-0011)**.

## Supported Algorithms

| Algorithm | Coin | Header Size | FPGA Work Size | Bitstream |
|-----------|------|-------------|----------------|-----------|
| groestl | GRS | 80 bytes | 80 bytes | `ztex_groestl.bit` |
| myr-gr | XMY | 80 bytes | 80 bytes | `ztex_myr_groestl.bit` |
| blakecoin | BLC | 80 bytes | 44 bytes (midstate) | `ztex_blake256_8.bit` |
| **blake3** | **DCR** | **180 bytes** | **184 bytes** | **`blake3_dcr.bit`** |

## Build

```bash
sudo apt-get install libusb-1.0-0-dev libcurl4-openssl-dev libssl-dev cmake build-essential
cd fpga_miner
mkdir -p build && cd build
cmake .. && make -j$(nproc)
```

The binary is placed at `fpga_miner/fpga_miner`.

## Usage

### BLAKE3 / Decred (DCP-0011)

```bash
# ZTEX boards (USB, auto-configure FPGA)
./fpga_miner -a blake3 -o stratum+tcp://dcr.suprnova.cc:3252 \
    -u YOUR_WORKER.rig1 -p x --ztex

# With debug logging
./fpga_miner -a blake3 -o stratum+tcp://dcr.suprnova.cc:3252 \
    -u YOUR_WORKER.rig1 -p x --ztex -D
```

### Groestl / GRS

```bash
./fpga_miner -a groestl -o stratum+tcp://grs.suprnova.cc:5544 \
    -u YOUR_WORKER.rig1 -p x --ztex
```

## Options

```
  -a, --algo <algo>       Mining algorithm: groestl, myr-gr, blakecoin, vcash, blake3
  -o, --url <url>         Stratum pool URL (stratum+tcp://host:port)
  -u, --user <user>       Pool username (worker name)
  -p, --pass <pass>       Pool password
  -t, --threads <n>       CPU miner threads (0 to disable CPU mining)
      --ztex              Enable ZTEX FPGA mining
      --serial <port>     Enable serial FPGA on specified port
      --firmware          Force FPGA firmware reload
      --freq <n>          Set FPGA frequency index (default: 24 = 100 MHz)
  -D                      Enable debug output
```

## Bitstream Files

Place bitstream files in the same directory as the binary or in the current
working directory. The miner auto-loads the correct bitstream based on the
selected algorithm:

- `blake3_dcr.bit` — BLAKE3 Decred (8 cores @ 75 MHz, ~20 MH/s per FPGA)
- `ztex_groestl.bit` — Groestl
- `ztex_myr_groestl.bit` — Myriad-Groestl
- `ztex_blake256_8.bit` — Blake256-8

## BLAKE3 FPGA Design Details

The BLAKE3 bitstream implements:
- 8 parallel mining cores on XC6SLX150 (40% LUT utilization)
- Pipelined G function (2-stage) for 75 MHz operation
- Precomputes BLAKE3 blocks 0-1 per work unit; iterates block 2 only per nonce
- 29 clock cycles per hash attempt
- 2-level register tree for header distribution (avoids routing congestion)
- Nonce at Decred header byte offset 140 (word 35)

### Performance

| Board | Cores | Clock | MH/s |
|-------|-------|-------|------|
| Single FPGA | 8 | 75 MHz | ~20.7 |
| Quad board (1.15y) | 32 | 75 MHz | ~83 |

### Protocol

The FPGA communicates via the ZTEX GPIF interface:
- **Work input:** 184 bytes (180-byte Decred header + 4-byte H7 target), byte-swapped
- **Status output:** 16 bytes [golden_nonce1, cur_nonce, hash7, golden_nonce2], LE
- **Frequency:** Settable via vendor request 0x83

## Building the Bitstream

Requires Xilinx ISE 14.7 Design Suite (System or Logic Edition) with
a license covering XC6SLX150.

```bash
source /opt/Xilinx/14.7/ISE_DS/settings64.sh
cd /path/to/blake3_dcr_fpga
./build_ise.sh
# Output: build/blake3_dcr.bit (~3 hours build time)
```

## Keyboard Commands (while running)

- `s` + Enter — Display mining summary
- `f` + Enter — Display FPGA status

## Project Structure

```
fpga_miner/
  fpga-miner.c          Main miner (stratum, FPGA control, all algos)
  libztex.c/h           ZTEX USB-FPGA communication library
  fpgautils.c/h         Serial FPGA utilities
  miner.h               Shared types, work struct, endian helpers
  util.c                Stratum protocol, JSON-RPC, networking
  api.c                 Monitoring API
  algo/
    blake3.c/h          BLAKE3 hash (180-byte Decred headers)
    groestl.c           Groestl hash
    myr-groestl.c       Myriad-Groestl hash
    blake256-8.c        Blake256-8 hash
    sha2.c/h            SHA-256
    sph_*.c/h           Sphlib hash primitives
  CMakeLists.txt        Build configuration
```

## License

Based on cpuminer by Jeff Garzik, pooler, and others. GPLv2.
BLAKE3 implementation based on the BLAKE3 specification.
