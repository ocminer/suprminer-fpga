# BC3 / SHA3-256t FPGA Miner — Proof-of-Concept Bitstream

This directory contains a **working proof-of-concept** FPGA bitstream (and its Verilog
source) for mining **BitcoinIII (BC3)**, whose proof-of-work is **SHA3-256t** — triple
SHA3-256 (three sequential Keccak-f[1600] permutations), 80-byte header, 32-bit nonce.

Target hardware: **ZTEX USB-FPGA 1.15y** — 4× Xilinx Spartan-6 **XC6SLX150** (2011),
shared FX2 USB bus. Built with Xilinx ISE 14.7.

## What this is
- **`ztex_sha3_10core_90mhz.bit`** — prebuilt bitstream: **10 Keccak cores per FPGA @ 90 MHz**.
- **`rtl/`** — the Verilog source that implements it:
  - `keccak_round.v` — one combinational Keccak-f[1600] round (theta / rho-pi / chi / iota)
  - `sha3_core.v` — autonomous triple-SHA3-256 nonce scanner (76 cycles/nonce)
  - `sha3_multicore.v` — 10 parallel cores with interleaved nonce ranges
  - `ztex_comm_80.v` — ZTEX FX2 host communication (80-byte work in, nonces out)
  - `top_sha3.v` — top level + clocking (DCM)

## Performance (this proof-of-concept)
| Unit | Hashrate |
|------|----------|
| Per FPGA | **11.85 MH/s** |
| Per board (4× XC6SLX150) | **~47.4 MH/s** |

Runs with the `suprminer-fpga` host miner in this repository (`-a sha3t`).

## Notes
- The SHA3-256t reference hash and nonce-scan are verified against real chain blocks
  (see `algo/sha3t.c` in the repository root).
- This PoC bitstream targets single-/small-board bring-up; the host miner adds per-FPGA
  validation and multi-board handling.
