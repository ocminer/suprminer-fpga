# suprminer-fpga — SHA3-256t (BC3) Benchmarks

Steady-state hashrate, power, and efficiency on BitcoinIII (BC3, SHA3-256t / triple SHA3-256).
Efficiency shown both ways: **MH/s/W** (higher is better) and **W/MH·s** (lower is better).

## FPGA — ZTEX USB-FPGA 1.15y (4× Xilinx Spartan-6 XC6SLX150, 2011)
Bitstream: 10 Keccak cores/FPGA @ 90 MHz (`src_r3`), `suprminer-fpga -a sha3t`.

| Unit | MH/s | Power | MH/s/W | W/MH·s |
|------|------|-------|--------|--------|
| Per FPGA | 11.85 | ~7.5 W | 1.58 | 0.633 |
| **Board (4 FPGA)** | **47.4** | **~30 W** | **1.58** | **0.633** |

Notes: board needs a ≥12V/3A (36W) supply for all 4 FPGAs under SHA3 load (a 2A/24W
supply causes rail droop → readback corruption on 2 of 4 FPGAs). ~65 % LUT, routing-bound;
10 cores/FPGA is the routing max on this device.

## GPU fleet — SHA3-256t (BC3)

| GPU | MH/s | Power | MH/s/W | Temp |
|-----|------|-------|--------|------|
| RTX 3070 | 1206 | 230 W | ~5.2 | 67–68 °C |
| RTX 5090 | 2442 | 546 W | ~4.5 | 65–85 °C |
| RTX 5070 Ti | 475 | 224 W | ~2.1 | 62 °C |
| **ZTEX 1.15y board** | **47.4** | **~30 W** | **1.58** | cool/passive |
| RTX 5080 | 389 | 285 W | ~1.4 | 66–74 °C |
| GTX 1080 Ti | 330 | 230 W | ~1.4 | — |

## Takeaways
- **Efficiency:** the 2011-era Spartan-6 board (1.58 MH/s/W) beats the RTX 5080 and GTX 1080 Ti
  (both 1.4) and is within range of the 5070 Ti (2.1). The **RTX 3070 is the efficiency king
  (5.2 MH/s/W)** — ~3.3× the FPGAs — followed by the 5090 (4.5).
- **Absolute throughput:** one RTX 3070 ≈ 25 ZTEX boards; one RTX 5090 ≈ 51 boards.
- **Verdict:** FPGAs are worth running as owned/sunk-cost hardware (tiny 30 W draw, cool,
  quiet) but not worth buying more of vs used 3070s. If the bitstream reaches ~108 MHz
  (in progress), the board hits ~56.8 MH/s ≈ 1.9 MH/s/W — competitive with the 5070 Ti.
