#!/bin/bash
# BitcoinIII (BC3) SHA3-256t mining on suprnova — 4x XC6SLX150 (requires >=12V/3A PSU)
cd /home/marcel/fpga_dev/fpga_miner
sudo pkill -9 -x fpga_miner 2>/dev/null; sleep 2
sudo FPGA_ONLY=0123 ./fpga_miner -a sha3t -o stratum+tcp://bc3.suprnova.cc:7700 \
  -u 1EF2o1X85dE6EoLKZotV8LkcgVaJAmZDtT.rig01 -p x --scan-time 10 --ztex 96 --watts-per-fpga 7.5  # bitstream=10c@90 (35.5 MH/s)
# Ports: 7700 VarDiff Low | 7701 VarDiff Main(1024) | 7702 fixed512 | 7703 fixed4096 | 7704 SSL | 7705 NiceHash
