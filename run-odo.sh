#!/bin/bash
# OdoCrypt DigiByte mining - 4 FPGAs × 3 cores × 44 MHz
cd /home/marcel/fpga_dev/fpga_miner
sudo pkill -9 -f suprminer-fpga 2>/dev/null; sleep 2
sudo ./suprminer-fpga -a odo -o stratum+tcp://digihash.digibyte.io:3013 \
  -u dgb1q5r7pszat4z46t8gu2lsw0p85sgzr3gymkxlth0 -p d=0.01 --scan-time 10 --ztex 44
