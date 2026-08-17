#!/bin/bash

cd /home/pi/fpga_miner
while true; do
        ./fpga_miner -a groestl -o stratum+tcp://grs.suprnova.cc:5544 -u suprnova.2 -p x --scan-time 10 --auto-freq --ztex 124
	sleep 2
done
exec bash
