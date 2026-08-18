#!/bin/bash
# BitcoinIII (BC3) SHA3-256t mining on suprnova — 5x ZTEX 1.15y / 20x XC6SLX150 (each board >=12V/3A PSU)
# Launches inside a tmux session 'miner' with the ncurses TUI. Attach: tmux attach -t miner  (q to quit)
cd /home/marcel/fpga_dev/fpga_miner
sudo pkill -9 -x suprminer-fpga 2>/dev/null; sleep 2
tmux kill-session -t miner 2>/dev/null
tmux new-session -d -s miner "cd /home/marcel/fpga_dev/fpga_miner && \
  sudo FPGA_ONLY=0123 ./suprminer-fpga -a sha3t -o stratum+tcp://bc3.suprnova.cc:7700 \
  -u 1EF2o1X85dE6EoLKZotV8LkcgVaJAmZDtT.fpga_cl01 -p x --scan-time 10 --ztex 96 --watts-per-fpga 7.5 \
  --tui --log-file /home/marcel/sha3_fpga/mining_suprminer.log --hash-clock 90"
echo "miner started in tmux 'miner' (5 boards / 20 FPGAs, ~237 MH/s). Attach: tmux attach -t miner"
# bitstream=10c@90 (11.85 MH/s/FPGA). Set --hash-clock 91.2 if the 91 MHz build deploys.
# Ports: 7700 VarDiff Low | 7701 VarDiff Main(1024) | 7702 fixed512 | 7703 fixed4096 | 7704 SSL | 7705 NiceHash
