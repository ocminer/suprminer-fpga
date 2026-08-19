#!/bin/bash
# err_watchdog.sh — DCM drift mitigation (until a positive-margin bitstream lands).
#
# Mechanism (measured 2026-08-19): the fixed-DCM bitstreams run with negative
# static margin; the DCM_SP's tap state drifts vs its lock-time temperature and
# hash correctness decays over ~20-60 min (ERR% in the heartbeat). Reconfiguring
# re-locks the DCM and resets ERR to ~0 even on a warm die. This watchdog
# restarts (=reconfigures) the miner whenever fleet-average ERR crosses the
# threshold: ~90s restart cost vs 50%+ silent share loss.
L=/home/marcel/sha3_fpga/mining_suprminer.log
THRESH=8.0
NTFY=https://ntfy.sh/marcel-suprminer-bench
while true; do
  sleep 300
  pgrep -x suprminer-fpga >/dev/null || continue
  AVG=$(grep "HEARTBEAT" $L 2>/dev/null | tail -40 | grep -oE "ERR=[0-9.]+%" | grep -oE "[0-9.]+" | awk '{s+=$1;n++} END{if(n>0) printf "%.1f", s/n; else print "0"}')
  BIG=$(echo "$AVG > $THRESH" | bc -l 2>/dev/null)
  if [ "$BIG" = "1" ]; then
    curl -s -H "Title: suprminer drift watchdog" -d "🔄 fleet ERR avg ${AVG}% > ${THRESH}% — reconfiguring (DCM re-lock). Normal until positive-margin bitstream deploys." $NTFY >/dev/null
    sudo pkill -9 -x suprminer-fpga; sleep 3
    tmux kill-session -t miner 2>/dev/null
    tmux new-session -d -s miner "cd /home/marcel/fpga_dev/fpga_miner && sudo FPGA_ONLY=0123 ./suprminer-fpga -a sha3t -o stratum+tcp://bc3.suprnova.cc:7700 -u 1EF2o1X85dE6EoLKZotV8LkcgVaJAmZDtT.fpga_cl01 -p x --scan-time 10 --ztex 96 --watts-per-fpga 7.5 --tui --log-file $L --hash-clock 84"
    sleep 180   # settle before next evaluation
  fi
done
