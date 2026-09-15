# BC3 on VU9P: BS1 proof of concept

BC3 SHA3-256t mining on BCU1525 VU9P cards with `suprminer-fpga`.
This is a fixed, single-core 300 MHz proof of concept. It is experimental:
long-run hash correctness and stability are not established. Keep CPU hash
verification enabled and stop on any mismatch.

ZTEX Spartan-6 boards continue to use the existing USB backend. Both backends
are in the same executable. Run a separate miner process for each backend in
a mixed configuration; do not combine `--ztex` or serial FPGA options with `--vu9p`.
Existing ZTEX bitstreams and command lines remain supported.

## Files and requirements

- `bc3_vu9p_bs1_300mhz.bit`: BCU1525, `xcvu9p-fsgd2104-2L-e`, build ID `5a3d0001`.
- `SHA256SUMS`: checksum for the exact published image.
- `program_bs1.tcl`: programs one explicitly selected card and leaves it stopped.
- `vu9p_bs1_bridge.tcl`: one persistent Vivado JTAG-AXI bridge per card.

Use Linux, a working Xilinx Vivado Lab installation and hardware server, and
`sha256sum` on PATH. The helpers target the Vivado 2026.1 command interface. Build the miner using
[`tools/build-host.sh`](../../tools/build-host.sh). No LTX file is needed.
The `rtl/` directory and `build_bs1_reference.tcl` provide a reconstructed,
fixed single-core reference source. This is **not a byte-reproducible source
release for the supplied bitstream**. The reference feeder includes the base nonce.

The reference uses the historical control/result interface and has only simulation
coverage here. A new build requires its own timing, CDC and hardware validation.
The supplied programmer deliberately accepts only the exact archived bitstream
checksum; it rejects a newly built reference image.

To build the reference with a licensed Vivado installation, choose a new output
directory and run from this directory:

```sh
vivado -mode batch -source build_bs1_reference.tcl \
  -tclargs /path/to/new-bs1-reference-build
```

The script generates the JTAG-to-AXI IP locally and does not program a card.

Provide adequate card cooling and your own independent temperature/fan supervision.
The miner reports the master-SLR temperature and rails; it does not control fans,
voltage, or clock frequency. Stop mining if cooling or telemetry fails. The
programmer checks temperature and VCCINT before and after configuration.

## Program and start one card

First stop the miner and bridge that own the selected card. Select its exact
hardware-target serial in Vivado Hardware Manager; never guess a serial from a
card index. Replace the paths and placeholders below with your own values.
Run the helper from this directory so the checksum filename resolves:

```sh
sha256sum -c SHA256SUMS
vivado_lab -mode batch -source program_bs1.tcl \
  -tclargs YOUR_CARD_SERIAL "$PWD/bc3_vu9p_bs1_300mhz.bit"
vivado_lab -mode batch -source vu9p_bs1_bridge.tcl \
  -tclargs YOUR_CARD_SERIAL 4711
```

Wait for `BRIDGE_READY` before starting the miner in another terminal. The bridge
listens only on `127.0.0.1`. It accepts one client owner and stops hashing when
that client disconnects. A failed STOP quarantines and exits the bridge.
Terminate the miner first, confirm the bridge reports a successful owner STOP,
then close the bridge before reprogramming or handing the card to another tool.
Do not use a second AXI client while a miner owns the card.

```sh
/path/to/build/bin/suprminer-fpga -a sha3t \
  -o stratum+tcp://YOUR_POOL_HOST:YOUR_POOL_PORT \
  -u YOUR_WORKER -p YOUR_POOL_PASSWORD --api-bind 0 \
  --vu9p 127.0.0.1:4711 --vu9p-build-id 5a3d0001 \
  --vu9p-active-lanes 1 --vu9p-rate-hps 300000000 \
  --vu9p-poll-work-ms 1000
```

The polling bound includes the 50 ms polling interval plus one POLL and one STOP
transaction. A value of 1000 allows up to 475 ms per whole transaction. Select a
bound that covers your measured bridge latency; an insufficient bound causes a
safe disconnect. The host rejects a bound that consumes the full nonce space,
rolls headers before nonce wrap, checks counter regression/overrun, and recomputes
returned nonces on the CPU before testing the full target and queueing a share.
Operating-system scheduling stalls are not bounded by a socket deadline.

For multiple cards, run one bridge per card with distinct serials and local ports. Use
one miner with comma-separated endpoints, or separate miner processes with
unique worker names and independent pool connections. Give each enabled miner
API a different port, or disable it as in the example. Verify accepted shares,
per-card counters and temperatures before leaving the installation unattended.

## Verification scope

The host retains the ZTEX/Stratum safety checks and is checked with the
repository's offline host tests plus VU9P protocol, worker and Tcl tests. These
mock tests do not establish USB or FPGA qualification on another host. Existing
ZTEX support is retained; no ZTEX board is reconfigured by the test suite.

From the repository root, run the Tcl tests without Vivado or hardware using:

```sh
python3 -I -B proof_of_concept/vu9p/test_helpers.py
```

The reference RTL simulation requires Python 3.9+ and Icarus Verilog (`iverilog`
and `vvp`). From the repository root:

```sh
python3 -I -B proof_of_concept/vu9p/test_bs1_reference.py
```

It compares full triple-SHA3 digests against Python's independent CPU implementation,
including nonce zero, wrap, pipeline flush and target comparisons. The source
manifest is [`rtl/REFERENCE_SOURCE.json`](rtl/REFERENCE_SOURCE.json).
