# suprminer-fpga

FPGA miner host software for ZTEX USB-FPGA 1.15y boards and BCU1525 VU9P cards.
The repository includes two BC3 (triple SHA3-256) proof-of-concept releases:

- [ZTEX 10-core / 90-MHz bitstream and RTL](proof_of_concept/README.md).
- [VU9P single-core / 300-MHz bitstream and reference RTL](proof_of_concept/vu9p/README.md).

ZTEX uses USB. VU9P uses an explicitly selected, loopback-only JTAG-AXI bridge.
The host also contains Groestl, Myriad-Groestl, Blake256-8, BLAKE3 and
txid-blake2b (Proxima) algorithm support; compatible images for those
algorithms are not included.

One program, several board families and bitstreams: the board family is picked
with `--fpga`, the bitstream with `--bitstream`, the algorithm with `-a`. The
table in `algo_table.c` says which algorithm has a bitstream and a driver for
which platform; serials, ports and tool paths are command-line options, never
constants. See [Board platforms and bitstreams](#board-platforms-and-bitstreams).

## Build and test

On a Debian-family Linux system:

```sh
sudo apt-get install build-essential cmake pkg-config libusb-1.0-0-dev \
  libcurl4-openssl-dev libncurses-dev python3
bash tools/build-host.sh /absolute/path/to/new-build-directory
```

Choose a new writable build directory outside the checkout. The helper compiles
the host and runs its regression tests without accessing hardware. The executable
is `bin/suprminer-fpga` under that build directory. Compile for the host CPU and
operating system on which it will run.

Use the relevant proof-of-concept guide for FPGA setup. Pool addresses, worker
names, passwords, device selections and local paths must be supplied by the
operator. Never copy a command without replacing its placeholders.

## General options

```text
-a, --algo ALGORITHM   Hash algorithm (BC3 uses sha3t)
-o, --url URL          Pool endpoint
-u, --user WORKER      Pool worker
-p, --pass PASSWORD    Pool password
--ztex                ZTEX USB backend
--vu9p ENDPOINTS       VU9P JTAG-AXI bridge backend (BS1 proof of concept)
--fpga PLATFORM        Register-bridge backend: ztex or vu9p
--bitstream FILE       Bitstream instead of the algorithm's default
--vu9p-mode MODE       bridge (default, vivado_lab bridge per board) or direct (FTDI cable driven by the miner)
--device LIST          VU9P boards: SERIAL[:port] per mode, or explicit ftdi:SERIAL, host:port, jtag:SERIAL[:port]
--program              VU9P: load the bitstream over JTAG before mining
--selftest             Run the algorithm's known-answer test and exit
--api-bind 0          Disable the optional miner API
--tui                 Interactive ZTEX device table and miner log
--help                Full command-line help
```

Do not combine the ZTEX and VU9P backends in one process. Use adequate cooling,
a suitable power supply and a single controller for each selected device.
Experimental features and reference RTL are not a long-term stability guarantee.
The optional image-frequency catalog is unbound; automatic frequency selection
is not enabled by this release.

## Board platforms and bitstreams

`--fpga vu9p` drives any VU9P bitstream that exposes one JTAG-AXI master
through the algorithm-agnostic register bridge `platform/vu9p_bridge.tcl`
(Vivado Lab Edition, free). A driver per bitstream family gives the registers
their meaning:

| Algorithm (`-a`) | Platform | Default bitstream | Driver |
|---|---|---|---|
| groestl, myr-gr, blakecoin, vcash, blake3, odo | ztex | see `bitstreams/README.md` | ZTEX USB backend |
| sha3t | ztex | `ztex_sha3.bit` | ZTEX USB backend |
| sha3t | vu9p | `vu9p_sha3t.bit` (not bundled) | `platform/vu9p_sha3t.c` (BS1 register map; the `--vu9p` backend remains for the published proof of concept) |
| proxima | vu9p | `vu9p_proxima.bit` (not bundled yet) | `platform/vu9p_proxima.c` |

Device specs are given on the command line only: `host:port` connects to a
bridge somebody already started, `jtag:SERIAL[:port]` makes the miner start one
`vivado_lab` bridge for that board (port 13400 + index by default). `--program`
loads the bitstream first; `--selftest` runs the algorithm's known-answer test
on every device and exits. Tool paths: `--vivado-lab`, `--hw-server`
(default 127.0.0.1:3121), `--tcl-dir`, `--log-dir`.

### VU9P modes: bridge or direct

`--vu9p-mode bridge` (default) talks to each board through a `vivado_lab`
JTAG-AXI bridge the miner starts for it; Vivado's `hw_server` keeps the cables,
so other tools (temperature guardians, programming scripts) keep working.
`--vu9p-mode direct` drives the FTDI cable itself. A bare serial in `--device`
follows the mode (`--device 214302895021A,21430289504CA`); explicit `jtag:`,
`ftdi:` and `host:port` entries override it.

### Direct mode (no Vivado at run time)

With `--vu9p-mode direct` (or `--device ftdi:SERIAL`) the miner drives the board's FTDI JTAG cable itself
(`platform/ftdi_mpsse.c`, libusb only) and talks to a BSCANE2 register bus in
the bitstream (`platform/vu9p_jtag.c`); `--program` loads the bitstream over
the same cable. No Vivado, hw_server, bridge process or helper script is
involved. The bitstream must contain the USER1 register bus (the b2b images
built with `JTAG_NATIVE=1`); the `jtag:SERIAL` / `host:port` specs keep working
for bitstreams that carry the Xilinx JTAG-to-AXI core. The cable must not be
held by another program (stop Vivado's `hw_server` first). `--tck-khz` sets the
JTAG clock (default 15000). Qualified on a BCU-1525 (XCVU9P): programming a
64 MB image takes about 40 s at 15 MHz, the built-in Proxima test passes, and a
mainnet run accepted 48 of 48 shares at the full core rate with 0 hardware
errors. The XCVU9P exposes an 18-bit instruction register (6 bits per SLR); the
driver addresses the configuration master field and finds the register bus on
whichever SLR holds it.

```sh
./suprminer-fpga -a proxima --fpga vu9p --device ftdi:SERIALA --bitstream /path/to/proxima.bit --program --selftest
```

### Proxima (txid-blake2b)

The Proxima pool protocol is a stratum dialect: `mining.notify` carries the
transaction prefix and a ttl, a share is `[worker, job_id, extranonce2, hash]`,
the difficulty is `2^k`. The FPGA enumerates the 48-bit extranonce2 itself; the
host computes the per-job BLAKE2b constants, verifies every reported hit with
its own BLAKE2b before submitting, and counts a mismatch as a hardware error.
The miner never submits before the pool has sent a difficulty.

```sh
# program one board and run the built-in test (29 known-answer vectors plus a search check)
./suprminer-fpga -a proxima --fpga vu9p --device jtag:SERIAL --bitstream /path/to/proxima.bit \
    --program --selftest

# mine; the pool login comes from a JSON file {"user": ..., "token": ..., "stratum": "..."}
./suprminer-fpga -a proxima --fpga vu9p --device jtag:SERIAL \
    --account my-account.json --worker rig1 --user-agent ProxiChorizo/2.0.0-fpga \
    -o stratum+tcp://POOL:PORT

# several boards, comma separated; a running bridge by host:port
./suprminer-fpga -a proxima --fpga vu9p --device jtag:SERIAL0,jtag:SERIAL1,127.0.0.1:13402 ...
```

`--kmin` limits the hit rate the board reports (default 2^27 per hit), `--tmax`
is the thermal stop (default 85 C, resume 5 C lower). The miner prints the
measured counter rate, verified hits and hardware errors every 30 seconds.
A Proxima demo bitstream is a separate release decision; none is included yet.

### SHA3-256t (BC3) through the register bridge

```sh
./suprminer-fpga -a sha3t --fpga vu9p --device jtag:SERIAL --bitstream /path/to/sha3t.bit --program \
    -o stratum+tcp://POOL:PORT -u WORKER -p x
```

The sha3t driver speaks the register map of the BS1 bitstream family. It has
not been qualified on hardware in this release; the published proof of concept
keeps using `--vu9p` and `proof_of_concept/vu9p/vu9p_bs1_bridge.tcl`.

### Adding a bitstream family

1. Pure hash code goes to `algo/`.
2. A VU9P driver implements `struct vu9p_algo_driver` (`platform/vu9p_driver.h`):
   open, start, stop, poll, hashes, work_expired, exhausted, selftest, status.
   The miner thread, the stratum handling and the statistics are shared.
3. One line in `algo_table.c` connects the algorithm name, the stratum dialect,
   the default bitstreams per platform and the driver.

## Run in a persistent terminal

The miner runs as an ordinary foreground program; no mining service is required.
To keep its terminal available after disconnecting, open a tmux shell:

```sh
tmux new-session -s fpgaminer
```

Run the complete miner command from the appropriate proof-of-concept guide
inside that shell. Press **Ctrl-B, then D** to detach while mining continues.
To return to its output:

```sh
tmux attach -t fpgaminer
```

Press **Ctrl-C** in the miner's terminal to stop the program, then rerun your
command when ready. For VU9P, confirm the bridge's successful owner STOP before
closing the bridge or reprogramming a card, as described in its guide. Detaching
tmux does not stop mining, and tmux does not restart a miner that exits.

For ZTEX, add `--tui` to show the device table above the live log; **Q** exits
and **PgUp/PgDn** scroll the device table. It requires a terminal. The public
TUI's device table currently covers ZTEX boards; use the ordinary miner output
for the VU9P proof of concept. Site-specific launchers and dashboards are not
included in this repository.

For contributions and releases, follow the [public release boundary](PUBLICATION.md)
and audit the staged files and outgoing commit history before pushing.

## Source and license

Derived from cpuminer by Jeff Garzik, pooler and other contributors, with
third-party notices retained in the source. The miner is distributed under
GPLv2; individual bundled components retain their source-file license notices.
