# suprminer-fpga

FPGA miner host software for ZTEX USB-FPGA 1.15y boards and BCU1525 VU9P cards.
The repository includes two BC3 (triple SHA3-256) proof-of-concept releases:

- [ZTEX 10-core / 90-MHz bitstream and RTL](proof_of_concept/README.md).
- [VU9P single-core / 300-MHz bitstream and reference RTL](proof_of_concept/vu9p/README.md).

ZTEX uses USB. VU9P uses an explicitly selected, loopback-only JTAG-AXI bridge.
The host also contains Groestl, Myriad-Groestl, Blake256-8 and BLAKE3 algorithm
support; compatible images for those algorithms are not included.

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
--vu9p ENDPOINTS       VU9P JTAG-AXI bridge backend
--api-bind 0          Disable the optional miner API
--tui                 Interactive ZTEX device table and miner log
--help                Full command-line help
```

Do not combine the ZTEX and VU9P backends in one process. Use adequate cooling,
a suitable power supply and a single controller for each selected device.
Experimental features and reference RTL are not a long-term stability guarantee.
The optional image-frequency catalog is unbound; automatic frequency selection
is not enabled by this release.

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
