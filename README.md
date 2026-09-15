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
--help                Full command-line help
```

Do not combine the ZTEX and VU9P backends in one process. Use adequate cooling,
a suitable power supply and a single controller for each selected device.
Experimental features and reference RTL are not a long-term stability guarantee.
The optional image-frequency catalog is unbound; automatic frequency selection
is not enabled by this release.

## Source and license

Derived from cpuminer by Jeff Garzik, pooler and other contributors, with
third-party notices retained in the source. The miner is distributed under
GPLv2; individual bundled components retain their source-file license notices.
