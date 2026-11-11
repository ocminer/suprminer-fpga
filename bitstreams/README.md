# Bitstreams

Bitstream files are not committed (see .gitignore). Default names per algorithm and platform
are listed in `algo_table.c`; any file can be used with `--bitstream <path>`.

| Platform | Algorithm | Default file | Notes |
|---|---|---|---|
| ztex | groestl / dmd-gr | ztex_groestl.bit | |
| ztex | myr-gr | ztex_myr_groestl.bit | |
| ztex | blakecoin / vcash | ztex_blake256_8.bit | |
| ztex | blake3 | blake3_dcr.bit | |
| ztex | odo | odo_dgb.bit | |
| ztex | sha3t | ztex_sha3.bit | variant ladder ztex_sha3_<MHz>.bit optional |
| vu9p | proxima | vu9p_proxima.bit | not bundled yet (separate release decision) |
| vu9p | sha3t | vu9p_sha3t.bit | not bundled |

A VU9P bitstream must expose one JTAG-AXI master (hw_axi) with the register map its driver in
`platform/` expects; the build id register identifies the family (proxima: 0x50B2Bxxx at 0x220).
