#!/usr/bin/env python3
"""Exercise actual option/backend selection while intercepting USB/network access.

Linux only. Usage: python3 tools/test-vu9p-cli.py /path/to/suprminer-fpga
The sentinel exits before any libusb initialization or connect system call.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

SENTINEL = r'''
#include <sys/socket.h>
#include <unistd.h>
int libusb_init(void **context) {
    (void)context;
    write(2, "TEST_USB_SELECTED\n", 18);
    _exit(97);
}
int connect(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)address; (void)length;
    write(2, "TEST_CONNECT_SELECTED\n", 22);
    _exit(98);
}
'''


def main():
    binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    base = ['-a', 'sha3t', '-o', 'stratum+tcp://127.0.0.1:1',
            '-u', 'TEST_WORKER', '-p', 'TEST_PASSWORD', '--api-bind', '0']
    fields = {'--vu9p': '127.0.0.1:1', '--vu9p-build-id': '5a3d0001',
              '--vu9p-active-lanes': '1', '--vu9p-rate-hps': '300000000',
              '--vu9p-poll-work-ms': '1000'}
    def options(mapping):
        return [v for pair in mapping.items() for v in pair]
    cases = [('help', ['--help'], 0), ('version', ['--version'], 0)]
    for field in fields:
        reduced = {k:v for k,v in fields.items() if k != field}
        cases.append(('missing-' + field, base + options(reduced), 1))
    for field, values in [('--vu9p-build-id', ['00000000', '5a3d00010', '-5a3d001']),
                          ('--vu9p-active-lanes', ['0', '2', '4294967296']),
                          ('--vu9p-rate-hps', ['0', '299999999', '300000001', '18446744073709551616']),
                          ('--vu9p-poll-work-ms', ['0', '51', '14317', '4294967296', '-1']),
                          ('--vu9p', ['127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:1,'])]:
        for value in values:
            changed = dict(fields); changed[field] = value
            cases.append((field + '=' + value, base + options(changed), 1))
    for args in [['--ztex', '90'], ['--scan-serial', '/dev/TEST_ONLY'],
                 ['--firmware'], ['--auto-freq'], ['--no-stratum'],
                 ['--heartbeat-interval', '30'], ['-a', 'groestl'],
                 ['-o', 'http://127.0.0.1:1']]:
        cases.append(('incompatible-' + args[0], base + options(fields) + args, 1))
    cases += [('valid-vu9p-selects-bridge', base + options(fields), 98),
              ('existing-ztex-selects-usb', base + ['--ztex', '90'], 97)]
    with tempfile.TemporaryDirectory(prefix='suprminer-cli-test-') as directory:
        work = pathlib.Path(directory)
        source = work/'sentinel.c'; source.write_text(SENTINEL)
        library = work/'sentinel.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(library)], check=True, timeout=30)
        env = {k:v for k,v in os.environ.items() if not k.startswith(
            ('ZTEX_', 'FPGA_', 'SHA3_', 'VU9P_', 'LD_', 'SUPRMINER_'))}
        env['LD_PRELOAD'] = str(library)
        for label, args, code in cases:
            result = subprocess.run([str(binary), *args], cwd=work, env=env,
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == code, (label, result.returncode, result.stderr)
            if code not in (97, 98):
                assert 'TEST_USB_SELECTED' not in result.stderr
                assert 'TEST_CONNECT_SELECTED' not in result.stderr
            print('PASS', label)
    print(f'{len(cases)} actual CLI cases passed; USB/network operations intercepted')


if __name__ == '__main__':
    main()
