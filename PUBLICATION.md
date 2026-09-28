# Public release boundary

This repository contains the public host software and the explicitly reviewed
proof-of-concept images and reference RTL. Private FPGA implementations,
performance builds, checkpoints, deployment configurations, credentials,
inventories, logs and operational handoffs do not belong in this repository.

Prepare public changes in a separate checkout of the current public branch.
Keep private development trees and their Git history out of the public checkout.
The default-deny `.gitignore` allows only individually reviewed paths; never use
`git add -f` to move a private artifact past it.

Before committing, inspect the complete staged diff and audit the actual index:

```sh
git diff --cached --stat
git diff --cached
python3 -I -B tools/check-public-release.py --staged
```

Before pushing, fetch the intended remote branch and audit every outgoing commit:

```sh
git fetch origin master
python3 -I -B tools/check-public-release.py --range origin/master HEAD
```

Checking only the final tree is insufficient: a file deleted by a later commit
would still be published in an earlier outgoing commit. Never push unrelated
branches, tags or private history with a release.

The checker verifies exact allowlisted paths, regular-file Git modes and fixed
SHA-256 hashes for the already published binary assets. It refuses other build
artifacts, disguised binaries, LFS pointers, private operational directories,
and several common credential formats. It reads Git objects, so an innocuous
working-tree file cannot hide different staged content. The diagnostics do not
print matching credential values.

This is a mechanical guard, not a complete secret or intellectual-property
scanner. It cannot decide whether newly written source is proprietary or whether
every possible credential format is present. Review source contents, metadata,
commit messages and any proposed allowlist changes before publication. New binary
assets require a separate explicit release decision and content review; changing
an existing image's filename does not make it an approved asset.

Run the checker regression tests without hardware or network access:

```sh
python3 -I -B tools/test-public-release.py
```
