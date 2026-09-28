#!/usr/bin/env python3
"""Audit Git objects before publishing the public proof-of-concept repository."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


# These assets were already public. A matching filename alone is insufficient.
PUBLIC_ASSETS = {
    "api/API.class": "5dd6c5a2f9d161756c1ce778f8835277928a47fdf739b3459689a30e079334f0",
    "bitstreams/ztex_ufm1_15y1.bin": "911b8032a5e2381f1079b7469bd1838bcc8980e340b655476c12f2ab0835535d",
    "proof_of_concept/vu9p/bc3_vu9p_bs1_300mhz.bit": "659ed0b524d3ed22567903e98fa26e9a7d0cfea87efb3e70c147db7442fe4cb2",
    "proof_of_concept/ztex_sha3_10core_90mhz.bit": "75517beca0628fcc315a8c30bb13797f6849ec77b4ed0a2c2ef8de618d08dda9",
}
ARTIFACT_SUFFIXES = {
    ".bit", ".bin", ".dcp", ".ltx", ".rbt", ".mcs", ".pdi", ".xclbin",
    ".xo", ".xsa", ".edf", ".edif", ".ngc", ".ngd", ".ncd", ".wdb",
    ".vcd", ".jou", ".log", ".zip", ".gz", ".tar", ".7z", ".o", ".a",
    ".so", ".exe", ".class", ".pem", ".key", ".p12", ".pfx",
}
PRIVATE_PATH_PARTS = {
    "deployment", "deliverables", "knowledge", "monitoring", "backups",
    "private", ".ssh", ".codex", ".env",
}
PRIVATE_NAMES = {"ALL_HANDOFF.md", "STATIC_MEMORY.md", "CURRENT_WORK.md"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    re.compile(rb"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)


class Refused(Exception):
    pass


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def commit_id(repo, revision):
    return git(repo, "rev-parse", "--verify", "--end-of-options",
               revision + "^{commit}").decode().strip()


def entries(repo, revision=None):
    if revision is None:
        raw = git(repo, "ls-files", "--stage", "-z")
    else:
        raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", revision)
    result = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        parts = metadata.decode("ascii").split()
        path = name.decode("utf-8", errors="strict")
        if any(ord(c) < 32 or ord(c) == 127 for c in path) or "\\" in path:
            raise Refused("nonportable path in tree/index")
        if revision is None:
            mode, oid, stage = parts
            if stage != "0":
                raise Refused("unmerged index entry")
        else:
            mode, kind, oid = parts
            if kind != "blob":
                raise Refused("submodules are not public release files")
        if mode not in {"100644", "100755"}:
            raise Refused("symlinks or unsupported Git file modes are not allowed")
        result[path] = oid
    return result


def content_check(path, data):
    if path in PUBLIC_ASSETS:
        if hashlib.sha256(data).hexdigest() != PUBLIC_ASSETS[path]:
            raise Refused("reviewed binary asset changed: " + path)
        return
    p = PurePosixPath(path)
    if p.suffix.lower() in ARTIFACT_SUFFIXES:
        raise Refused("unapproved artifact: " + path)
    if len(data) > 2 * 1024 * 1024 or b"\0" in data:
        raise Refused("unapproved binary or oversized text: " + path)
    if data.startswith((b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b")):
        raise Refused("binary/archive disguised as a public source file: " + path)
    if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise Refused("LFS pointers need a separate asset-content review: " + path)
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("unapproved non-UTF-8 file: " + path) from exc
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        # Never include the matched secret in diagnostics.
        raise Refused("credential marker found in: " + path)


def audit(repo, revision=None):
    files = entries(repo, revision)
    if ".gitignore" not in files:
        raise Refused("public release allowlist is missing")
    ignore = git(repo, "cat-file", "blob", files[".gitignore"]).decode("utf-8")
    lines = [line.strip() for line in ignore.splitlines() if line.strip()
             and not line.lstrip().startswith("#")]
    if not lines or lines[0] != "*":
        raise Refused("public allowlist must ignore unreviewed files by default")
    allowed = set()
    for line in lines[1:]:
        if not line.startswith("!/") or any(c in line[2:] for c in "*?[]\\"):
            raise Refused("public exceptions must be exact paths")
        if not line.endswith("/"):
            allowed.add(line[2:])
    for path, oid in files.items():
        p = PurePosixPath(path)
        if path not in allowed:
            raise Refused("tracked path is outside the public allowlist: " + path)
        if PRIVATE_PATH_PARTS.intersection(p.parts) or p.name in PRIVATE_NAMES:
            raise Refused("private operational path in public tree: " + path)
        if "rtl" in p.parts and not path.startswith("proof_of_concept/"):
            raise Refused("RTL outside the public proof-of-concept tree: " + path)
        content_check(path, git(repo, "cat-file", "blob", oid))
    if revision is not None:
        content_check("commit message", git(repo, "show", "-s", "--format=%B", revision))
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--staged", action="store_true", help="audit actual index blobs")
    selection.add_argument("--commit", metavar="REV", help="audit a committed tree")
    selection.add_argument("--range", nargs=2, metavar=("BASE", "TIP"),
                           help="audit every commit in BASE..TIP, including deleted files")
    args = parser.parse_args()
    try:
        if args.staged:
            count = audit(args.repo)
            print("PUBLIC_RELEASE_PASS staged_files=" + str(count))
        elif args.commit:
            revision = commit_id(args.repo, args.commit)
            count = audit(args.repo, revision)
            print("PUBLIC_RELEASE_PASS commit=" + revision + " files=" + str(count))
        else:
            base, tip = (commit_id(args.repo, rev) for rev in args.range)
            revisions = git(args.repo, "rev-list", "--reverse", base + ".." + tip).decode().splitlines()
            for revision in revisions:
                audit(args.repo, revision)
            # Also check the proposed final tree if the range happens to be empty.
            audit(args.repo, tip)
            print("PUBLIC_RELEASE_PASS commits=" + str(len(revisions)) + " tip=" + tip)
    except (Refused, subprocess.CalledProcessError, UnicodeError, ValueError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            reason = "Git object lookup failed; nothing approved for publication"
        else:
            reason = str(exc)
        print("PUBLIC_RELEASE_REFUSED " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
