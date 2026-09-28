#!/usr/bin/env python3
"""Offline tests of publication refusals using disposable Git repositories."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check-public-release.py")
spec = importlib.util.spec_from_file_location("public_release", CHECKER)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def fake_key():
    return b"-----BEGIN " + b"PRIVATE KEY-----\n" + b"fixture-only-value\n"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.name", "Publication test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.write(".gitignore", b"*\n!/.gitignore\n!/README.md\n")
        self.write("README.md", b"Public source documentation.\n")
        self.git("add", ".gitignore", "README.md")
        self.git("commit", "--quiet", "-m", "Public baseline")
        self.base = self.git("rev-parse", "HEAD").decode().strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       stderr=subprocess.PIPE)

    def write(self, name, data):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def allow(self, path):
        p = self.repo / ".gitignore"
        p.write_bytes(p.read_bytes() + ("!/" + path + "\n").encode())
        self.git("add", ".gitignore")

    def refused(self, reason):
        with self.assertRaisesRegex(guard.Refused, reason):
            guard.audit(self.repo)

    def test_clean_index_and_commit(self):
        self.assertEqual(guard.audit(self.repo), 2)
        self.assertEqual(guard.audit(self.repo, self.base), 2)

    def test_force_added_private_path(self):
        self.write("private/design.bit", b"not a public image")
        self.git("add", "-f", "private/design.bit")
        self.refused("outside the public allowlist")

    def test_operational_file_remains_private_if_allowlisted(self):
        self.allow("deployment/local.json")
        self.write("deployment/local.json", b"{}\n")
        self.git("add", "-f", "deployment/local.json")
        self.refused("private operational path")

    def test_same_name_replacement_of_public_image(self):
        name = "proof_of_concept/vu9p/bc3_vu9p_bs1_300mhz.bit"
        self.allow(name)
        self.write(name, b"different image under the approved filename")
        self.git("add", "-f", name)
        self.refused("reviewed binary asset changed")

    def test_disguised_binary_and_lfs_pointer(self):
        for data in (b"\x7fELFpretend-binary", b"PK\x03\x04archive",
                     b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\n"):
            with self.subTest(data=data[:7]):
                self.write("README.md", data)
                self.git("add", "README.md")
                self.refused("disguised|LFS pointers")

    def test_index_cannot_be_hidden_by_clean_working_copy(self):
        self.write("README.md", fake_key())
        self.git("add", "README.md")
        self.write("README.md", b"Innocent unstaged content.\n")
        self.refused("credential marker")

    def test_unstaged_file_does_not_change_the_audited_index(self):
        self.write("README.md", fake_key())
        self.assertEqual(guard.audit(self.repo), 2)

    def test_deleted_private_content_in_outgoing_history(self):
        self.write("README.md", fake_key())
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "Intermediate content")
        self.write("README.md", b"Clean final content.\n")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "Remove intermediate content")
        self.assertEqual(guard.audit(self.repo, "HEAD"), 2)
        result = subprocess.run([sys.executable, "-I", "-B", str(CHECKER),
                                 "--repo", str(self.repo), "--range", self.base, "HEAD"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("credential marker", result.stderr)
        self.assertNotIn("fixture-only-value", result.stderr)

    def test_symlink(self):
        (self.repo / "README.md").unlink()
        (self.repo / "README.md").symlink_to(".gitignore")
        self.git("add", "README.md")
        self.refused("symlinks")

    def test_wildcard_expansion_of_allowlist(self):
        self.allow("*.bit")
        self.refused("exact paths")

    def test_commit_message_is_checked(self):
        self.git("commit", "--quiet", "--allow-empty", "-m", fake_key().decode())
        with self.assertRaisesRegex(guard.Refused, "credential marker"):
            guard.audit(self.repo, "HEAD")

    def test_already_published_assets_match(self):
        checkout = CHECKER.parent.parent
        for path in guard.PUBLIC_ASSETS:
            with self.subTest(path=path):
                guard.content_check(path, (checkout / path).read_bytes())


if __name__ == "__main__":
    unittest.main()
