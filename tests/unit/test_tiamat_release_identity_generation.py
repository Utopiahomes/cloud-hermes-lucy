"""Offline RELEASE identities must retain purpose and custody boundaries."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import deploy.postgres.generate_tiamat_release_identity_v1 as tool
from deploy.postgres.verify_tiamat_release_backup_v1 import verify_archive


class ReleaseIdentityGenerationTests(unittest.TestCase):
    def test_distinct_private_keys_match_public_bytes(self) -> None:
        root_secret, root_public, signer_secret, signer_public = tool.generate_identities(
            root_key_id="tiamat-release-root.staging.1",
            release_key_id="tiamat-release-signer.staging.1",
        )
        self.assertNotEqual(
            root_secret["root_private_key_b64"], signer_secret["release_private_key_b64"]
        )
        for secret, public, private_field, public_field in (
            (root_secret, root_public, "root_private_key_b64", "root_public_key_b64"),
            (signer_secret, signer_public, "release_private_key_b64", "release_public_key_b64"),
        ):
            private = Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(secret[private_field], validate=True)
            )
            self.assertEqual(
                private.public_key().public_bytes_raw(),
                base64.b64decode(public[public_field], validate=True),
            )

    def test_reused_id_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "distinct"):
            tool.generate_identities(root_key_id="same", release_key_id="same")

    def test_in_memory_restore_checks_both_keys_and_refuses_wrong_root(self) -> None:
        identities = tool.generate_identities(root_key_id="root", release_key_id="signer")
        archive_bytes = io.BytesIO()
        with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
            for name, value in zip(
                (
                    "root-private.json",
                    "root-public.json",
                    "release-private.json",
                    "release-public.json",
                ),
                identities,
                strict=True,
            ):
                encoded = json.dumps(value).encode()
                member = tarfile.TarInfo(f"ceremony/{name}")
                member.size = len(encoded)
                archive.addfile(member, io.BytesIO(encoded))
        root_sha = hashlib.sha256(
            base64.b64decode(identities[1]["root_public_key_b64"])
        ).hexdigest()
        signer_sha = hashlib.sha256(
            base64.b64decode(identities[3]["release_public_key_b64"])
        ).hexdigest()
        expected = {
            "ceremony_dir": "ceremony",
            "expected_root_id": "root",
            "expected_root_sha256": root_sha,
            "expected_release_id": "signer",
            "expected_release_sha256": signer_sha,
        }
        verify_archive(io.BytesIO(archive_bytes.getvalue()), **expected)
        expected["expected_root_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            verify_archive(io.BytesIO(archive_bytes.getvalue()), **expected)

    @unittest.skipUnless(os.name == "nt", "Windows DACL refusal")
    def test_windows_write_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "staging"
            with self.assertRaisesRegex(OSError, "Windows"):
                tool.write_identities(
                    output, tool.generate_identities(root_key_id="root", release_key_id="signer")
                )
            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_posix_modes_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            root = repo / "secrets" / "generated" / "tiamat-release"
            output = root / "staging-test"
            with (
                mock.patch.object(tool, "_REPOSITORY_ROOT", repo),
                mock.patch.object(tool, "_SECRET_ROOT", root),
            ):
                tool.write_identities(
                    output, tool.generate_identities(root_key_id="root", release_key_id="signer")
                )
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for name in (
                    "root-private.json",
                    "root-public.json",
                    "release-private.json",
                    "release-public.json",
                ):
                    self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
                before = (output / "root-private.json").read_bytes()
                with self.assertRaises(FileExistsError):
                    tool.write_identities(
                        output,
                        tool.generate_identities(
                            root_key_id="other", release_key_id="other-signer"
                        ),
                    )
                self.assertEqual((output / "root-private.json").read_bytes(), before)

    @unittest.skipIf(os.name == "nt", "POSIX symlinks")
    def test_posix_symlinked_root_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            root = repo / "secrets" / "generated" / "tiamat-release"
            root.parent.mkdir(parents=True)
            redirected = repo / "redirected"
            redirected.mkdir(mode=0o700)
            root.symlink_to(redirected, target_is_directory=True)
            with (
                mock.patch.object(tool, "_REPOSITORY_ROOT", repo),
                mock.patch.object(tool, "_SECRET_ROOT", root),
                self.assertRaisesRegex(OSError, "symlink"),
            ):
                tool.write_identities(
                    root / "staging-test",
                    tool.generate_identities(root_key_id="root", release_key_id="signer"),
                )
            self.assertEqual(list(redirected.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX symlinks")
    def test_posix_symlinked_parent_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            redirected = repo / "redirected"
            redirected.mkdir(mode=0o700)
            (repo / "secrets").symlink_to(redirected, target_is_directory=True)
            root = repo / "secrets" / "generated" / "tiamat-release"
            with (
                mock.patch.object(tool, "_REPOSITORY_ROOT", repo),
                mock.patch.object(tool, "_SECRET_ROOT", root),
                self.assertRaisesRegex(OSError, "symlink"),
            ):
                tool.write_identities(
                    root / "staging-test",
                    tool.generate_identities(root_key_id="root", release_key_id="signer"),
                )
            self.assertEqual(list(redirected.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX paths")
    def test_posix_out_of_tree_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            root = repo / "secrets" / "generated" / "tiamat-release"
            outside = repo / "outside"
            with (
                mock.patch.object(tool, "_REPOSITORY_ROOT", repo),
                mock.patch.object(tool, "_SECRET_ROOT", root),
                self.assertRaisesRegex(ValueError, "output must be under"),
            ):
                tool.write_identities(
                    outside,
                    tool.generate_identities(root_key_id="root", release_key_id="signer"),
                )
            self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
