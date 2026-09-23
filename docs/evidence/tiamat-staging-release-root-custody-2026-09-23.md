# Staging RELEASE identity custody — 2026-09-23

This is custody evidence for the **staging RELEASE** identity, not the recovery root. It does not authorize provider dispatch, install a release inventory, or change the live recovery anchor.

## Public identities

| Purpose | Key ID | SHA-256 of raw Ed25519 public key |
|---|---|---|
| RELEASE root | `tiamat-release-root.staging.1` | `e56147d2ed53475f8ab315f469f745ce9ea7a7703a101341b9b2ac0a9e47ae05` |
| RELEASE signer | `tiamat-release-signer.staging-gate2b.1` | `dd88eb7da8fd111108090b015290553d3133f4aa2535020de8c2dfcf37c6f39a` |

The approved public root pin is `deploy/postgres/tiamat-staging-release-root-pin.json`. Root and signer have distinct material. Neither private key is in Git, Render, AWS, or the Windows project checkout.

## Ceremony and backup

- The identities were generated on native Ubuntu storage at `/home/fortisanima/tiamat-recovery-offline-20260918/secrets/generated/tiamat-release/staging-20260923`, using the repository's `generate_tiamat_release_identity_v1.py` copied byte-for-byte into that offline checkout (source SHA-256 `3dcc696e336f6096253107c1a078eed721a99be8931480c77aacfa73bb69f8c4`). The generator refused Windows and checked POSIX private directory/file permissions and symlink-free output paths.
- An encrypted GPG AES-256 archive was copied to removable drive `D:` as `tiamat-release-staging-1-2026-09-23.gpg`. The ciphertext was 587 bytes; its SHA-256 was `156EFB0C31A5796CB5A108B185DE3477C9F2E4EB0C3BF2F1551FFA78F73FA936`. The staging and USB ciphertext hashes matched. The drive letter is an observation, not a permanent identifier.
- A separate, USB-derived ciphertext copy was decrypted through a visible local passphrase prompt and streamed to `verify_tiamat_release_backup_v1.py` (SHA-256 `ee1a2346565ba3c9a09b8e40147729c34435cbe2a65b54c29e94589a6d0f757a`). Ray reported `restore passed`; the verifier checked the exact four-file archive, key IDs, private-to-public key pairs and both expected fingerprints without writing plaintext files. Temporary ciphertext copies on `C:` were removed after the USB hash was rechecked. The offline originals and encrypted USB backup were retained.
- No passphrase or private-key bytes were captured in this evidence. Durable placement of the USB away from the laptop and passphrase-manager storage are operator custody tasks, not verified here.

This evidence establishes a recoverable staging signing identity. It does **not** establish a signed generation-one inventory, an installed release, or an active serving entitlement. Those remain later Gate 2 steps.
