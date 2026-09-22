# Tiamat staging recovery-root custody — 2026-09-22

This record contains no private key or passphrase. It concerns the **staging** root only; a
production deployment requires its own scoped signing identity and custody record.

- Root ID: `tiamat-recovery-root.staging.1`
- Public-key SHA-256: `54865ab6738e51177c2880f1fc31baf86afb4f0f4b58bc415c943d0def39d996`
- Operational copy: Ubuntu WSL, `/home/fortisanima/tiamat-recovery-offline-20260918/secrets/generated/tiamat-recovery/staging-20260918/root-private.json` (mode `0600`). This remains on the laptop for current staging ceremonies.
- Removable backup: `tiamat-recovery-root-staging-1-2026-09-22.gpg` at the root of Ray's PNY USB 2.0 FD. The `D:` letter observed during preparation is not a permanent device identifier.
- Backup format: GnuPG symmetric encryption, AES-256, salted/iterated S2K with SHA-512. The passphrase was entered by Ray directly at a local prompt; it was not passed through the agent, command arguments, chat, or repository.
- Encrypted file size: 211 bytes. Encrypted file SHA-256: `83894d0acd04d00e92d577fd56c56007b138ebcb06acdb529f2c0dbf65e416fd`.
- Verification: the USB ciphertext hash matched the WSL encrypted artifact. A copy of the USB ciphertext was taken back into WSL; Ray reported that the local, in-memory decrypt-and-derive check printed `USB recovery test passed: root ID and public fingerprint match`. The agent did not observe or retain the passphrase. A separate non-interactive repeat could not obtain a passphrase and did not decrypt; this is **not** a second successful test. No plaintext restore file was created. The temporary encrypted test copy was removed.
- External effects: no AWS call, anchor change, root rotation, new signature, or provider dispatch was part of this custody procedure.

## Owner actions still required

1. Store the USB separately from the laptop. Record its physical location in a private owner record, not in this repository.
2. Confirm the unique passphrase is saved in Ray's password manager. Keep an offline sealed recovery copy separately from the USB if desired. The agent has not verified either passphrase-custody step.
3. Retest the USB backup after moving it to its long-term location, and periodically thereafter. If the root is ever deliberately replaced, create and test a backup for the **new** root; this archive will still decrypt but will not become a backup of a replacement key.

The laptop plus this removable USB are two copies on separate media. Their independence against a
single physical incident depends on Ray storing the USB away from the laptop. A second removable
copy would improve resilience but is not recorded here as completed.
