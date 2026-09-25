# Recipient-owned upgrade — local verification, 2026-09-25

Status: local release candidate. No publication, real deployment or broadcast
was performed for this verification. The original recovery tab was untouched.

## Verified locally

- The isolated circuit compiles and its development proving key passes zkey
  verification. It adds a private spending-key preimage check and secret-key
  nullifier derivation; output ownership is a public identifier.
- Seven recipient/state/encryption/backup tests pass. Negative ownership tests
  bypass host validation and are rejected by the circuit witness calculator.
- All 22 repository tests pass, including legacy replay and full unsigned
  recipient encoding coverage.
- Five new-key staged-verifier scenarios pass the Bitcoin Script interpreter:
  shield plus four withdrawal recipient-boundary/regression cases. Existing
  recipient-substitution, stage substitution and timeout tests also pass.
- The offline browser-builder rehearsal passes Add, two-wallet Send, encrypted
  import, receiver-only withdrawal, backup restore, state synchronization,
  Lock, early-spend rejection and mature withdrawal. Each generated covenant
  and funding signature is checked locally. Network statuses are mocked.
- Root and UI TypeScript checks pass; production UI build passes.
- An isolated localhost browser preview shows the independent-wallet controls
  in dark mode. Clearing an unbacked-up receiver is blocked. No actual funded
  wallet, password or private note was loaded in that preview.

## Corrections caught by the rehearsal

Final cryptographic review corrected the owner derivation to place the spending
secret in MiMC's **key** input, with a fixed public domain in its plaintext input.
The reversed ordering would be an invertible permutation under a publicly known
key and is unsafe. A regression test fixes this ordering in the protocol.

Pool import must retain the original empty-state constructor constants in the
contract code part, then apply current mutable roots. Reconstructing constructor
constants from current roots produces a different script and is rejected.

The tracked funding balance is now the actual funding-split change. A public
withdrawal to the same key is not silently added to that one-output balance.

## Release gates and limits

See `TWO_WALLET_DEMO.md` for manual file delivery, sequential state updates,
mined-but-not-proven-unspent status, 16-note capacity and partial-chain backup
limitations. There is no independent security audit, external mobile test,
new-protocol mined evidence or Merkle/header verification for this candidate.

Before publication: review source/privacy diff, build and fingerprint the
recipient verifier artifacts, package a new version, and obtain controlled
publication/deployment approval. Historical testnet evidence must stay labeled
as historical, not as proof of the recipient-owned upgrade.
