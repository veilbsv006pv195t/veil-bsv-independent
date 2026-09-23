# Veil BSV provenance and independent-work record

This document records the origin and external inputs of the Veil BSV proof of
concept. It is intended to make the project's provenance reviewable; it is not
legal advice and does not override any employment, consultancy, confidentiality,
or intellectual-property agreement.

## Origin

- Work began on 18 September 2026 in response to a publicly stated bounty for a
  ZEC-style shielded pool on BSV with on-chain zero-knowledge verification,
  notes, nullifiers, shielding, private transfers, and unshielding.
- The implementation was produced as a standalone proof of concept with OpenAI
  Codex assistance from that public requirement.
- No employer or client source code, private repository, internal document,
  ticket, credential, account, or infrastructure appears in this repository or
  its dependency graph. The repository contains no package published under an
  employer- or client-controlled namespace.
- Contributors must independently confirm that they did not introduce
  confidential employer material or work in circumstances that assign the
  resulting intellectual property to another party.

## Public technical sources

The implementation uses these publicly distributed packages, pinned in
`package-lock.json`:

| Package | Version | Role | Declared license | Public project |
| --- | ---: | --- | --- | --- |
| `circomlib` | 2.0.5 | MiMC circuit templates | GPL-3.0 | <https://github.com/iden3/circomlib> |
| `circomlibjs` | 0.1.7 | Matching JavaScript MiMC implementation | GPL-3.0 | <https://github.com/iden3/circomlibjs> |
| `snarkjs` | 0.7.6 | Groth16 setup, proving, and verification | GPL-3.0 | <https://github.com/iden3/snarkjs> |
| `circom2` | 0.2.22 | Circom compiler | GPL-3.0 | <https://github.com/antimatter15/circom> |
| `scrypt-ts` | 1.4.5 | BSV smart-contract compiler and runtime | MIT | <https://github.com/sCrypt-Inc/scrypt-ts> |
| `scrypt-ts-lib` | 0.1.28 | BN254 verifier and MiMC contract library | MIT | <https://github.com/sCrypt-Inc/scrypt-ts-lib> |
| `vite` | 7.1.5 | Browser application build | MIT | <https://vite.dev> |
| `typescript` | 5.3.3 | TypeScript compiler | Apache-2.0 | <https://www.typescriptlang.org> |

Transitive packages and their exact integrity hashes are recorded in
`package-lock.json`. Each dependency remains subject to its own license. In
particular, the GPL-3.0 packages must be considered when distributing combined
or derivative work.

## Clean-repository boundary

The independent repository is created from an allowlisted source snapshot. It
must not contain:

- parent repository history or remotes;
- `.private/`, wallets, keys, private receipts, or testnet account credentials;
- personal email addresses, usernames, machine names, or absolute local paths;
- employer or client code, documentation, credentials, accounts, or
  infrastructure; or
- dependency caches and operating-system metadata.

Before publishing a release, run the test suite, regenerate the release archive,
verify `MANIFEST.sha256`, and repeat the confidential-data scan. Keep the
timestamped source manifest with the project records.

Sanitized public-chain facts such as TXIDs, block hashes, heights and explorer
links are intentionally retained under `evidence/`. They are independently
observable and contain no keys, note openings, raw transaction bytes, wallet
credentials or private service records.

## Public-chain disclosure

A BSV testnet or mainnet deployment publishes the compiled locking script,
transaction values, transaction graph, state roots, and timing permanently.
Tor can reduce network-origin disclosure during broadcast but cannot make the
on-chain contract confidential.
