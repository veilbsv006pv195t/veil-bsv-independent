# Security status

Veil is an experimental, unaudited shielded-pool proof of concept. It must not custody real funds.

## Known limitations

- The replay script performs a single-contributor Groth16 setup. This is useful for rebuilding the bounty demo but unsafe for production because the setup secret is not credibly destroyed.
- The circuit and covenant have not had an independent cryptographic or Script audit.
- The fixed 16-note tree and 1-in/1-or-2-out join-split are demonstration limits.
- Recipient note encryption, scanning keys, recovery, reorg handling, concurrency, and production note selection are out of scope.
- The large verifier depends on BSV miner relay policy in addition to consensus validity.
- Browser state is intentionally local demo state and is not a chain indexer.
- The UI's displayed current height is a demo value. A chain-connected wallet must derive height from a trusted, reorg-aware source and must not treat a merely observed tip as irreversible finality.
- Note locks use absolute block heights below `500,000,000`. The circuit proves maturity and the covenant enforces transaction `nLockTime` plus a non-final sequence; changing this relationship can silently weaken the lock.
- `npm audit` reports high-severity advisories in transitive dependencies of the pinned sCrypt/circom toolchain. The affected networking/Rabin helpers are not used by the browser proof flow, but the dependency graph must be upgraded or isolated before production use.

## Before any deployment

1. Run a real multi-party ceremony and pin the resulting verification key.
2. Obtain independent circuit, covenant, and wallet audits.
3. Add encrypted note delivery and authenticated viewing keys.
4. Add chain indexing, confirmation/reorg handling, concurrent-state conflict recovery, and wallet backups.
5. Test the exact serialized transactions with the target miner's current policy and fee quote.
6. Deploy to testnet, publish txids, and run adversarial proof, amount, root, recipient, and double-spend vectors.

Please report vulnerabilities privately to the repository owner rather than testing against funds you do not own.
