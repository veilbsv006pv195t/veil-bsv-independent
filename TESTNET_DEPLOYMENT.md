# Optimized-v4 BSV testnet deployment

This document describes the controlled testnet workflow for the deployed v4
staged verifier. Local replay does not require Tor, a wallet, or testnet funds.
Every live command is separate from build and audit commands.

All remote status and submission requests fail closed through the local Tor
SOCKS proxy at `127.0.0.1:19050`. There is no direct-network fallback. Private
keys, signed transaction bytes and note openings remain in the ignored
`.private/` directory with mode `0600` and must never be published.

## Local replay

```bash
npm ci
npm run bounty:replay
```

This is the public bounty replay. It compiles and tests everything locally and
never broadcasts.

## Deployment controls

```bash
npm run deploy:v4:status
npm run deploy:v4:dry-run
npm run deploy:v4:prepare -- --funding=TXID:VOUT:SATS:BLOCKHEIGHT
npm run deploy:v4:audit
npm run deploy:v4:send -- --expect=EXACT_AUDITED_TXID
npm run deploy:v4:confirm
```

`prepare` validates the confirmed funding outpoint, constructs and signs
locally, and saves private intent records. `audit` reparses those exact bytes
and executes the relevant checks without network access. `send` requires the
exact audited TXID and transmits only the saved bytes. An uncertain response
must be reconciled by TXID before any manual retry.

## Lifecycle controls

The shield and transfer paths use the same pattern: prepare, audit, then submit
an exact parent-first chain. No command used by the public replay sends funds.

```bash
npm run lifecycle:v4:prepare-shield
npm run lifecycle:v4:audit-shield
npm run lifecycle:v4:prepare-transfer
npm run lifecycle:v4:audit-transfer
npm run lifecycle:v4:prepare-lock-test
npm run lifecycle:v4:audit-lock-test
```

Individual send commands are intentionally explicit and guarded by audited
TXIDs or manifest hashes. Operators should inspect `package.json --scripts`
and the relevant script help before using them. The seven proof stages are:

1. begin;
2. preparation;
3. Miller stage 0;
4. Miller stage 1;
5. Miller stage 2;
6. Miller stage 3; and
7. finalizer.

They form a strict dependency chain. After robust local testing, the chain can
be submitted parent-first without waiting for a block between every stage,
provided the chosen miner accepts the complete unconfirmed ancestor chain.
Serial confirmation remains the conservative diagnostic mode.

## Completed testnet result

The optimized-v4 deployment and complete shield, private-transfer,
shielded-height-lock, and mature-unshield pipelines mined successfully. The
height-locked unshield begin was submitted 20 blocks before its lock height and
was not mined before maturity. The final unshield produced the exact bound
10,000-satoshi recipient output.

See `evidence/testnet-v4-lifecycle.json` for public TXIDs, block heights,
hashes, and explorer links. That file deliberately excludes raw transaction
bytes, keys, note openings, wallet addresses used only for operations, and
private API records.

## Safety boundary

- Testnet evidence is not a security audit.
- The proving ceremony is development-only.
- Do not use real funds.
- Never publish `.private/` or copy its contents into an issue or bounty post.
- Never interpret `SEEN_ON_NETWORK` as proof of mining; require a block height,
  block hash, and inclusion evidence.
- Publishing, changing repository visibility, tagging a release, or contacting
  the bounty author are separate external actions requiring deliberate review.
