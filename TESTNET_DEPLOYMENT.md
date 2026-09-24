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

## Fresh operator wallet and funding

Create a new wallet for this testnet rehearsal only:

```bash
npm run wallet:testnet:init
npm run wallet:testnet:status
```

The first command creates `.private/testnet-deployment-wallet.json`, protects
it with mode `0600`, and prints only its public testnet address. It fails if the
file already exists. `status` reparses the WIF, verifies that it is a testnet
key and that its derived address matches the record, then prints only public
metadata.

Fund the displayed address with testnet BSV, never mainnet BSV. Public options
listed by BSV documentation include:

- <https://bsvfaucet.com/>
- <https://witnessonchain.com/faucet/tbsv>
- <https://docs.bsvblockchain.org/network-topology/nodes/sv-node/installation/sv-node/network-environments/testnet>

The exact requirement depends on current miner policy and the selected
lifecycle. For the complete deployment, shield, private transfer, locked note,
and mature unshield rehearsal, start with at least **2,100,000 testnet
satoshis (0.021 tBSV)**. This is test currency with no monetary value. Record a
confirmed funding output as `TXID:VOUT:SATS:BLOCKHEIGHT`; do not paste the WIF
into a shell command, issue, log, or chat.

For a reviewer handoff, use a brand-new disposable wallet funded directly from
a faucet where possible. Transfer the wallet file through a private channel,
not GitHub. The reviewer places it at
`.private/testnet-deployment-wallet.json`, runs `chmod 600` on it, and verifies
it with `npm run wallet:testnet:status` before doing anything else. This keeps
the public repository reproducible without publishing a spendable secret.

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

A clean deployment no longer depends on the historical v3 replacement case.
If an audited deployment intentionally replaces a recorded pending v3 spend,
`send` additionally requires
`--replace-pending-v3=EXACT_RECORDED_V3_TXID`; otherwise that flag is rejected.

## Lifecycle controls

The shield and transfer paths use the same pattern: prepare, audit, then submit
an exact parent-first chain. No command used by the public replay sends funds.

```bash
npm run lifecycle:v4:prepare-shield
npm run lifecycle:v4:audit-shield
npm run lifecycle:v4:prepare-transfer
npm run lifecycle:v4:audit-transfer
npm run lifecycle:v4:confirm-transfer
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

The exact submission commands are deliberately separate:

```bash
npm run lifecycle:v4:send-split -- --expect=EXACT_SPLIT_TXID
npm run lifecycle:v4:send-begin -- --expect=EXACT_BEGIN_TXID
npm run lifecycle:v4:send-stage -- --stage=prepare --expect=EXACT_TXID
npm run lifecycle:v4:send-stage -- --stage=miller-0 --expect=EXACT_TXID
npm run lifecycle:v4:send-stage -- --stage=miller-1 --expect=EXACT_TXID
npm run lifecycle:v4:send-stage -- --stage=miller-2 --expect=EXACT_TXID
npm run lifecycle:v4:send-stage -- --stage=miller-3 --expect=EXACT_TXID
npm run lifecycle:v4:send-stage -- --stage=finalize --expect=EXACT_TXID
```

The private-transfer equivalents are `send-transfer-split`,
`send-transfer-begin`, and `send-transfer-stage`. Always take the exact TXIDs
and stage names from the immediately preceding audit output. Do not copy the
historical evidence TXIDs into a fresh run.

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
