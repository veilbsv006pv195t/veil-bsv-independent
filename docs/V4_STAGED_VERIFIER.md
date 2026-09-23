# Optimized-v4 staged verifier

Optimized-v4 replaces the 928 KB monolithic verifier with an authenticated
seven-transaction pipeline:

1. `ShieldedPoolV4.begin` commits the exact proof, public transition, pool code,
   locked value, and recovery height.
2. `VeilV4Preparation.prepare` computes the public-input G1 multiplication and
   normalizes the three dynamic pairing points.
3. Four specialized Miller contracts each execute 16 loop digits.
4. `VeilV4Finalizer.finalize` performs the two terminal line operations, checks
   the residue witness and Groth16 pairing equation, and releases only the
   proof-bound successor pool/output set.

Every boundary commits to the complete verifier state with SHA-256. Each
contract commits to the exact next contract code-part with HASH256, so a caller
cannot skip, reorder, or substitute a stage. Prepared gamma/delta lines are
immutable constructor data. The finalizer also authenticates the original pool
code before recreating its state.

Preparation, all four Miller stages, and the finalizer provide a block-height
timeout path. After the committed recovery height, anyone can return the locked
value to the old pool roots. The entry contract caps the timeout at 144 blocks.
This prevents an invalid or abandoned proof from freezing the pool forever.

## Local evidence

Run:

```sh
npm run build:v4
npm run test:v4
```

`build:v4` compiles the contracts and writes `build/v4/chain-manifest.json`
using the real public verification key. `test:v4` creates a fresh shield proof
and executes all seven transactions in the Bitcoin Script interpreter under a
10,000-byte Script-number policy.

The current manifest keeps every locking script below the miner's 500,000-byte
policy target. Shield and two-note private-transfer paths pass locally. Network
send commands are separate, Tor-only, single-transaction operations gated by
the exact audited TXID; preparation and audit commands never broadcast.

The test also rejects substituted successor code, altered committed state, an
all-zero residue witness, and recovery before the committed height. Recovery at
the committed height recreates the prior pool state successfully. It asserts
that every unlocking script is below 500,000 bytes; the largest is preparation
at 483,947 bytes.

## Testnet deployment and lifecycle controls

The following commands use the local Tor SOCKS proxy and the active GorillaPool
Arcade policy endpoint:

```sh
npm run deploy:v4:status
npm run deploy:v4:dry-run
npm run deploy:v4:prepare -- --funding=TXID:VOUT:SATS:BLOCKHEIGHT
npm run deploy:v4:audit
npm run lifecycle:v4:confirm-shield
npm run lifecycle:v4:prepare-transfer
npm run lifecycle:v4:audit-transfer
npm run lifecycle:v4:prepare-lock-test
npm run lifecycle:v4:audit-lock-test
npm run lifecycle:v4:send-locked-shield-chain -- --expect-manifest=<audited-manifest-hash>
npm run lifecycle:v4:send-early-unshield -- --expect=<audited-unshield-begin-txid>
```

Preparation validates funding and prior mined inclusion evidence, signs
locally, stores raw bytes and note secrets only under the ignored `.private/`
directory with mode 0600, and prints a sanitized audit. Transfer preparation
also proves that local state rejects the spent note and that the successor pool
rejects replay of the old transition.

Live sends require an explicit `--expect=<exact-audited-txid>` argument. Each
stage also refuses to run until ARC supplies mined block, block-hash, and Merkle
inclusion evidence for its direct predecessor. There is no direct-network
fallback or automatic retry.

## Testnet result

The v4 deployment, complete shield pipeline, complete private-transfer
pipeline, locked-note creation, and mature unshield pipeline have all mined on
BSV testnet. The locked-unshield begin transaction was submitted while the
observed tip was 1,759,629 with `nLockTime` 1,759,649. ARC accepted it into its
network but it was not mined prematurely; it entered block 1,759,651. The
unshield finalizer later paid the bound 10,000-satoshi recipient output in
block 1,759,654.

This establishes miner acceptance of the staged execution and the intended
block-height exclusion. It does not constitute a security audit or a claim of
production readiness. See `evidence/testnet-v4-lifecycle.json` for sanitized
public TXIDs and block evidence.
