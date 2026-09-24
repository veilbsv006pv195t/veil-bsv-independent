# Veil BSV

Veil is a replayable proof of concept for the bounty requirement:

> ZEC-style shielded pool on BSV: notes, nullifiers, shield, private transfer, and unshield, with zero-knowledge verification on-chain.

It includes the protocol, a complete local replay, public testnet evidence, and
an optional wallet UI. The bounty replay does not require a running server,
hosted website, wallet, testnet coins, or blockchain connection.

**Live static demo:**
[`veilbsv006pv195t.github.io/veil-bsv-independent`](https://veilbsv006pv195t.github.io/veil-bsv-independent/)

The site has no Veil backend and never receives private inputs. Its default
mode generates and verifies proofs in the visitor's browser against local demo
state. An optional reviewer mode can unlock a disposable, testnet-only wallet
in the browser and prepare real testnet transactions, but it is disabled unless
an encrypted wallet envelope is deliberately included in the site. The public
repository replay and mined testnet evidence remain the authoritative
implementation evidence.

## One-command bounty replay

The release archive includes `RUN_REPLAY.command`. On macOS, double-click it and
choose **Open** if Finder asks for confirmation. It installs the pinned
dependencies and runs the complete replay in a Terminal window.

From a clean clone with Node.js 20+ and npm, the equivalent terminal commands
are:

```bash
npm ci
npm run bounty:replay
```

This compiles the circuit and optimized-v4 staged contracts, runs the local
shield/private-transfer/unshield demonstration, executes the complete staged
verifier in the Bitcoin Script interpreter, runs positive and negative tests,
type-checks the source, and builds the browser UI. It never reads `.private/`,
contacts a miner, or broadcasts a transaction.

The first clean run creates a fresh development ceremony and is intentionally
CPU-intensive; `snarkjs powersoftau prepare phase2` may use all available CPU
cores for several minutes. The fresh key proves independent source replay. The
same command separately checks the committed deployment verification key
against the exact v4 contract hashes that were mined on testnet.

See [`REPLAY_GUIDE.md`](REPLAY_GUIDE.md) for the short non-developer checklist
and the exact success criteria.

## Optional local wallet UI

The UI is supplementary and is not required to satisfy or replay the bounty.
Its normal mode creates and verifies real proofs against local demo state but
does **not** broadcast or spend funds. Developers can run it locally with:

```bash
npm run build:circuit
npm run dev:ui
```

Then open `http://127.0.0.1:5173`. This temporary local development process is
only a file preview for the optional UI; it is not a Veil server or part of the
bounty replay.

### Optional password-unlocked testnet reviewer mode

The static UI can also prepare and submit the real v4 staged transaction chain
without a Veil server. This mode is intentionally limited to a disposable
testnet wallet. Put its unencrypted record in the ignored file
`.private/live-demo-wallet.json`:

```json
{
  "network": "testnet",
  "address": "testnet address",
  "wif": "matching testnet WIF",
  "funding": {
    "txid": "confirmed funding transaction ID",
    "vout": 0,
    "satoshis": 10000000
  }
}
```

Then run `npm run live-wallet:encrypt` interactively. The command requires a
password of at least 24 characters and writes only an AES-256-GCM envelope to
`ui/public/live-wallet/encrypted-wallet.json`; it never prints the password or
WIF. The address and funding outpoint remain public so the static page does not
depend on an address-indexing API. Deliver the password separately from the site
URL.

After unlock, the reviewer chooses the action and amount. The browser generates
the Groth16 proof, constructs and signs the deployment/funding/verifier chain,
runs the Bitcoin Script interpreter against every covenant and sponsor input,
and shows the exact action, recipient, miner fees, and TXIDs. Nothing is sent
until the reviewer checks the confirmation box and clicks the separate
**Broadcast exact testnet chain** button. Submission is parent-first to ARC;
network height, policy, and submission status are read directly from public
testnet APIs, while the confirmed starting outpoint is bound into the envelope.

Keep the tab open for the whole reviewer session. Private note state is
deliberately kept in memory rather than persisted by the public site; reloading
after a broadcast retires that one-session reviewer wallet flow.

The password is not a spending policy. Anyone who knows it can recover the
disposable WIF from browser memory and control all of that wallet's testnet
coins. Retire the password and remove the encrypted envelope after review.
Never use this mode with mainnet funds. The current **Send** action demonstrates
a private nullifier-and-new-note transfer back to a fresh note controlled by the
same disposable reviewer wallet; interoperable recipient note delivery remains
out of scope, as documented below.

## Independent live testnet operator

The replay above needs no wallet or coins. An operator who wants to reproduce
the mined lifecycle can instead create a fresh, testnet-only wallet:

```bash
npm run wallet:testnet:init
npm run wallet:testnet:status
```

`init` prints only the funding address. The private key stays in the ignored
`.private/testnet-deployment-wallet.json` file with mode `0600`; the command
refuses to replace an existing wallet. Fund that address with **testnet BSV
only**. The BSV documentation lists public testnet faucets, including
[`bsvfaucet.com`](https://bsvfaucet.com/) and
[`witnessonchain.com/faucet/tbsv`](https://witnessonchain.com/faucet/tbsv).
A full deployment plus shield, transfer, lock, and unshield rehearsal should
start with at least 2,100,000 testnet satoshis for the current scripted fee
budget and headroom.

The command-line live path remains intentionally controlled: prepare locally,
audit exact bytes, approve the displayed TXID or manifest hash, then submit
parent-first through Tor. The optional reviewer mode above provides the same
prepare/review/submit boundary in a static browser UI. See
[`TESTNET_DEPLOYMENT.md`](TESTNET_DEPLOYMENT.md) for the complete operator
runbook. A pre-funded demonstration wallet may be handed to a reviewer through
a private channel, but its key must never be committed, attached to a release,
or posted publicly.

For the short circuit-only demonstration, run:

```bash
npm run demo
```

Expected result:

```text
✓ shield            ...
✓ private transfer  ...
✓ unshield          ...
✓ height lock rejected a spend before block 900,000
✓ tampered statement rejected
✓ sCrypt verifier accepted the Groth16 proof
```

Run the historical monolithic BSV locking script itself, including a positive
unshield and a tampered-proof rejection:

```bash
npm run build:contract
npm run test:onchain
```

On the reference machine the script test reports:

```text
✓ Bitcoin Script accepted the unshield proof
✓ Bitcoin Script rejected an all-zero residue witness
✓ Bitcoin Script rejected the note one block before unlock
✓ Bitcoin Script rejected a tampered proof
locking script: 1,097,379 bytes
```

That command is retained as a regression test. The deployed optimized-v4 path
is the staged verifier below, not this monolithic contract.

The v4 verifier splits proof checking across seven authenticated transactions.
The largest generated locking script is 248,381 bytes and the local test
asserts every unlocking script is also below 500,000 bytes. The complete
shield, private-transfer, height-lock and mature-unshield sequences have been
mined on BSV testnet. Public transaction evidence is recorded in
[`evidence/testnet-v4-lifecycle.json`](evidence/testnet-v4-lifecycle.json).

Run all circuit/state tests and build the UI:

```bash
npm test
npm run typecheck
npm run build:ui
```

## What is actually proven

Every transition has one public Groth16 signal: a domain-separated SHA-256 hash
of the complete public transition, reduced to a fixed 248-bit field element.
The BSV covenant independently serializes the same transition and recomputes
that hash from its current state and the proposed transaction. MiMC remains in
the private note, nullifier, and Merkle-tree relations inside the circuit.

```text
transparent BSV
      │ shield (public amount)
      ▼
┌──────────────────────────────────────────┐
│ Stateful pool UTXO                       │
│ noteRoot · nullifierRoot · nextNoteIndex │
└──────────────────────────────────────────┘
      │              │
      │ private send │ unshield (public amount + P2PKH)
      ▼              ▼
 new notes       transparent BSV
```

The circuit enforces:

- `note = MiMC(MiMC(MiMC(amount, ownerKey), lockHeight), rho)`;
- ownership by knowledge of `ownerKey` and `rho`;
- block-height maturity without revealing the note's committed lock height;
- membership of the input note in the append-only note tree;
- `nullifier = MiMC(note, ownerKey)`;
- a zero leaf in the nullifier tree before spend, then insertion of that nullifier;
- proven-empty append positions for new notes;
- 64-bit amount ranges and exact value conservation;
- mode rules for shield, private transfer, and unshield;
- binding of roots, indices, commitments, nullifier, public amounts, and withdrawal recipient into the one public statement.

The contract then enforces:

- the Groth16 BN254 proof inside Bitcoin Script, using prepared constant lines
  and a checked pairing-residue witness to avoid the full final exponentiation;
- the proof height against transaction `nLockTime`, with a non-final input sequence;
- the exact successor state output;
- `old pool value + publicIn - publicOut`;
- the exact P2PKH withdrawal output; and
- retention of a one-satoshi state anchor.

## Requirement coverage

| Requirement | Implementation |
| --- | --- |
| Notes | MiMC commitments in an append-only depth-4 Merkle tree |
| Nullifiers | Public nullifier plus a stateful nullifier Merkle tree; a used slot cannot be spent again |
| Height locks | Each note privately commits to an absolute BSV block height; spends prove maturity and bind it to transaction `nLockTime` |
| Shield | Public input becomes one private note and increases the pool UTXO value |
| Private transfer | One private note becomes a recipient note plus a private change note; no public value crosses the boundary |
| Unshield | One private note becomes an optional change note plus a bound P2PKH payout |
| ZK on-chain | Compiled sCrypt covenant calls the BN254 Groth16 verifier and binds transaction outputs |
| Replayable | Scripted clean build, three-transition CLI replay, negative tests, browser prover, and Script VM test |
| Independent live use | Fresh testnet-only wallet initialization, public faucet guidance, guarded exact-TXID submission, and mined public evidence |

## Repository map

- `circuits/shielded_pool.circom` — universal shield/transfer/unshield relation.
- `src/contracts/shieldedPool.ts` — stateful BSV covenant and on-chain verifier.
- `src/v4/` — deployed staged pool, preparation, four Miller stages, and finalizer.
- `src/crypto.ts` — notes, nullifiers, Merkle state, and transition builder.
- `src/groth16.ts` — snarkjs → sCrypt BN254 conversion.
- `ui/` — responsive non-developer wallet interface with in-browser proofs.
- `scripts/demo.ts` — complete proof replay and tamper test.
- `scripts/verify-onchain.ts` — actual Bitcoin Script execution test.
- `scripts/test-v4-chain.ts` — complete optimized-v4 staged Script execution and negative tests.
- `tests/pool.test.ts` — circuit witnesses and double-spend regression tests.
- `evidence/testnet-v4-lifecycle.json` — sanitized public testnet transaction evidence.
- `evidence/deployed-verification-key.json` — exact public verification key used by the mined deployment.
- `evidence/deployed-v4-chain-manifest.json` — exact deployed contract sizes and code-part hashes.

## Block-height locks

Every note has a private `lockHeight` committed into its note hash. A value of
zero means immediately spendable. To spend a locked note, the owner supplies a
public `currentHeight`; the Groth16 circuit proves privately that:

```text
input note lockHeight <= currentHeight
```

The covenant then requires a block-height `nLockTime >= currentHeight` and a
non-final input sequence. Bitcoin therefore cannot mine the transaction before
the note is mature. Lock heights must be below `500,000,000`, keeping them in
Bitcoin's block-height namespace rather than its timestamp namespace.

In the UI, choose **Lock**, enter an amount, and select an unlock block. Locked
coins are shown separately from the spendable private balance.

## Current scope

This is bounty-grade, auditable proof-of-concept code—not production money software:

- The tree is intentionally depth 4 (16 notes) so anyone can replay it quickly. Increase `TREE_DEPTH` and the circuit depth together for a larger pool.
- The join-split is 1-in/1-or-2-out. Production wallets need note selection and multi-input aggregation.
- The scripted single-contributor ceremony is **development only** and gives no production toxic-waste protection. A real deployment must use a multi-party ceremony or a different proving system.
- Proof verification uses a seven-transaction authenticated pipeline. This
  improves miner-policy compatibility at the cost of latency, fees, and
  intermediate state. Production submission should send the dependency chain
  parent-first and reconcile every TXID on an uncertain response.
- Notes are not yet encrypted for recipient discovery; the demo assumes note plaintext is delivered out of band.
- No security audit has been performed. Do not use real funds.

See [SECURITY.md](SECURITY.md) before extending or deploying the protocol.
See [COMPATIBILITY.md](COMPATIBILITY.md) for supported demo computers and the
recommended presentation setup.
See [PROVENANCE.md](PROVENANCE.md) for the independent-work boundary, public
dependencies, and release provenance record.
See [BOUNTY_COMPLIANCE.md](BOUNTY_COMPLIANCE.md) for the bounty-condition
mapping and public testnet evidence.
See [TESTNET_DEPLOYMENT.md](TESTNET_DEPLOYMENT.md) for the Tor-only v4
deployment and lifecycle controls.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency notices.

## License

MIT for original project source. Dependencies retain their own licenses;
notably snarkjs/circomlib are GPL-3.0. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
