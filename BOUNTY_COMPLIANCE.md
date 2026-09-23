# Bounty compliance

Veil targets the publicly stated BSV bounty for a ZEC-style shielded pool with
on-chain zero-knowledge verification, notes, nullifiers, shield, private
transfer, unshield, and simultaneous shielding plus block-height locking.

## Condition matrix

| Condition | Where it is implemented | Replay/evidence |
| --- | --- | --- |
| Notes | `circuits/shielded_pool.circom`, `src/crypto.ts` | `npm run demo`, `npm test` |
| Nullifiers | Circuit membership/update rules and pool state | Double-spend regression and transfer replay rejection |
| Shield | Mode 0 transition and v4 staged covenant | Mined shield finalizer in public evidence |
| Private transfer | Mode 1 one-in/two-out transition | Mined transfer finalizer in public evidence |
| Unshield | Mode 2 bound P2PKH payout | Mined 10,000-satoshi recipient output |
| ZK on-chain | Groth16 BN254 verifier split across authenticated v4 stages | `npm run test:v4` and mined staged chains |
| Shielded and locked together | `lockHeight` is committed inside the private note | Locked note plus pre-maturity exclusion and mature unshield evidence |
| Public repo that can be replayed | Source, pinned lockfile, fresh development ceremony and exact deployed-verifier manifest | `npm ci && npm run bounty:replay` |

## What the chain evidence proves

The public record shows that miners accepted the v4 staged deployment and the
complete shield, private-transfer, and mature-unshield pipelines. For the
height-lock test, the exact begin transaction had `nLockTime` 1,759,649. It was
submitted at observed tip 1,759,629, remained unmined before maturity, and was
mined at height 1,759,651. The finalizer was mined at height 1,759,654 and
created the bound 10,000-satoshi recipient output.

ARC's pre-maturity `SEEN_ON_NETWORK` response is not described as a script
rejection. Bitcoin's height lock prevents premature inclusion in a block; it
does not require relay infrastructure to discard the transaction.

The sanitized evidence file contains no keys, note secrets, raw transaction
bytes, recovery credentials, or private service records.

The replay deliberately distinguishes an independently generated development
proving key from the exact public verification key used on testnet. It tests the
protocol with the fresh key, then reproduces and checks the mined verifier's
contract hashes from `evidence/deployed-verification-key.json`.

The exact deployed proving key and circuit WASM are kept out of Git history
because of their size. Their SHA-256 hashes are committed in
`evidence/deployed-v4-chain-manifest.json`; the matching files are packaged as
the `veil-v4-deployed-proving-artifacts` release asset.

## Remaining publication steps

Before announcing the bounty submission:

1. run the replay from a clean clone;
2. verify the release manifest and confidential-data scan;
3. publish the repository and immutable release/tag;
4. post the repository, replay command, evidence links, and limitations; and
5. notify the bounty author through the requested public channel.

Publishing and contacting the bounty author are deliberate external actions
and are not performed by any replay or test command.
