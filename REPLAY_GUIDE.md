# Replay Veil

Jack's bounty asks for a public repository that can be replayed. Veil does not
need a hosted service, public server, wallet account, or testnet coins for that
replay.

## macOS: double-click replay

1. Install Node.js 20 or newer from [`nodejs.org`](https://nodejs.org/) if it is
   not already installed.
2. Download and unzip the `veil-bsv-replay-0.2.2.zip` release asset.
3. Double-click `RUN_REPLAY.command` in the extracted folder. If macOS asks for
   confirmation, Control-click the file, choose **Open**, and confirm.
4. Leave the Terminal window open until it reports `VEIL BOUNTY REPLAY PASSED`.

The first run downloads pinned development dependencies and generates fresh
proof material. It can use most CPU cores for several minutes. That is expected.

## Terminal replay

From the extracted folder:

```bash
npm ci
npm run bounty:replay
```

The replay compiles the circuit and staged Bitcoin contracts, creates and
verifies shield/private-transfer/unshield proofs, checks rejection paths,
executes the staged verifier in the Bitcoin Script interpreter, checks the
exact deployed contract hashes, runs the tests, and builds the optional UI.

It does not:

- start or require a public server;
- read `.private/`;
- access a wallet or require testnet coins;
- contact a miner; or
- broadcast any transaction.

The mined testnet transaction evidence is in
[`evidence/testnet-v4-lifecycle.json`](evidence/testnet-v4-lifecycle.json), and
the bounty-condition mapping is in
[`BOUNTY_COMPLIANCE.md`](BOUNTY_COMPLIANCE.md).
