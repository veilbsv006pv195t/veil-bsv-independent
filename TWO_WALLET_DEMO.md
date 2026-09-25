# Two-wallet testnet demo — release candidate

This upgrade is not attested by the historical mined transactions. Local tests
use real proofs and Script execution but synthetic network responses. Publish
the audited build and confirm a fresh testnet pool before recording a live demo.
Do not refresh the old recovery tab to try this candidate.

## What changed

Each independent wallet derives a private spending secret and a separate
encryption key from its disposable testnet key. Its `veilt2` receiving address
contains a MiMC public owner identifier, a compressed encryption public key, and
a checksum. It does not contain the spending secret. A spend proves knowledge
of the secret preimage. Knowing a received note's amount, randomness and index
is no longer sufficient to spend it.

The new circuit lives in `circuits/recipient/`; its artifacts are isolated in
`build/recipient/` and `ui/public/zk/recipient/`. A different verification key
means a new verifier chain and pool deployment. Legacy replay stays separate.

## Guided mode: both demo wallets in one browser

Use **Guided demo** on first funded-wallet unlock. If you already have a live
v0.3.0 balance, first save its latest encrypted single-wallet backup in the old
tab, then restore that backup in the upgraded page; do not re-unlock the stale
original funding envelope. Initial setup creates a separate demo recipient and
prefills its full address in Send. Both keys remain under the demonstrator's
control. Uncheck guided mode for the ordinary independent-wallet flow below.

1. Save the combined encrypted **two-wallet** backup before any action. Keep
   the file and its 24+ character passphrase privately. Password inputs are masked.
2. Choose Add, Send, Lock or Withdraw and the amount. Send's demo address is
   editable; the exact review still requires a checkbox and broadcast click.
3. After acceptance, save an updated combined backup. Close the wallet dialog
   and keep the page open. Read-only checks run every 30 seconds; you can also
   use **Check mining and handoff now**. No new action is allowed while pending.
4. Once ARC reports MINED, Veil imports a demo payment into the other wallet
   and synchronizes pool state automatically. Switch to **Demo recipient** to
   see its balance. Save the newly synchronized combined backup.
5. To demonstrate the recipient spending, supply and bind a separate mined
   testnet fee-funding output to that recipient. Funds are not moved automatically
   for fees. Then review and explicitly broadcast its chosen action as usual.

Restore the latest combined file after reopening the page: this preserves both
identities and pending handoff without replacing the recipient. The page stores
only a non-secret setup marker; Tor may clear it on exit. There is no automatic
secret restoration from the website password. An accepted pending handoff can
be restored once mined, but a partial broadcast still needs the original tab.
Switches preserve each wallet's in-tab activity; backups preserve wallet state,
not the presentation-only activity list. An external recipient still needs the
downloaded encrypted payment file delivered manually.

## Ordinary mode: before recording

1. Use separate browser tabs for wallet A and wallet B. For network privacy,
   use the verified Tor-routed browser for **both**. The site itself cannot
   guarantee your browser's network routing.
2. In B, select **Create independent receiving wallet**. Choose a unique
   backup passphrase of at least 24 characters and download the encrypted
   backup. Keep that file and passphrase privately. Copy B's full Veil address.
3. Fund B's **testnet address** separately for miner fees. The private payment
   itself cannot pay the external fee sponsors. Each current verifier chain
   costs roughly 431,000 testnet sats, plus initial deployment if applicable;
   the exact review screen is authoritative.
4. In A, unlock the disposable funded wallet (or create another independent
   wallet). A published encrypted wallet may include its public funding
   transaction: unlocking then checks its TXID, amount, wallet ownership and
   ARC's mined status automatically, and displays the exact outpoint. Otherwise,
   under **Bind a mined funding output**, enter the public raw funding transaction
   and its output index. The output must still be unspent; mining alone does not
   establish that. Do not spend from the same funded wallet in an older tab.
   Click **Prepare a fresh pool**. This does not broadcast.
5. Save backups outside the browser. Do not share a wallet backup or its
   passphrase as a payment. The encrypted payment file is a different file.

## Demonstrate the actions

1. **Add:** choose an amount in A. Review the action, fees and every TXID, then
   approve the exact chain. Save an updated encrypted backup after acceptance.
2. **Send:** paste B's complete Veil address, choose an amount smaller than A's
   available mature note (leave at least one sat of change), review and submit.
   A's balance decreases by the sent amount. Download the encrypted payment
   file and A's updated backup.
3. Wait for the finalizer to be mined. In B, import that payment file. Import
   checks authenticated encryption, recipient ownership, unspent note state,
   roots, contract code, stage lineage and ARC's `MINED` status. B's balance
   increases; replaying the same file cannot credit it twice.
4. **Withdraw from B:** bind B's mined fee-funding output. Choose B's public
   testnet address and withdrawal amount; review and submit the chain. Save
   B's updated backup and download its **public pool update**.
5. After B's finalizer mines, import its public update into A before A's next
   action. A retains its own private notes; no secrets are in this update.
6. **Lock in A:** choose a portion of a mature note and a near-future block
   height, leaving change. Review and submit. Save the updated backup.
   A request that cannot be covered by a mature note is rejected before proof
   generation. An unlocked change note remains spendable.
7. **Withdraw after maturity:** wait for the selected height, then withdraw
   the locked amount. Network finality/mining may occur in a later block.
   Review the exact output and fee, submit, then inspect the finalizer in the
   testnet explorer. Save the final backup.

ARC acceptance is not mining. Neither a returned `MINED` status nor this import
flow is independent Merkle/header verification. Record live confirmations
separately; do not describe the offline rehearsal as a live broadcast.

## Important limits

- No Veil backend is needed, but public testnet APIs and a static host are.
- External-wallet delivery is manual. Guided mode only automates delivery between
  its two local demo wallets. Files can be several MB because they include public
  transaction lineage. There is no automatic inbox or wallet discovery.
- Synchronize **each** public pool update in order. Missing intermediate
  updates, stale snapshots and a different pool are rejected. Do not make
  concurrent transactions from separate wallets against the same pool.
- A `MINED` transaction is not proof that its output remains unspent. Funding
  and pool snapshots may become stale; network rejection must not be described
  as a successful transfer. This prototype does not have a spent-output indexer.
- The pool holds at most 16 append-only note slots. Send and Lock use two
  slots and must leave change. Withdraw without change can drain a full tree.
- The UI tracks one fee-funding output, not an entire wallet balance. Public
  withdrawal outputs are separate coins; bind a suitable output explicitly if
  you want to use it for subsequent fees.
- Backups restore completed, mined pool states. They do **not** automatically
  resume a partially broadcast chain. Never reload/close the tab mid-chain;
  keep its exact signed plan and seek controlled recovery if submission fails.
- Dark mode is supported. Mobile proof generation is heavy and remains to be
  tested on the reviewer's actual device. Do not promise instant completion.
- This is a development/testnet ceremony and a prototype, not independently
  audited production cryptography. Never use mainnet funds.

## Local verification

```bash
npm run build:circuit:recipient
npm run test:recipient
npm run test:v4:recipient
npm run sync:ui-artifacts
npm run test:two-wallet
npm test
npm run typecheck
npm run typecheck:ui
npm run build:ui
```

The two-wallet rehearsal blocks all unexpected network requests and every
non-GET request. It uses synthetic unfunded keys only. It covers Alice's Add,
Send to Bob, Bob's payment import and independent withdrawal, backup restore,
wrong-wallet/replay rejection, Alice's synchronization, Lock, early rejection,
and mature withdrawal using the actual browser transaction builder.
