# Automatic encrypted backups (testnet candidate)

## v0.3.3: preserve valid recovery checkpoints

Restoring a backup establishes a valid recovery checkpoint. Enabling, disabling,
or changing the automatic-backup passphrase does not change wallet recovery data
and does not require a new download or acknowledgment. Keep the restored file and
its original passphrase; a new session passphrase applies to future exports only.
Explicit on-demand copies remain available without switching automatic mode off.

Actual recovery changes still queue a new encrypted snapshot. A notice beside
Prepare explains any outstanding backup and links to Backup status; preparation
stays disabled until the current snapshot is acknowledged saved. This prerequisite
does not start a transaction timer or report a failed preparation. Height refreshes
cannot bypass the backup gate. Upload is only for restoring a session, never for
acknowledging a saved backup.

## v0.3.2 follow-up: on-demand export while automatic mode is active

Once automatic mode is enabled, Download encrypted two-wallet backup now creates a current backup using the retained session passphrase without disabling automatic mode. Changing the passphrase remains a separate explicit action. Initial automatic setup still disables the competing manual button until Enable is pressed. Wallet operations and encryption remain mutually exclusive. The existing latest-file download link remains available for a direct user-initiated retry if the browser blocks downloads; an export request never proves a disk save.

Target path: `/veil-bsv-independent/v0.3.3/`. Keep earlier versions unchanged.
This is a UI-only update: no contract, circuit, encryption-format or pool change.
Existing v0.3.0 single-wallet and combined backups remain readable. Do not operate
the same wallet concurrently in old and new tabs.

## Use

1. Wait for any existing action and handoff to finish in the old tab. Save its
   newest backup. Keep it; do not rely on the original funding envelope.
2. Restore that backup in the new version. Do not start a new wallet or pool.
3. Open the live-wallet dialog, enter your unique 24+ character backup passphrase,
   read and check the session-only consent, and enable automatic backups.
4. Enabling automatic mode after restore does not require another download. When
   recovery data actually changes, check the timestamped `.veil` file in Downloads. Resolve any save prompt
   or download-blocking warning. Keep the file outside temporary browser storage.
   Click “I checked Downloads: this backup is saved” for the matching filename.
5. After an accepted full chain and after mined synchronization, Veil queues another
   compressed/encrypted backup. Check/acknowledge the newest file before another
   action. Do not mistake a pending-handoff backup for the synchronized backup.

The browser cannot report that an anchor-triggered download was durably written.
“Download requested” means only that a request was made. “Saved” is explicitly a
user acknowledgment. A download link stays available for manual retry until the
wallet changes or the tab leaves. Earlier disk files are not overwritten or deleted.
On failure, no automatic retry storm occurs; use Retry or the manual download.

## Privacy and recovery boundaries

- Automatic mode is off initially and after restore. The consent retains the
  passphrase only in this page's memory. It is not logged, exported in timers,
  put into local/session storage or uploaded. Disabling, locking, restoring or
  page exit clears the retained reference; JavaScript cannot promise memory erasure.
- Compression precedes authenticated encryption. The exact binary container is
  decrypted locally as a structural/authentication check before download. No
  plaintext backup file is written. This is not a test of disk durability.
- Automatic backup work has its own stopwatch and does not broadcast anything.
  Snapshot revision checks discard an in-flight result if wallet data changes.
  A confirmation for old state never clears the new backup requirement.
- Mining and handoff gates remain. These backups are recovery snapshots, not a
  resumable journal for a partially submitted chain. Keep a partial chain's live
  review open; do not reload. Background timer throttling may delay downloads.
- External-recipient encrypted payment delivery remains a separate operation.
- Tor/private-browser storage is not a durable backup destination. Browser support,
  prompts and repeated automatic downloads must be tested in the actual browser;
  no browser-specific successful-download claim is made from unit tests.

## Acceptance tests

Use only synthetic unfunded wallets for UI testing. Verify opt-in, masking, one
download per revision, timestamped names, explicit saved acknowledgment, disabled
mode/manual fallback, download-blocking fallback, stale snapshot cancellation,
failure without repeated prompts, restore resets opt-in, and legacy backup import.
Also verify restore → enable and passphrase changes preserve the valid checkpoint,
optional-copy failures do not dirty it, and dirty data remains gated across settings
changes. Only a current offered revision can be acknowledged saved.
For real Tor testing, enable on the existing restored wallet without broadcasting;
check Downloads and restore the resulting file in an isolated non-transacting tab.
Never reset the funded tab until its latest recovery backup has been verified.
