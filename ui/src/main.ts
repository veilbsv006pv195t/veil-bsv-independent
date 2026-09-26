import './styles.css'
import { proveAction } from './prover'
import type { LiveVeilSession, PreparedLiveAction } from './live-builder'
import { broadcastRawTransaction, explorerUrl, testnetHeight, transactionStatus } from './live-network'
import { unlockLiveWallet, createReceivingWallet, validateReceivingWallet, type LiveWallet } from './live-wallet'
import { createHash } from '../../src/crypto'
import { recipientIdentity, RECIPIENT_PROTOCOL, type EncryptedPayment } from '../../src/recipient'
import { encryptBackup, decryptBackup, type WalletBackup } from '../../src/walletBackup'
import { GuidedDemo, GUIDED_FORMAT, GUIDED_MARKER, otherRole, type Role } from './guided-demo'
import { fetchUsdQuote, mainnetUsd, isFresh, type UsdQuote } from './usd-price'
import { canUnlockOriginalWallet, canCreateGuidedRecipient } from './wallet-entry-guard'
import { Stopwatches, elapsed } from './stopwatches'
import { MAX_BACKUP_FILE_BYTES } from '../../src/backupCompression'
import { encodeBackupFile, decodeBackupFile } from '../../src/backupFile'

const timers = new Stopwatches()
let foregroundTiming: number | null = null
let actionTiming: number | null = null
const miningTimings = new Map<string, number>()
let miningCheckBusy = false
let modalExpanded = false
let modalSize = { width: '', height: '' }

function timingStrip(): string {
    const snapshot = timers.snapshot()
    const active = snapshot.operations.filter(r => r.outcome === 'In progress')
    const last = active.at(-1) ?? snapshot.operations.at(-1)
    return `<strong>Overall ${elapsed(snapshot.overallMs)}${snapshot.running ? '' : ' · stopped'}</strong>${(active.length ? active : last ? [last] : []).map(r => `<span>${escapeHtml(r.label)} ${elapsed(r.elapsedMs)} · ${r.outcome === 'In progress' ? `${escapeHtml(r.phases.at(-1)!.label)} ${elapsed(r.phases.at(-1)!.elapsedMs)}` : escapeHtml(r.outcome)}</span>`).join('')}${last ? '' : '<span>Starts with the first operation</span>'}`
}
function updateTimers(): void {
    document.querySelectorAll('[data-timing-strip]').forEach(node => { node.innerHTML = timingStrip() })
    const details = document.querySelector('#timing-records')
    if (details) details.innerHTML = timers.snapshot().operations.map(r => `<li><strong>${escapeHtml(r.label)} · ${elapsed(r.elapsedMs)} · ${escapeHtml(r.outcome)}</strong><ul>${r.phases.map(p => `<li>${escapeHtml(p.label)}: ${(p.elapsedMs / 1000).toFixed(1)}s</li>`).join('')}</ul></li>`).join('')
}
function modalToolbar(): string {
    return `<div class="modal-toolbar"><button class="secondary-button" id="expand-modal" aria-pressed="${modalExpanded}">${modalExpanded ? 'Restore size' : 'Expand'}</button><div data-timing-strip class="timing-strip">${timingStrip()}</div></div>`
}
async function checkMiningTimings(): Promise<void> {
    if (miningCheckBusy || !miningTimings.size) return
    miningCheckBusy = true
    try {
        for (const [txid, id] of miningTimings) {
            // Guided actions finish after both mining and handoff, not mining alone.
            if (state.guided?.pending?.txid === txid) continue
            try {
                const status = await transactionStatus(txid)
                if (status?.txStatus === 'MINED') { timers.finish(id, 'ARC reports mined'); miningTimings.delete(txid) }
                else if (status && /REJECT|CONFLICT|DOUBLE_SPEND/.test(status.txStatus)) { timers.finish(id, `ARC ${status.txStatus}`); miningTimings.delete(txid) }
            } catch { /* Keep elapsed wait running. This check never resubmits. */ }
        }
    } finally { miningCheckBusy = false; updateTimers() }
}

type Action = 'shield' | 'send' | 'lock' | 'withdraw'
type Theme = 'light' | 'dark'

interface Activity {
    received?: boolean
    kind: Action
    title: string
    detail: string
    amount: number
    time: string
    proof: string
}

declare global {
    interface Window {
        bsv?: {
            isBSVOS?: boolean
            getStatus?: () => Promise<{ locked?: boolean; hasWallet?: boolean }>
            getBalance?: () => Promise<{ confirmed?: number }>
        }
    }
}

const icons = {
    shield: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5.5 5.7v5.1c0 4.2 2.7 8 6.5 9.2 3.8-1.2 6.5-5 6.5-9.2V5.7L12 3Z"/><path d="m9.2 11.7 1.8 1.8 4-4"/></svg>`,
    send: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h13M14 8l4 4-4 4"/></svg>`,
    withdraw: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v13M8 13l4 4 4-4"/><path d="M5 20h14"/></svg>`,
    check: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 12.5 3.5 3.5L18 7.5"/></svg>`,
    lock: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="10" rx="3"/><path d="M8 10V8a4 4 0 0 1 8 0v2"/></svg>`,
    copy: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>`,
    sun: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"/></svg>`,
    moon: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14.4A8 8 0 0 1 9.6 3.5 8.5 8.5 0 1 0 20.5 14.4Z"/></svg>`,
}

function initialTheme(): Theme {
    try {
        const stored = localStorage.getItem('veil-theme')
        if (stored === 'light' || stored === 'dark') return stored
    } catch {
        // Privacy-focused browsers may disable storage; the system preference still works.
    }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

const state = {
    guided: null as GuidedDemo | null,
    guidedRequested: true,
    restoredSingle: false,
    guidedMessage: '',
    guidedPolling: false,
    guidedViews: {
        sender: { fundingChecked: false, activities: [] as Activity[] },
        recipient: { fundingChecked: false, activities: [] as Activity[] },
    },
    quote: null as UsdQuote | null,
    priceLoading: false,
    action: 'shield' as Action,
    theme: initialTheme(),
    privateBalance: 1_000,
    lockedBalance: 0,
    publicBalance: 25_400,
    currentHeight: 910_000,
    connected: false,
    liveSession: null as LiveVeilSession | null,
    liveAddress: '',
    receivingAddress: '',
    receivingWallet: null as LiveWallet | null,
    backupDirty: false,
    fundingChecked: false,
    liveDialogOpen: false,
    liveUnlocking: false,
    liveConfirm: false,
    liveError: '',
    pendingLivePlan: null as PreparedLiveAction | null,
    liveBroadcastIndex: -1,
    demoRunning: false,
    busy: false,
    proofProgress: 0 as number | null,
    proofProgressLabel: '',
    recipient: '',
    amount: '',
    unlockHeight: '',
    activities: [
        {
            kind: 'shield' as const,
            title: 'Added privately',
            detail: 'Groth16 verified locally · replay seed',
            amount: 1_000,
            time: 'Just now',
            proof: '20e4…81b9',
        },
    ] as Activity[],
}

document.documentElement.dataset.theme = state.theme

const copy = {
    shield: {
        eyebrow: 'From your BSV wallet',
        title: 'Add money privately',
        description: 'Your deposit amount is public. What happens after it enters Veil is private.',
        recipient: false,
        cta: 'Add privately',
    },
    send: {
        eyebrow: 'From your private balance',
        title: 'Send privately',
        description: 'The recipient and amount stay hidden. Only a proof appears on-chain.',
        recipient: true,
        recipientLabel: 'Recipient’s Veil address',
        recipientPlaceholder: 'veilt2… (complete recipient address)',
        cta: 'Send privately',
    },
    lock: {
        eyebrow: 'Protected by the BSV blockchain',
        title: 'Lock until a block',
        description: 'These coins cannot move before the block height you choose—even with your keys.',
        recipient: false,
        cta: 'Lock coins',
    },
    withdraw: {
        eyebrow: 'To a regular BSV wallet',
        title: 'Withdraw',
        description: 'Move funds out of Veil. The withdrawal amount and destination become public.',
        recipient: true,
        recipientLabel: 'BSV address',
        recipientPlaceholder: '1…',
        cta: 'Withdraw',
    },
} as const

function formatSats(value: number): string {
    return new Intl.NumberFormat('en-GB').format(value)
}

function shortProof(signal: string): string {
    return `${signal.slice(0, 6)}…${signal.slice(-6)}`
}

function render(): void {
    const oldModal = document.querySelector<HTMLElement>('.live-modal')
    if (oldModal && !modalExpanded) modalSize = { width: oldModal.style.width, height: oldModal.style.height }
    const active = copy[state.action]
    const max = state.action === 'shield' ? state.publicBalance : state.privateBalance
    const live = state.liveSession !== null
    const needsRecipient = active.recipient
    const actionDescription = live && state.action === 'send'
        ? state.guided ? 'Guided demo: the other wallet is prefilled. You can replace it. Payment to the demo wallet is imported automatically after ARC reports MINED; external recipients still need the encrypted payment file.' : 'Send to another wallet’s Veil v2 address. After mining, deliver the encrypted payment file. Only that recipient can spend the note. No automatic delivery or discovery.'
        : active.description
    document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
      <div class="shell">
        <header class="topbar">
          <a class="brand" href="#" aria-label="Veil home">
            <span class="brand-mark">${icons.shield}</span>
            <span>Veil</span>
          </a>
          <div class="header-actions">
            <button class="network" data-run-demo ${state.demoRunning || state.busy ? 'disabled' : ''}>
              <i></i> ${state.demoRunning ? 'Running demo…' : 'Run local proof demo'}
            </button>
            <button class="theme-toggle" id="theme-toggle" aria-label="Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode" title="Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode">
              ${state.theme === 'dark' ? icons.sun : icons.moon}
            </button>
            <button class="wallet-button" id="connect-wallet">
              ${live
                  ? '<span class="wallet-dot"></span> Live testnet unlocked'
                  : state.receivingWallet ? (state.fundingChecked ? 'Funded wallet unlocked' : 'Receiving wallet ready') : state.connected
                    ? '<span class="wallet-dot"></span> Wallet connected'
                    : 'Unlock live testnet'}
            </button>
          </div>
        </header>

        <main>
          <aside class="timing-panel" aria-label="Operation stopwatches">
            <div data-timing-strip class="timing-strip">${timingStrip()}</div>
            <div class="timing-controls"><button id="restart-overall">Start/restart overall</button><button id="stop-overall">Stop overall</button><button id="save-timings">Export timings</button></div>
            <details><summary>All operation and stage timings</summary><p>Local to this tab; wall-clock elapsed time includes review and network waits. Download timers end when offered, not when saved to disk. A blocked browser may delay display updates. Export before reloading.</p><ol id="timing-records"></ol></details>
          </aside>
          <aside class="version-notice" aria-label="Version information">
            <strong>v0.3.0 · Two-wallet testnet candidate</strong>
            <span>New protocol; do not import old pool notes. No contract is deployed merely by opening this page.</span>
            <a href="https://veilbsv006pv195t.github.io/veil-bsv-independent/" target="_blank" rel="noopener noreferrer">Open previous version for comparison ↗</a>
          </aside>
          ${state.guided ? `<aside class="version-notice guided-controls" aria-label="Guided two-wallet demo">
            <strong>Guided demo · ${state.guided.active === 'sender' ? 'Sender' : 'Demo recipient'} wallet</strong>
            <span>Two separate keys in this browser for demonstration. Back up both together. Not a separately controlled third-party wallet.</span>
            <div>${(['sender', 'recipient'] as Role[]).map(role => `<button class="secondary-button" data-wallet-role="${role}" aria-pressed="${state.guided!.active === role}" ${state.busy || state.liveUnlocking || state.pendingLivePlan || state.guidedPolling ? 'disabled' : ''}>${role === 'sender' ? 'Sender' : 'Demo recipient'}</button>`).join('')}</div>
            <span role="status">${escapeHtml(state.guidedMessage || (state.guided.pending ? 'Waiting for mining. Automatic handoff checks every 30 seconds while this page is open.' : 'Ready. Save a combined backup before preparing an action.'))}</span>
            ${state.guided.pending ? `<a href="${explorerUrl(state.guided.pending.txid)}" target="_blank" rel="noopener noreferrer">View pending finalizer ↗</a><button class="secondary-button" id="check-guided-handoff" ${state.guidedPolling ? 'disabled' : ''}>Check mining and handoff now</button>` : ''}
            ${state.guided.active === 'recipient' ? '<span>The recipient starts with no fee funding. Receiving is free; sending or withdrawing requires a separate mined fee-funding output. No funds are moved automatically.</span>' : ''}
          </aside>` : ''}
          <section class="hero-copy">
            <div class="privacy-pill">${icons.lock} Zero-knowledge privacy</div>
            <h1>Veil your BSV</h1>
            <p>Deposit, pay, and withdraw without revealing your private activity.</p>
          </section>

          <section class="wallet-grid">
            <aside class="balance-card">
              <div class="balance-topline">
                <span>Private balance</span>
                <span class="status-chip">${icons.check} Protected</span>
              </div>
              <div class="balance"><strong>${formatSats(state.privateBalance)}</strong><span>sats</span></div>
              <div class="balance-fiat" id="usd-estimate">${usdMarkup()}</div>

              <div class="locked-summary ${state.lockedBalance > 0 ? 'has-lock' : ''}">
                ${icons.lock}
                <span><small>Height-locked</small><strong>${formatSats(state.lockedBalance)} sats</strong></span>
              </div>

              <div class="address-card">
                <div><span>Your private address</span><strong>${state.receivingAddress ? escapeHtml(shortProof(state.receivingAddress)) : 'Local demo only'}</strong></div>
                <button id="copy-address" aria-label="Copy private address">${icons.copy}</button>
              </div>

              <div class="balance-footer">
                <div><span>${live || state.receivingWallet ? 'Tracked fee-funding output' : 'Available in wallet'}</span><strong>${formatSats(state.publicBalance)} sats</strong></div>
                ${state.connected
                    ? '<span class="demo-label">WALLET</span>'
                    : `<button class="demo-label" data-run-demo ${state.demoRunning || state.busy ? 'disabled' : ''}>${state.demoRunning ? 'RUNNING' : 'DEMO'}</button>`}
              </div>
            </aside>

            <section class="action-card">
              <nav class="action-tabs" aria-label="Private money actions">
                ${tab('shield', 'Add', icons.shield)}
                ${tab('send', 'Send', icons.send)}
                ${tab('lock', 'Lock', icons.lock)}
                ${tab('withdraw', 'Withdraw', icons.withdraw)}
              </nav>

              <div class="form-copy">
                <span>${active.eyebrow}</span>
                <h2>${active.title}</h2>
                <p>${actionDescription}</p>
              </div>

              ${needsRecipient ? `
                <label class="field-label" for="recipient">${active.recipientLabel}</label>
                <div class="text-field">
                  <input id="recipient" autocomplete="off" spellcheck="false" placeholder="${active.recipientPlaceholder}" value="${escapeHtml(state.recipient)}" />
                </div>
                ${state.guided && state.action === 'send' ? `<p class="recipient-hint">Editable destination. <button id="use-demo-recipient" type="button">Use ${state.guided.active === 'sender' ? 'demo recipient' : 'sender'} address</button></p>` : ''}
              ` : ''}

              <label class="field-label" for="amount">Amount</label>
              <div class="amount-field">
                <input id="amount" inputmode="numeric" placeholder="0" value="${escapeHtml(state.amount)}" />
                <div class="amount-unit"><span>sats</span><button id="max-amount">Max</button></div>
              </div>
              <div class="available">Available: ${formatSats(max)} sats</div>

              ${state.action === 'lock' ? `
                <label class="field-label" for="unlock-height">Unlock block</label>
                <div class="height-field">
                  <input id="unlock-height" inputmode="numeric" placeholder="e.g. ${formatSats(state.currentHeight + 1_000)}" value="${escapeHtml(state.unlockHeight)}" />
                  <span>Current: ${formatSats(state.currentHeight)}</span>
                </div>
                <div class="height-shortcuts">
                  <button data-height="100">+100 blocks</button>
                  <button data-height="1000">+1,000 blocks</button>
                </div>
              ` : ''}

              <button class="primary-button" id="submit-action" ${state.busy || state.guidedPolling || state.guided?.pending || (state.guided && !live) ? 'disabled' : ''}>
                ${state.busy
                    ? '<span class="spinner"></span> Preparing audited transaction chain…'
                    : live
                      ? `Prepare ${active.cta.toLowerCase()} <span>→</span>`
                      : `${active.cta} <span>→</span>`}
              </button>
              ${state.busy ? `
                <div class="proof-progress${state.proofProgress === null ? ' indeterminate' : ''}" role="progressbar" aria-label="Transaction preparation" aria-valuemin="1" aria-valuemax="100" ${state.proofProgress === null ? '' : `aria-valuenow="${state.proofProgress}"`} aria-valuetext="${escapeHtml(state.proofProgressLabel)}">
                  <div class="proof-progress-track"><span style="width: ${state.proofProgress === null ? '35%' : `${state.proofProgress}%`}"></span></div>
                  <div class="proof-progress-copy"><span id="proof-progress-label">${escapeHtml(state.proofProgressLabel)}</span><strong id="proof-progress-percent">${state.proofProgress === null ? '' : `${state.proofProgress}%`}</strong></div>
                </div>
              ` : ''}
              ${live && state.liveError && !state.pendingLivePlan && !state.liveDialogOpen ? `<p class="live-error" role="alert">${escapeHtml(state.liveError)} No transaction was broadcast by this preparation attempt.</p>` : ''}
              <div class="trust-line">${icons.lock}<span>${live
                  ? 'Key stays in this tab. Nothing broadcasts before exact TXID review.'
                  : 'Keys stay in your wallet. Proofs reveal no private details.'}</span></div>
            </section>
          </section>

          <section class="activity-section">
            <div class="section-heading"><div><span>RECENT ACTIVITY</span><h2>Private by default</h2></div><button id="proof-info">How it works</button></div>
            <div class="activity-list">
              ${state.activities.map(activityRow).join('')}
            </div>
          </section>
        </main>

        <footer><span>${state.receivingWallet ? 'INDEPENDENT TESTNET WALLET · Import a payment or bind funding to prepare a new pool.' : live
            ? 'LIVE TESTNET MODE · Every signed transaction requires review before broadcast.'
            : 'Real proofs, local demo state. No transaction is broadcast.'}</span><span>Source included with release</span></footer>
        <div class="toast" id="toast" role="status"></div>
      </div>
      ${state.liveDialogOpen || state.pendingLivePlan ? liveDialog() : ''}
    `
    wireEvents()
    const modal = document.querySelector<HTMLElement>('.live-modal')
    if (modal) {
        modal.classList.toggle('expanded', modalExpanded)
        if (!modalExpanded) { modal.style.width = modalSize.width; modal.style.height = modalSize.height }
    }
    updateTimers()
}

function liveDialog(): string {
    const plan = state.pendingLivePlan
    if (plan) {
        const submissionStarted = state.liveBroadcastIndex >= 0
        return `<div class="modal-backdrop" id="live-modal-backdrop">
          <section class="live-modal review-modal" role="dialog" aria-modal="true" aria-labelledby="live-title">
            ${modalToolbar()}
            <button class="modal-close" id="close-live-modal" aria-label="Close" ${state.busy || submissionStarted ? 'disabled' : ''}>×</button>
            <span class="live-kicker">${submissionStarted ? state.busy ? 'SUBMITTING · MINING NOT YET CONFIRMED' : 'SUBMISSION INTERRUPTED · KEEP THIS CHAIN OPEN' : 'SIGNED LOCALLY · NOT BROADCAST'}</span>
            <h2 id="live-title">Review the exact testnet chain</h2>
            <div class="review-summary">
              <div><span>Action</span><strong>${escapeHtml(plan.action)}</strong></div>
              <div><span>Amount</span><strong>${formatSats(plan.amount)} sats</strong></div>
              <div><span>Total miner fees</span><strong>${formatSats(plan.totalFees)} sats</strong></div>
              <div><span>Transactions</span><strong>${plan.transactions.length}</strong></div>
              ${plan.recipient ? `<div class="wide"><span>${plan.action === 'send' ? 'Private recipient · encrypted file handoff required' : 'Public recipient'}</span><strong>${escapeHtml(plan.recipient)}</strong></div>` : ''}
              ${plan.unlockHeight ? `<div class="wide"><span>Unlock height</span><strong>${formatSats(plan.unlockHeight)}</strong></div>` : ''}
            </div>
            <ol class="tx-review-list">
              ${plan.transactions.map((tx, index) => `<li class="${state.liveBroadcastIndex === index ? 'active' : ''}">
                <div><span>${index + 1}. ${escapeHtml(tx.name)}</span><small>${formatSats(tx.bytes)} B · ${formatSats(tx.feeSatoshis)} sat fee</small></div>
                <a href="${explorerUrl(tx.txid)}" target="_blank" rel="noopener noreferrer" aria-label="View transaction ${tx.txid} on Whatsonchain testnet in a new tab">${tx.txid.slice(0, 12)}…${tx.txid.slice(-10)}</a>
              </li>`).join('')}
            </ol>
            <div class="review-footer">
            <p class="review-warning">${submissionStarted ? 'Submission has started. Some transactions may already be accepted. Keep this page open; retry only this exact chain if needed.' : escapeHtml(plan.warning)}</p>
            <label class="live-confirm"><input id="live-confirm" type="checkbox" ${state.liveConfirm ? 'checked' : ''} ${state.busy ? 'disabled' : ''}/><span>I checked the action, amount, recipient, fees, and TXIDs. Broadcast this exact parent-first chain on BSV testnet.</span></label>
            <button class="primary-button danger-button" id="broadcast-live-plan" ${!state.liveConfirm || state.busy ? 'disabled' : ''}>
              ${state.busy ? '<span class="spinner"></span> Broadcasting exact chain…' : 'Broadcast exact testnet chain →'}
            </button>
            </div>
            ${state.liveError ? `<p class="live-error" role="alert">${escapeHtml(state.liveError)}${submissionStarted ? ' Keep this page open and retry the same chain; accepted ancestors will not be resent.' : ''}</p>` : ''}
          </section>
        </div>`
    }
    return `<div class="modal-backdrop" id="live-modal-backdrop">
      <section class="live-modal" role="dialog" aria-modal="true" aria-labelledby="live-title">
        ${modalToolbar()}
        <button class="modal-close" id="close-live-modal" aria-label="Close" ${state.busy || state.liveUnlocking ? 'disabled' : ''}>×</button>
        <span class="live-kicker">DISPOSABLE WALLET · TESTNET ONLY</span>
        <h2 id="live-title">${state.liveSession ? 'Live wallet · receive and back up' : state.receivingWallet ? 'Independent wallet ready' : 'Restore or set up a testnet wallet'}</h2>
        ${state.liveSession || state.receivingWallet ? `
          <p>Private keys and notes stay in this tab and your encrypted backup. Keep both the backup file and its passphrase safe. Never reload during preparation or a partially submitted chain.</p>
          <div class="unlocked-address"><span>Testnet address</span><strong>${escapeHtml(state.liveAddress)}</strong></div>
          ${!state.liveSession && state.receivingWallet && state.fundingChecked ? `
            <div class="unlocked-address"><span>Mined fee-funding output · ${formatSats(state.receivingWallet.funding.satoshis)} sats</span><strong class="wrap-address">${state.receivingWallet.funding.txid}:${state.receivingWallet.funding.vout}</strong></div>
            <p>Funding transaction and wallet ownership checked. Mining does not prove this output is still unspent. Do not spend from this wallet in another tab or browser.</p>
          ` : ''}
          <div class="unlocked-address"><span>This wallet’s Veil receiving address · give this to the sender</span><strong class="wrap-address">${escapeHtml(state.receivingAddress)}</strong></div>
          <button class="secondary-button" id="copy-receiving-address">Copy this wallet’s receiving address</button>
          <p>To receive here, give this address to another wallet. To send from here, enter the OTHER wallet’s receiving address—not this one. Never share your backup.</p>
          <p>${state.guided ? 'Save both wallets together. Close this dialog to allow mining checks and automatic synchronization. A mined snapshot is not an unspent-output guarantee; never transact from another tab using these wallets.' : state.liveSession ? 'Import each other wallet’s pool update before the next action. Updates must be direct successors. A mined snapshot is not an unspent-output guarantee; do not transact concurrently.' : state.fundingChecked ? 'Funded wallet ready. Save its encrypted backup, then prepare a fresh pool. Preparation does not broadcast; the exact transactions require a separate review.' : 'Independent receiver ready. Save its encrypted backup before sharing the address. Import a mined payment file, then bind your own testnet funding output for miner fees.'}</p>
          <p>New .veil backups are compressed before encryption and stored as compact binary files. Older .json backups can still be restored here; older website builds cannot read the new format. Keep your previous backup until recovery is verified.</p>
          <label class="field-label" for="backup-password">Unique backup passphrase (24+ characters)</label>
          <div class="text-field"><input id="backup-password" type="password" autocomplete="new-password" /></div>
          <button class="secondary-button" id="save-wallet-backup">Download encrypted ${state.guided ? 'two-wallet' : 'wallet'} backup${state.backupDirty ? ' · required' : ''}</button>
          ${state.guided ? '<p>This one encrypted file includes BOTH keys, private notes and any pending handoff. Keep the newest download; the website password alone does not recover these notes. Restore this file after a reload—do not unlock the original funding envelope again.</p>' : `
            ${state.restoredSingle ? '<p role="status">Single-wallet backup restored. No recipient keys were created or replaced. Keep the original backup. Do not transact from another tab using this wallet.</p>' : ''}
            ${hasGuidedMarker() && state.restoredSingle ? '<p>A previous guided-setup marker exists in this browser. It does not identify a wallet or prove a recipient was saved. Restore a combined backup if you have one; creating a new recipient will not recover an earlier recipient.</p><label class="live-confirm"><input id="confirm-new-recipient" type="checkbox" /> I have no existing recipient to recover for this demo and want to create a NEW recipient. I will keep my original backup and save the combined backup.</label>' : ''}
            <button class="secondary-button" id="enable-guided-demo">Set up guided demo recipient</button>`}
          ${state.guided ? '' : '<label class="field-label" for="payment-file">Import encrypted payment file</label><input id="payment-file" type="file" accept=".json,application/json" />'}
          ${state.liveSession ? `
            <button class="secondary-button" id="save-payment-file" ${state.liveSession.paymentFile() ? '' : 'disabled'}>Download last encrypted payment</button>
            <button class="secondary-button" id="save-pool-state">Download public pool update</button>
            ${state.guided ? '' : '<label class="field-label" for="pool-file">Import next public pool update</label><input id="pool-file" type="file" accept=".json,application/json" />'}
          ` : state.guided?.active === 'recipient' ? '<p>Waiting for the sender’s payment. The guided recipient joins that pool automatically after mining.</p>' : `<button class="primary-button" id="start-new-pool" ${state.fundingChecked ? '' : 'disabled'}>Prepare a fresh pool with this funded wallet</button>`}
            <details><summary>Bind a mined funding output for fees</summary>
              <p>Use a still-unspent P2PKH output to this wallet’s testnet address. This replaces the tracked fee output; it does not consolidate other coins.</p>
              <label for="funding-hex">Raw funding transaction (hex)</label><textarea id="funding-hex" spellcheck="false"></textarea>
              <label for="funding-index">Output index</label><input id="funding-index" type="number" min="0" value="0" />
              <button class="secondary-button" id="bind-funding">Check mined funding output</button>
            </details>
          ${state.liveSession ? '<button class="primary-button" id="use-live-wallet">Choose an action →</button>' : ''}
          <button class="secondary-button" id="lock-live-wallet">Lock wallet and return to Restore</button>
          <p>Save the latest encrypted backup first. Returning to Restore clears the current wallet from this tab; it does not move any funds.</p>
        ` : `
          <h3>Returning user — restore your backup</h3>
          <p>Already used Veil? Restore your latest encrypted wallet backup here. Enter its backup passphrase first, then choose the file to restore. Do not select an encrypted payment file.</p>
          ${hasGuidedMarker() ? '<p role="status">A previous setup marker exists. First-time unlock is disabled. Restore your latest backup: single-wallet and combined two-wallet backups are both supported. A single-wallet restore does not create or replace a recipient.</p>' : ''}
          <label class="field-label" for="restore-password">Backup passphrase</label>
          <div class="text-field"><input id="restore-password" type="password" autocomplete="current-password" /></div>
          <label class="live-confirm"><input id="guided-demo-choice" type="checkbox" ${state.guidedRequested ? 'checked' : ''} /> Guided demo: create a separate recipient on first setup</label>
          <label class="field-label" for="restore-backup">Restore encrypted wallet backup</label>
          <input id="restore-backup" type="file" accept=".veil,.json,application/json,application/octet-stream" />
          <h3 class="setup-divider">First-time setup only</h3>
          <p>The separately delivered live-wallet password opens the original funding wallet, not your saved private notes. If you have used it already, restore above instead. Wallet data is decrypted locally; passwords are never sent to GitHub, Veil, ARC, or WhatsOnChain.</p>
          <label class="field-label" for="live-password">First-time live-wallet password</label>
          <div class="text-field"><input id="live-password" type="password" autocomplete="current-password" spellcheck="false" ${walletUnlockAllowed() ? '' : 'disabled'} /></div>
          <button class="primary-button" id="unlock-live-wallet" ${walletUnlockAllowed() ? '' : 'disabled'}>
            ${state.liveUnlocking ? '<span class="spinner"></span> Unlocking and checking testnet…' : state.busy ? 'Wallet operation in progress…' : hasGuidedMarker() ? 'Restore required — use backup above' : 'First-time unlock →'}
          </button>
          <button class="secondary-button" id="create-receiving-wallet">Create independent receiving wallet</button>
        `}
        ${state.liveError ? `<p class="live-error" role="alert">${escapeHtml(state.liveError)}</p>` : ''}
        <p class="live-safety">Anyone with the password controls this disposable testnet wallet. Never use this mode with mainnet funds.</p>
      </section>
    </div>`
}

function usdMarkup(): string {
    const q = state.quote
    return `${q ? mainnetUsd(state.privateBalance, q) : 'USD estimate unavailable'} <span>(~mainnet currency)</span><br><small>Testnet coins have no monetary value.</small><br>
      ${q && isFresh(q) ? `<small>CoinGecko: $${q.usdPerBsv} / BSV · ${escapeHtml(new Date(q.updatedAt).toISOString())}</small>` : ''}
      <button id="refresh-usd" type="button" ${state.priceLoading ? 'disabled' : ''}>${state.priceLoading ? 'Checking USD price…' : 'Refresh USD price'}</button>`
}

async function refreshUsd(): Promise<void> {
    if (state.priceLoading) return
    state.priceLoading = true
    // Do not re-render password fields or a transaction review on quote updates.
    try { state.quote = await fetchUsdQuote() } catch { state.quote = null }
    finally { state.priceLoading = false; updateUsdDisplay() }
}
function updateUsdDisplay(): void {
    const node = document.querySelector('#usd-estimate')
    if (node) { node.innerHTML = usdMarkup(); node.querySelector('#refresh-usd')?.addEventListener('click', () => void refreshUsd()) }
}

function rememberGuided(): void {
    try { localStorage.setItem(GUIDED_MARKER, 'restore-backup-required') } catch { /* No secrets or addresses in storage. */ }
}
function walletUnlockAllowed(): boolean {
    return canUnlockOriginalWallet({
        busy: state.busy, unlocking: state.liveUnlocking,
        hasWallet: Boolean(state.liveSession || state.receivingWallet || state.guided),
        pendingPlan: Boolean(state.pendingLivePlan), checkingHandoff: state.guidedPolling,
        restoreRequired: hasGuidedMarker(),
    })
}
function hasGuidedMarker(): boolean {
    try { return localStorage.getItem(GUIDED_MARKER) !== null } catch { return false }
}
async function enableGuided(confirmedNewRecipient = false): Promise<void> {
    if (state.guided) return
    if (!canCreateGuidedRecipient(hasGuidedMarker(), state.restoredSingle, confirmedNewRecipient)) throw new Error('Restore the combined backup if a recipient already exists. Otherwise restore your single-wallet backup and explicitly confirm creating a new demo recipient.')
    const wallet = state.receivingWallet ?? (state.liveSession?.backupPayload() as { wallet: LiveWallet } | undefined)?.wallet
    if (!wallet) throw new Error('Unlock or restore the sender first')
    const pair = await GuidedDemo.create(wallet, state.liveSession)
    state.guided = pair
    state.guidedViews = {
        sender: { fundingChecked: state.fundingChecked, activities: state.activities },
        recipient: { fundingChecked: false, activities: [] },
    }
    rememberGuided()
    state.backupDirty = true
    state.guidedMessage = 'Separate recipient created. Download the combined two-wallet backup before proceeding.'
    if (state.action === 'send') state.recipient = pair.defaultRecipient()
}
function syncGuidedSlot(): void {
    const pair = state.guided
    if (!pair) return
    const slot = pair.slots[pair.active]
    slot.session = state.liveSession
    if (state.receivingWallet) slot.wallet = state.receivingWallet
    state.guidedViews[pair.active] = { fundingChecked: state.fundingChecked, activities: state.activities }
}
function selectGuidedRole(role: Role): void {
    const pair = state.guided
    if (!pair || state.busy || state.pendingLivePlan || state.liveUnlocking || state.guidedPolling) return
    syncGuidedSlot()
    pair.active = role
    displayGuidedRole()
    state.action = 'send'
    state.amount = ''
    state.recipient = pair.defaultRecipient()
    state.liveError = ''
    state.liveDialogOpen = false
    render()
}
function displayGuidedRole(): void {
    const pair = state.guided!
    const slot = pair.slots[pair.active]
    state.liveSession = slot.session
    state.receivingWallet = slot.session ? null : slot.wallet
    state.liveAddress = slot.wallet.address
    state.receivingAddress = slot.address
    state.privateBalance = slot.session?.privateBalance() ?? 0
    state.lockedBalance = slot.session?.lockedBalance(state.currentHeight) ?? 0
    state.publicBalance = slot.session?.fundingBalance() ?? slot.wallet.funding.satoshis
    state.fundingChecked = state.guidedViews[pair.active].fundingChecked
    state.activities = state.guidedViews[pair.active].activities
    state.connected = true
}
async function checkGuidedHandoff(): Promise<void> {
    const pair = state.guided
    if (!pair?.pending || state.guidedPolling || state.busy || state.liveUnlocking || state.pendingLivePlan || state.liveDialogOpen) return
    state.guidedPolling = true
    syncGuidedSlot()
    const pending = pair.pending
    const peerRole = otherRole(pending.from)
    const previousBalance = pair.slots[peerRole].session?.privateBalance() ?? 0
    try {
        const changed = await pair.poll(updateProofProgress)
        if (state.guided !== pair) return
        if (changed) {
            const timing = miningTimings.get(pending.txid)
            if (timing !== undefined) { timers.finish(timing, 'ARC reports mined; wallets synchronized'); miningTimings.delete(pending.txid) }
            state.backupDirty = true
            if (pending.payment) state.guidedViews[peerRole].activities.unshift({
                kind: 'send', received: true, title: 'Received privately on testnet',
                detail: `ARC reports MINED · ${pending.txid.slice(0, 12)}…`,
                amount: (pair.slots[peerRole].session?.privateBalance() ?? 0) - previousBalance,
                time: 'Just now', proof: shortProof(pending.txid),
            })
            displayGuidedRole()
            state.guidedMessage = 'ARC reports MINED. Both wallets synchronized; any demo payment has been imported. Save an updated two-wallet backup.'
        } else state.guidedMessage = 'Waiting for mining. No recipient funds credited yet; no transactions are resent.'
    } catch (error) { state.guidedMessage = error instanceof Error ? error.message : 'Mining check unavailable; handoff retained for retry.' }
    finally {
        state.guidedPolling = false
        // Avoid clearing a passphrase or file input while the user backs up.
        if (!state.liveDialogOpen && !state.pendingLivePlan) render()
    }
}

function tab(action: Action, label: string, icon: string): string {
    return `<button class="action-tab ${state.action === action ? 'active' : ''}" data-action="${action}">${icon}<span>${label}</span></button>`
}

function activityRow(activity: Activity): string {
    const sign = activity.received || activity.kind === 'shield' ? '+' : activity.kind === 'lock' ? '' : '−'
    return `<button class="activity-row" data-proof="${activity.proof}">
      <span class="activity-icon ${activity.kind}">${icons[activity.kind]}</span>
      <span class="activity-main"><strong>${activity.title}</strong><small>${activity.detail}</small></span>
      <span class="activity-amount"><strong>${sign}${formatSats(activity.amount)} sats</strong><small>${activity.time}</small></span>
      <span class="activity-arrow">›</span>
    </button>`
}

function escapeHtml(value: string): string {
    return value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]!)
}

function showToast(message: string): void {
    const toast = document.querySelector<HTMLDivElement>('#toast')!
    toast.textContent = message
    toast.classList.add('show')
    window.setTimeout(() => toast.classList.remove('show'), 2800)
}

function updateProofProgress(percent: number | null, label: string): void {
    timers.phase(foregroundTiming, label)
    updateTimers()
    state.proofProgress = percent === null ? null : Math.max(1, Math.min(100, Math.round(percent)))
    state.proofProgressLabel = label
    const progress = document.querySelector<HTMLDivElement>('.proof-progress')
    const track = document.querySelector<HTMLSpanElement>('.proof-progress-track span')
    const labelElement = document.querySelector<HTMLSpanElement>('#proof-progress-label')
    const percentElement = document.querySelector<HTMLElement>('#proof-progress-percent')
    if (progress) {
        progress.classList.toggle('indeterminate', state.proofProgress === null)
        progress.setAttribute('aria-valuetext', label)
        if (state.proofProgress === null) progress.removeAttribute('aria-valuenow')
        else progress.setAttribute('aria-valuenow', String(state.proofProgress))
    }
    if (track) track.style.width = state.proofProgress === null ? '35%' : `${state.proofProgress}%`
    if (labelElement) labelElement.textContent = label
    if (percentElement) percentElement.textContent = state.proofProgress === null ? '' : `${state.proofProgress}%`
}

async function connectWallet(): Promise<void> {
    if (state.liveSession || state.receivingWallet) {
        state.liveDialogOpen = true
        state.liveError = ''
        render()
        return
    }
    if (window.bsv?.getStatus) {
        try {
            const status = await window.bsv.getStatus()
            if (!status.hasWallet) throw new Error('No wallet is enrolled')
            if (status.locked) throw new Error('Unlock your BSV wallet first')
            const balance = await window.bsv.getBalance?.()
            state.publicBalance = balance?.confirmed ?? state.publicBalance
            state.connected = true
            render()
            showToast('Wallet connected')
            return
        } catch (error) {
            showToast(error instanceof Error ? error.message : 'Could not connect wallet')
            return
        }
    }
    state.liveDialogOpen = true
    state.liveError = ''
    render()
}

async function unlockBrowserWallet(): Promise<void> {
    if (!walletUnlockAllowed()) return
    const timing = timers.start('First-time wallet unlock', 'Decrypt wallet and check funding')
    foregroundTiming = timing
    const input = document.querySelector<HTMLInputElement>('#live-password')
    let password = input?.value ?? ''
    if (input) input.value = ''
    state.liveUnlocking = true
    state.liveError = ''
    render()
    try {
        if (hasGuidedMarker()) throw new Error('Restore your latest two-wallet backup below. Do not reopen the original funded wallet after creating a guided pair.')
        const { wallet, fundingChecked } = await unlockLiveWallet(password)
        password = ''
        const height = await testnetHeight()
        state.receivingWallet = wallet
        state.liveAddress = wallet.address
        state.receivingAddress = recipientIdentity(wallet.wif, await createHash()).address
        state.fundingChecked = fundingChecked
        state.backupDirty = true
        state.connected = true
        state.publicBalance = wallet.funding.satoshis
        state.privateBalance = 0
        state.lockedBalance = 0
        state.currentHeight = height
        state.activities = []
        if (state.guidedRequested) await enableGuided()
        timers.finish(timing, 'Completed')
    } catch (error) {
        timers.finish(timing, 'Failed')
        password = ''
        state.liveError = error instanceof Error ? error.message : 'Could not unlock the live wallet'
    } finally {
        foregroundTiming = null
        state.liveUnlocking = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
    }
}

function clearLiveWallet(): void {
    if (state.busy || state.liveUnlocking || state.pendingLivePlan || state.guidedPolling) return
    if (state.guided?.pending) { state.liveError = 'Wait for mining and wallet synchronization before returning to Restore.'; state.liveDialogOpen = true; render(); return }
    if (state.backupDirty) { state.liveError = 'Download an up-to-date encrypted wallet backup before clearing this tab.'; state.liveDialogOpen = true; render(); return }
    state.liveSession = null
    state.guided = null
    state.restoredSingle = false
    state.guidedMessage = ''
    state.receivingWallet = null
    state.receivingAddress = ''
    state.fundingChecked = false
    state.liveAddress = ''
    state.connected = false
    state.liveDialogOpen = true
    state.pendingLivePlan = null
    state.liveConfirm = false
    state.liveError = ''
    state.liveBroadcastIndex = -1
    resetDemoState()
    render()
    showToast('Live wallet key cleared from this tab')
}

function downloadJson(value: unknown, name: string): void {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = name
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
}
async function readJsonFile(file: File | undefined): Promise<any> {
    if (!file || file.size >= MAX_BACKUP_FILE_BYTES) throw new Error('Select a JSON file smaller than 64 MB')
    return JSON.parse(await file.text())
}
async function walletTask(task: () => Promise<void>, label = 'Wallet operation'): Promise<void> {
    if (state.busy || state.liveUnlocking || state.pendingLivePlan || state.guidedPolling) return
    state.busy = true
    state.liveError = ''
    render()
    const timing = timers.start(label)
    foregroundTiming = timing
    updateTimers()
    try { await task(); timers.finish(timing, label.includes('export') || label.includes('backup download') ? 'Download offered' : 'Completed') }
    catch (error) { timers.finish(timing, 'Failed'); state.liveError = error instanceof Error ? error.message : 'Wallet operation failed' }
    finally { foregroundTiming = null; syncGuidedSlot(); state.busy = false; state.liveDialogOpen = true; render() }
}
async function adoptSession(session: LiveVeilSession): Promise<void> {
    const height = await testnetHeight()
    state.liveSession = session
    state.receivingWallet = null
    state.receivingAddress = session.receivingAddress()
    state.liveAddress = session.publicAddress()
    state.privateBalance = session.privateBalance()
    state.publicBalance = session.fundingBalance()
    state.connected = true
    state.backupDirty = true
    state.currentHeight = height
    state.lockedBalance = session.lockedBalance(state.currentHeight)
    state.activities = []
}
async function saveBackup(password: string): Promise<void> {
    timers.phase(foregroundTiming, 'Serialize, deduplicate, compress and encrypt')
    syncGuidedSlot()
    const payload = state.guided?.backupPayload() ?? state.liveSession?.backupPayload() ?? {
        protocol: RECIPIENT_PROTOCOL, wallet: state.receivingWallet, pool: null, notes: [],
    }
    const encrypted = await encryptBackup(payload, password)
    timers.phase(foregroundTiming, 'Authenticate and decompress backup for verification')
    // Test authentication before offering the file. The user still needs to
    // retain both the downloaded file and passphrase outside this browser.
    const file = encodeBackupFile(encrypted)
    // Verify the exact binary container offered for download, not only its envelope.
    await decryptBackup(decodeBackupFile(file), password)
    const url = URL.createObjectURL(new Blob([file], { type: 'application/octet-stream' }))
    const link = document.createElement('a')
    link.href = url
    link.download = state.guided ? 'veil-encrypted-two-wallet-backup.veil' : 'veil-encrypted-wallet-backup.veil'
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    state.backupDirty = false
    showToast(`Compact encrypted backup offered: ${(file.length / 1_000_000).toFixed(2)} MB`)
}
async function restoreWallet(envelope: WalletBackup, password: string): Promise<void> {
    timers.phase(foregroundTiming, 'Authenticate, decompress and decode backup')
    const payload = await decryptBackup(envelope, password) as any
    timers.phase(foregroundTiming, 'Validate wallet and check mined pool')
    if (payload?.format === GUIDED_FORMAT) {
        const pair = await GuidedDemo.restore(payload, updateProofProgress)
        state.guided = pair
        state.restoredSingle = false
        state.guidedViews = {
            sender: { fundingChecked: false, activities: [] },
            recipient: { fundingChecked: false, activities: [] },
        }
        rememberGuided()
        displayGuidedRole()
        state.recipient = pair.defaultRecipient()
        state.guidedMessage = pair.pending ? 'Restored both wallets and pending handoff. Checking mining automatically.' : 'Restored both wallets from the encrypted backup; no replacement keys generated.'
        if (pair.pending) miningTimings.set(pair.pending.txid, timers.start('Restored pending handoff', 'Mining/handoff wait since restore; earlier duration unknown'))
        state.backupDirty = false
        return
    }
    if (payload?.protocol !== RECIPIENT_PROTOCOL || !Array.isArray(payload.notes)) throw new Error('Unsupported backup payload')
    if (!payload.pool) {
        if (payload.notes.length) throw new Error('Backup has notes without a pool')
        const wallet = validateReceivingWallet(payload.wallet)
        state.receivingWallet = wallet
        state.liveAddress = wallet.address
        state.receivingAddress = recipientIdentity(wallet.wif, await createHash()).address
        state.publicBalance = wallet.funding.satoshis
        state.privateBalance = 0
        state.lockedBalance = 0
        state.fundingChecked = false
        state.connected = true
        state.activities = []
    } else {
        const { LiveVeilSession } = await import('./live-builder')
        await adoptSession(await LiveVeilSession.restoreBackup(payload, updateProofProgress))
    }
    state.backupDirty = false
    // Restoring must reproduce the saved wallet, never generate replacement keys.
    // The shared marker remains intact and still prevents first-time unlock.
    state.restoredSingle = true
}

window.addEventListener('beforeunload', event => {
    if (state.liveSession || state.receivingWallet || state.pendingLivePlan) {
        event.preventDefault()
        event.returnValue = ''
    }
})

async function prepareLiveAction(amount: number, unlockHeight: number): Promise<boolean> {
    const session = state.liveSession
    if (!session) return false
    actionTiming = timers.start(`${state.action === 'shield' ? 'Add' : state.action} · live testnet`, 'Prepare')
    foregroundTiming = actionTiming
    state.busy = true
    state.liveError = ''
    state.proofProgress = 1
    state.proofProgressLabel = 'Preparing exact testnet transaction chain'
    render()
    try {
        state.guided?.assertReady()
        if (state.guided && state.backupDirty) throw new Error('Download the latest two-wallet backup before preparing another action')
        const plan = await session.prepare(
            state.action,
            amount,
            state.recipient.trim(),
            unlockHeight,
            updateProofProgress
        )
        state.pendingLivePlan = plan
        timers.phase(actionTiming, 'User review — not broadcast')
        foregroundTiming = null
        state.liveConfirm = false
        state.liveDialogOpen = false
        state.currentHeight = plan.startHeight
        state.busy = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
        return true
    } catch (error) {
        timers.finish(actionTiming, 'Preparation failed')
        foregroundTiming = null
        state.busy = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        state.liveError = error instanceof Error ? error.message : 'Could not prepare the live transaction chain'
        render()
        showToast(state.liveError)
        return false
    }
}

async function broadcastLivePlan(): Promise<void> {
    const plan = state.pendingLivePlan
    const session = state.liveSession
    if (!plan || !session || !state.liveConfirm || state.busy) return
    timers.phase(actionTiming, 'Broadcasting exact chain')
    state.busy = true
    state.liveError = ''
    render()
    try {
        for (let index = 0; index < plan.transactions.length; index++) {
            state.liveBroadcastIndex = index
            timers.phase(actionTiming, `Submit ${index + 1}/${plan.transactions.length}: ${plan.transactions[index].name}`)
            render()
            const transaction = plan.transactions[index]
            await broadcastRawTransaction(transaction.rawHex, transaction.txid)
        }
        session.commit(plan)
        syncGuidedSlot()
        if (state.guided) {
            state.guided.accepted(plan)
            state.guidedMessage = 'ARC accepted the chain. Waiting for mining before automatic handoff; keep this page open and save both wallets now.'
        }
        state.privateBalance = plan.newPrivateBalance
        state.lockedBalance = plan.newLockedBalance
        state.publicBalance = session.fundingBalance()
        state.backupDirty = true
        const finalTx = plan.transactions.at(-1)!
        if (actionTiming !== null) {
            timers.phase(actionTiming, state.guided ? 'Waiting for mining and automatic handoff' : 'Waiting for mining')
            miningTimings.set(finalTx.txid, actionTiming)
        }
        state.activities.unshift({
            kind: plan.action,
            title:
                plan.action === 'shield'
                    ? 'Added privately on testnet'
                    : plan.action === 'send'
                      ? 'Transferred privately on testnet'
                      : plan.action === 'lock'
                        ? `Locked until block ${formatSats(plan.unlockHeight ?? 0)}`
                        : 'Withdrawn on testnet',
            detail: `ARC accepted · ${finalTx.txid.slice(0, 12)}…`,
            amount: plan.amount,
            time: 'Just now',
            proof: shortProof(finalTx.txid),
        })
        state.amount = ''
        state.recipient = state.action === 'send' && state.guided ? state.guided.defaultRecipient() : ''
        state.unlockHeight = ''
        state.pendingLivePlan = null
        state.liveConfirm = false
        state.liveBroadcastIndex = -1
        state.busy = false
        render()
        state.liveDialogOpen = true
        render()
        showToast(state.guided ? 'ARC accepted. Save the combined backup, then close this dialog to check mining and synchronize both wallets.' : plan.action === 'send' ? 'ARC accepted. Save your backup and encrypted payment file; recipient imports after mining.' : 'ARC accepted. Save an updated encrypted backup and share the pool update with the other wallet.')
    } catch (error) {
        timers.phase(actionTiming, 'Submission interrupted — waiting for exact-chain retry')
        state.busy = false
        state.liveError = error instanceof Error ? error.message : 'ARC did not accept the transaction chain'
        render()
    }
}

async function submit(): Promise<boolean> {
    if (state.guided?.pending || state.guidedPolling) { showToast('Wait for mining and wallet synchronization'); return false }
    if (state.guided?.active === 'recipient' && !state.liveSession) { showToast('Waiting for a mined payment to the demo recipient'); return false }
    if (state.receivingWallet) { state.liveDialogOpen = true; render(); showToast('Import a payment or prepare a funded pool first'); return false }
    const amount = Number.parseInt(state.amount, 10)
    const available = state.action === 'shield' ? state.publicBalance : state.privateBalance
    if (!Number.isSafeInteger(amount) || amount <= 0) {
        showToast('Enter an amount greater than zero')
        return false
    }
    if (amount > available) {
        showToast(`You only have ${formatSats(available)} sats available`)
        return false
    }
    if ((state.action === 'send' || state.action === 'lock') && amount === available) {
        showToast('Leave at least 1 sat as private change')
        return false
    }
    if (
        copy[state.action].recipient &&
        state.recipient.trim().length < 4
    ) {
        showToast(state.action === 'send' ? 'Enter a Veil address' : 'Enter a BSV address')
        return false
    }
    const unlockHeight = Number.parseInt(state.unlockHeight, 10)
    if (
        state.action === 'lock' &&
        (!Number.isSafeInteger(unlockHeight) ||
            unlockHeight <= state.currentHeight ||
            unlockHeight >= 500_000_000)
    ) {
        showToast(`Choose a block above ${formatSats(state.currentHeight)}`)
        return false
    }

    if (state.liveSession) return prepareLiveAction(amount, unlockHeight)

    const localTiming = timers.start(`${state.action === 'shield' ? 'Add' : state.action} · local proof`, 'Preparing private proof')
    foregroundTiming = localTiming
    state.busy = true
    state.proofProgress = 1
    state.proofProgressLabel = 'Preparing private proof'
    render()
    let proof
    try {
        proof = await proveAction(
            state.action,
            BigInt(amount),
            BigInt(state.privateBalance),
            state.recipient,
            state.action === 'lock' ? BigInt(unlockHeight) : 0n,
            BigInt(state.currentHeight),
            updateProofProgress
        )
    } catch (error) {
        timers.finish(localTiming, 'Failed')
        foregroundTiming = null
        state.busy = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
        showToast(error instanceof Error ? error.message : 'Could not create the private proof')
        return false
    }

    timers.finish(localTiming, 'Proof verified locally — not broadcast')
    foregroundTiming = null
    if (state.action === 'shield') {
        state.publicBalance -= amount
        state.privateBalance += amount
    } else if (state.action === 'lock') {
        state.privateBalance -= amount
        state.lockedBalance += amount
    } else {
        state.privateBalance -= amount
        if (state.action === 'withdraw') state.publicBalance += amount
    }
    state.activities.unshift({
        kind: state.action,
        title:
            state.action === 'shield'
                ? 'Added privately'
                : state.action === 'send'
                  ? 'Sent privately'
                  : state.action === 'lock'
                    ? `Locked until block ${formatSats(unlockHeight)}`
                    : 'Withdrawn',
        detail: `Groth16 verified locally · ${(proof.elapsedMs / 1000).toFixed(1)}s`,
        amount,
        time: 'Just now',
        proof: shortProof(proof.publicSignal),
    })
    await new Promise((resolve) => window.setTimeout(resolve, 500))
    state.amount = ''
    state.recipient = ''
    state.unlockHeight = ''
    state.busy = false
    state.proofProgress = 0
    state.proofProgressLabel = ''
    render()
    showToast('Done — zero-knowledge proof verified')
    return true
}

function resetDemoState(): void {
    state.action = 'shield'
    state.privateBalance = 1_000
    state.lockedBalance = 0
    state.publicBalance = 25_400
    state.busy = false
    state.proofProgress = 0
    state.proofProgressLabel = ''
    state.recipient = ''
    state.amount = ''
    state.unlockHeight = ''
    state.activities = [
        {
            kind: 'shield',
            title: 'Added privately',
            detail: 'Groth16 verified locally · replay seed',
            amount: 1_000,
            time: 'Just now',
            proof: '20e4…81b9',
        },
    ]
}

async function runDemo(): Promise<void> {
    if (state.demoRunning || state.busy) return
    if (state.liveSession || state.receivingWallet) {
        showToast('Lock the live wallet before running the local proof demo')
        return
    }
    resetDemoState()
    state.demoRunning = true
    render()
    showToast('Running the complete private-money demo')

    const steps: Array<{ action: Action; amount: string; recipient?: string; unlockHeight?: string }> = [
        { action: 'shield', amount: '400' },
        { action: 'send', amount: '200', recipient: 'veil1jackdemo' },
        { action: 'lock', amount: '200', unlockHeight: String(state.currentHeight + 100) },
        { action: 'withdraw', amount: '200', recipient: '1JackDemoAddress' },
    ]

    for (const step of steps) {
        state.action = step.action
        state.amount = step.amount
        state.recipient = step.recipient ?? ''
        state.unlockHeight = step.unlockHeight ?? ''
        render()
        document.querySelector('.wallet-grid')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
        await new Promise((resolve) => window.setTimeout(resolve, 900))
        if (!(await submit())) {
            state.demoRunning = false
            render()
            showToast('Demo stopped before completion')
            return
        }
        await new Promise((resolve) => window.setTimeout(resolve, 900))
    }

    state.demoRunning = false
    render()
    document.querySelector('.activity-section')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    await new Promise((resolve) => window.setTimeout(resolve, 700))
    showToast('Demo complete — four real proofs verified locally')
}

function wireEvents(): void {
    document.querySelector('#restart-overall')?.addEventListener('click', () => { timers.resetOverall(); updateTimers() })
    document.querySelector('#stop-overall')?.addEventListener('click', () => { timers.stopOverall(); updateTimers() })
    document.querySelector('#save-timings')?.addEventListener('click', () => {
        const id = timers.start('Timing report export')
        timers.finish(id, 'Download offered')
        downloadJson(timers.snapshot(), 'veil-timings.json'); updateTimers()
    })
    document.querySelector('#expand-modal')?.addEventListener('click', () => {
        const modal = document.querySelector<HTMLElement>('.live-modal')!
        if (!modalExpanded) modalSize = { width: modal.style.width, height: modal.style.height }
        modalExpanded = !modalExpanded
        modal.classList.toggle('expanded', modalExpanded)
        const button = document.querySelector<HTMLButtonElement>('#expand-modal')!
        button.textContent = modalExpanded ? 'Restore size' : 'Expand'
        button.setAttribute('aria-pressed', String(modalExpanded))
        // No render: preserve passwords, file selections, scroll and pending review.
    })
    document.querySelector('#refresh-usd')?.addEventListener('click', () => void refreshUsd())
    document.querySelector<HTMLInputElement>('#guided-demo-choice')?.addEventListener('change', event => {
        state.guidedRequested = (event.target as HTMLInputElement).checked
    })
    document.querySelector('#enable-guided-demo')?.addEventListener('click', () => {
        const confirmed = document.querySelector<HTMLInputElement>('#confirm-new-recipient')?.checked === true
        void walletTask(() => enableGuided(confirmed), 'Create guided recipient')
    })
    document.querySelectorAll<HTMLButtonElement>('[data-wallet-role]').forEach(button => button.addEventListener('click', () => selectGuidedRole(button.dataset.walletRole as Role)))
    document.querySelector('#check-guided-handoff')?.addEventListener('click', () => void checkGuidedHandoff())
    document.querySelector('#use-demo-recipient')?.addEventListener('click', () => {
        if (state.guided && !state.busy && !state.pendingLivePlan) { state.recipient = state.guided.defaultRecipient(); render() }
    })
    document.querySelector('#create-receiving-wallet')?.addEventListener('click', () => void walletTask(async () => {
        const wallet = createReceivingWallet()
        state.receivingWallet = wallet
        state.liveAddress = wallet.address
        state.receivingAddress = recipientIdentity(wallet.wif, await createHash()).address
        state.privateBalance = 0
        state.publicBalance = 0
        state.lockedBalance = 0
        state.activities = []
        state.backupDirty = true
        state.fundingChecked = false
        state.connected = true
    }, 'Create independent receiving wallet'))
    document.querySelector('#copy-receiving-address')?.addEventListener('click', () => {
        if (state.backupDirty && !state.liveSession) { showToast('Save the encrypted receiver backup before sharing this address'); return }
        void navigator.clipboard?.writeText(state.receivingAddress)
    })
    document.querySelector('#save-wallet-backup')?.addEventListener('click', () => {
        const input = document.querySelector<HTMLInputElement>('#backup-password')!
        const password = input.value
        input.value = ''
        void walletTask(() => saveBackup(password), state.guided ? 'Two-wallet backup download' : 'Single-wallet backup download')
    })
    document.querySelector<HTMLInputElement>('#restore-backup')?.addEventListener('change', event => {
        const file = (event.target as HTMLInputElement).files?.[0]
        const input = document.querySelector<HTMLInputElement>('#restore-password')!
        const password = input.value
        input.value = ''
        void walletTask(async () => {
            if (!file || file.size >= MAX_BACKUP_FILE_BYTES) throw new Error('Choose a .veil or legacy .json backup smaller than 64 MB')
            await restoreWallet(decodeBackupFile(new Uint8Array(await file.arrayBuffer())), password)
        }, 'Restore encrypted wallet backup')
    })
    document.querySelector<HTMLInputElement>('#payment-file')?.addEventListener('change', event => {
        const file = (event.target as HTMLInputElement).files?.[0]
        void walletTask(async () => {
            if (state.guided) throw new Error('Guided mode imports payments automatically after mining. Use a separate ordinary wallet for manual imports.')
            const payment = await readJsonFile(file) as EncryptedPayment
            if (state.liveSession) {
                await state.liveSession.importPayment(payment)
                await adoptSession(state.liveSession)
            } else if (state.receivingWallet) {
                const { LiveVeilSession } = await import('./live-builder')
                await adoptSession(await LiveVeilSession.receive(state.receivingWallet, payment, updateProofProgress))
            }
        }, 'Import encrypted payment')
    })
    document.querySelector('#save-payment-file')?.addEventListener('click', () => {
        const payment = state.liveSession?.paymentFile()
        if (payment) void walletTask(async () => { downloadJson(payment, 'veil-encrypted-payment.json') }, 'Encrypted payment export')
    })
    document.querySelector('#save-pool-state')?.addEventListener('click', () => void walletTask(async () => {
        downloadJson(state.liveSession!.poolSnapshot(), 'veil-public-pool-update.json')
    }, 'Public pool update export'))
    document.querySelector<HTMLInputElement>('#pool-file')?.addEventListener('change', event => {
        const file = (event.target as HTMLInputElement).files?.[0]
        void walletTask(async () => {
            if (state.guided) throw new Error('Guided mode synchronizes pool state automatically after mining')
            await state.liveSession!.importPoolSnapshot(await readJsonFile(file))
            await adoptSession(state.liveSession!)
        }, 'Import public pool update')
    })
    document.querySelector('#bind-funding')?.addEventListener('click', () => {
        const raw = document.querySelector<HTMLTextAreaElement>('#funding-hex')!.value.trim()
        const index = Number(document.querySelector<HTMLInputElement>('#funding-index')!.value)
        void walletTask(async () => {
            state.guided?.assertReady()
            if (state.liveSession) {
                await state.liveSession.bindFunding(raw, index)
                state.publicBalance = state.liveSession.fundingBalance()
            } else if (state.receivingWallet) {
                const { checkedFunding } = await import('./live-funding')
                state.receivingWallet.funding = await checkedFunding(raw, index, state.receivingWallet.address)
                state.publicBalance = state.receivingWallet.funding.satoshis
                state.fundingChecked = true
            }
            state.backupDirty = true
        }, 'Check and bind fee funding')
    })
    document.querySelector('#start-new-pool')?.addEventListener('click', () => void walletTask(async () => {
        if (state.guided && (state.guided.active !== 'sender' || state.backupDirty)) throw new Error('Save the combined backup first; only the sender prepares a fresh pool')
        if (!state.fundingChecked || !state.receivingWallet) throw new Error('Bind mined funding first')
        const { LiveVeilSession } = await import('./live-builder')
        await adoptSession(await LiveVeilSession.create(state.receivingWallet, updateProofProgress))
    }, 'Prepare fresh pool'))
    document.querySelectorAll<HTMLButtonElement>('[data-run-demo]').forEach((button) => {
        button.addEventListener('click', runDemo)
    })
    document.querySelectorAll<HTMLButtonElement>('[data-action]').forEach((button) => {
        button.addEventListener('click', () => {
            if (state.busy || state.pendingLivePlan || state.guidedPolling) return
            state.action = button.dataset.action as Action
            state.amount = ''
            state.recipient = state.action === 'send' && state.guided ? state.guided.defaultRecipient() : ''
            state.unlockHeight = ''
            render()
        })
    })
    document.querySelector('#connect-wallet')?.addEventListener('click', connectWallet)
    document.querySelector('#theme-toggle')?.addEventListener('click', () => {
        state.theme = state.theme === 'dark' ? 'light' : 'dark'
        document.documentElement.dataset.theme = state.theme
        try {
            localStorage.setItem('veil-theme', state.theme)
        } catch {
            // The selected theme still applies for this tab when storage is unavailable.
        }
        render()
    })
    document.querySelector('#copy-address')?.addEventListener('click', async () => {
        if (!state.receivingAddress) { showToast('Create or unlock a live wallet for a real receiving address'); return }
        if (state.receivingWallet && state.backupDirty) { showToast('Save the encrypted receiver backup before sharing this address'); return }
        await navigator.clipboard?.writeText(state.receivingAddress)
        showToast('Private address copied')
    })
    document.querySelector('#max-amount')?.addEventListener('click', () => {
        const maximum =
            state.action === 'shield'
                ? state.publicBalance
                : state.action === 'send' || (state.liveSession !== null && state.action === 'lock')
                  ? Math.max(0, state.privateBalance - 1)
                  : state.privateBalance
        state.amount = String(maximum)
        render()
    })
    document.querySelector<HTMLInputElement>('#amount')?.addEventListener('input', (event) => {
        state.amount = (event.target as HTMLInputElement).value.replace(/\D/g, '')
    })
    document.querySelector<HTMLInputElement>('#recipient')?.addEventListener('input', (event) => {
        state.recipient = (event.target as HTMLInputElement).value
    })
    document.querySelector<HTMLInputElement>('#unlock-height')?.addEventListener('input', (event) => {
        state.unlockHeight = (event.target as HTMLInputElement).value.replace(/\D/g, '')
    })
    document.querySelectorAll<HTMLButtonElement>('[data-height]').forEach((button) => {
        button.addEventListener('click', () => {
            state.unlockHeight = String(
                state.currentHeight + Number.parseInt(button.dataset.height ?? '0', 10)
            )
            render()
        })
    })
    document.querySelector('#submit-action')?.addEventListener('click', () => {
        void submit()
    })
    document.querySelector('#proof-info')?.addEventListener('click', () => {
        showToast('Notes hide balances. Nullifiers stop double-spends. Block locks are proven privately.')
    })
    document.querySelectorAll<HTMLButtonElement>('[data-proof]').forEach((row) => {
        row.addEventListener('click', () => showToast(`Groth16 statement ${row.dataset.proof} · verified locally`))
    })
    document.querySelector('#unlock-live-wallet')?.addEventListener('click', () => {
        void unlockBrowserWallet()
    })
    document.querySelector<HTMLInputElement>('#live-password')?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') void unlockBrowserWallet()
    })
    document.querySelector('#use-live-wallet')?.addEventListener('click', () => {
        state.liveDialogOpen = false
        render()
    })
    document.querySelector('#lock-live-wallet')?.addEventListener('click', clearLiveWallet)
    document.querySelector<HTMLInputElement>('#live-confirm')?.addEventListener('change', (event) => {
        state.liveConfirm = (event.target as HTMLInputElement).checked
        render()
    })
    document.querySelector('#broadcast-live-plan')?.addEventListener('click', () => {
        void broadcastLivePlan()
    })
    document.querySelector('#close-live-modal')?.addEventListener('click', () => {
        if (state.busy || state.liveUnlocking || state.liveBroadcastIndex >= 0) return
        if (state.pendingLivePlan) timers.finish(actionTiming, 'Review dismissed — not broadcast')
        state.liveDialogOpen = false
        state.pendingLivePlan = null
        state.liveConfirm = false
        state.liveError = ''
        state.liveBroadcastIndex = -1
        render()
    })
    document.querySelector('#live-modal-backdrop')?.addEventListener('click', (event) => {
        // Deliberate close only; background clicks never discard work or inputs.
        if (event.target === event.currentTarget) event.preventDefault()
    })
}

render()
// Quotes disclose no wallet identifiers to the provider. Requests use this browser's route.
void refreshUsd()
window.setInterval(() => { updateUsdDisplay(); void refreshUsd() }, 5 * 60_000)
window.setInterval(() => void checkGuidedHandoff(), 30_000)
window.setInterval(updateTimers, 250)
window.setInterval(() => void checkMiningTimings(), 30_000)
