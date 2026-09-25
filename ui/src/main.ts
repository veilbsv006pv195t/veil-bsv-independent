import './styles.css'
import { proveAction } from './prover'
import type { LiveVeilSession, PreparedLiveAction } from './live-builder'
import { broadcastRawTransaction, explorerUrl, testnetHeight } from './live-network'
import { unlockLiveWallet } from './live-wallet'

type Action = 'shield' | 'send' | 'lock' | 'withdraw'
type Theme = 'light' | 'dark'

interface Activity {
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
    action: 'shield' as Action,
    theme: initialTheme(),
    privateBalance: 1_000,
    lockedBalance: 0,
    publicBalance: 25_400,
    currentHeight: 910_000,
    connected: false,
    liveSession: null as LiveVeilSession | null,
    liveAddress: '',
    liveDialogOpen: false,
    liveUnlocking: false,
    liveConfirm: false,
    liveError: '',
    pendingLivePlan: null as PreparedLiveAction | null,
    liveBroadcastIndex: -1,
    demoRunning: false,
    busy: false,
    proofProgress: 0,
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
        recipientPlaceholder: 'veil1…',
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
    const active = copy[state.action]
    const max = state.action === 'shield' ? state.publicBalance : state.privateBalance
    const live = state.liveSession !== null
    const needsRecipient = active.recipient && !(live && state.action === 'send')
    const actionDescription = live && state.action === 'send'
        ? 'Moves value through a nullifier into a fresh private note controlled by this disposable testnet wallet.'
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
                  : state.connected
                    ? '<span class="wallet-dot"></span> Wallet connected'
                    : 'Unlock live testnet'}
            </button>
          </div>
        </header>

        <main>
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
              <div class="balance-fiat">≈ £${(state.privateBalance * 0.0000042).toFixed(2)} <span>(~mainnet currency)</span></div>

              <div class="locked-summary ${state.lockedBalance > 0 ? 'has-lock' : ''}">
                ${icons.lock}
                <span><small>Height-locked</small><strong>${formatSats(state.lockedBalance)} sats</strong></span>
              </div>

              <div class="address-card">
                <div><span>Your private address</span><strong>veil1qx7k…8f4n</strong></div>
                <button id="copy-address" aria-label="Copy private address">${icons.copy}</button>
              </div>

              <div class="balance-footer">
                <div><span>Available in wallet</span><strong>${formatSats(state.publicBalance)} sats</strong></div>
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

              <button class="primary-button" id="submit-action" ${state.busy ? 'disabled' : ''}>
                ${state.busy
                    ? '<span class="spinner"></span> Preparing audited transaction chain…'
                    : live
                      ? `Prepare ${active.cta.toLowerCase()} <span>→</span>`
                      : `${active.cta} <span>→</span>`}
              </button>
              ${state.busy ? `
                <div class="proof-progress" role="progressbar" aria-valuemin="1" aria-valuemax="100" aria-valuenow="${state.proofProgress}">
                  <div class="proof-progress-track"><span style="width: ${state.proofProgress}%"></span></div>
                  <div class="proof-progress-copy"><span id="proof-progress-label">${state.proofProgressLabel}</span><strong id="proof-progress-percent">${state.proofProgress}%</strong></div>
                </div>
              ` : ''}
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

        <footer><span>${live
            ? 'LIVE TESTNET MODE · Every signed transaction requires review before broadcast.'
            : 'Real proofs, local demo state. No transaction is broadcast.'}</span><span>Source included with release</span></footer>
        <div class="toast" id="toast" role="status"></div>
      </div>
      ${state.liveDialogOpen || state.pendingLivePlan ? liveDialog() : ''}
    `
    wireEvents()
}

function liveDialog(): string {
    const plan = state.pendingLivePlan
    if (plan) {
        const submissionStarted = state.liveBroadcastIndex >= 0
        return `<div class="modal-backdrop" id="live-modal-backdrop">
          <section class="live-modal review-modal" role="dialog" aria-modal="true" aria-labelledby="live-title">
            <button class="modal-close" id="close-live-modal" aria-label="Close" ${state.busy || submissionStarted ? 'disabled' : ''}>×</button>
            <span class="live-kicker">SIGNED LOCALLY · NOT BROADCAST</span>
            <h2 id="live-title">Review the exact testnet chain</h2>
            <div class="review-summary">
              <div><span>Action</span><strong>${escapeHtml(plan.action)}</strong></div>
              <div><span>Amount</span><strong>${formatSats(plan.amount)} sats</strong></div>
              <div><span>Total miner fees</span><strong>${formatSats(plan.totalFees)} sats</strong></div>
              <div><span>Transactions</span><strong>${plan.transactions.length}</strong></div>
              ${plan.recipient ? `<div class="wide"><span>Public recipient</span><strong>${escapeHtml(plan.recipient)}</strong></div>` : ''}
              ${plan.unlockHeight ? `<div class="wide"><span>Unlock height</span><strong>${formatSats(plan.unlockHeight)}</strong></div>` : ''}
            </div>
            <ol class="tx-review-list">
              ${plan.transactions.map((tx, index) => `<li class="${state.liveBroadcastIndex === index ? 'active' : ''}">
                <div><span>${index + 1}. ${escapeHtml(tx.name)}</span><small>${formatSats(tx.bytes)} B · ${formatSats(tx.feeSatoshis)} sat fee</small></div>
                <a href="${explorerUrl(tx.txid)}" target="_blank" rel="noopener noreferrer" aria-label="View transaction ${tx.txid} on Whatsonchain testnet in a new tab">${tx.txid.slice(0, 12)}…${tx.txid.slice(-10)}</a>
              </li>`).join('')}
            </ol>
            <p class="review-warning">${escapeHtml(plan.warning)}</p>
            <label class="live-confirm"><input id="live-confirm" type="checkbox" ${state.liveConfirm ? 'checked' : ''} ${state.busy ? 'disabled' : ''}/><span>I checked the action, amount, recipient, fees, and TXIDs. Broadcast this exact parent-first chain on BSV testnet.</span></label>
            <button class="primary-button danger-button" id="broadcast-live-plan" ${!state.liveConfirm || state.busy ? 'disabled' : ''}>
              ${state.busy ? '<span class="spinner"></span> Broadcasting exact chain…' : 'Broadcast exact testnet chain →'}
            </button>
            ${state.liveError ? `<p class="live-error" role="alert">${escapeHtml(state.liveError)}${submissionStarted ? ' Keep this page open and retry the same chain; accepted ancestors will not be resent.' : ''}</p>` : ''}
          </section>
        </div>`
    }
    return `<div class="modal-backdrop" id="live-modal-backdrop">
      <section class="live-modal" role="dialog" aria-modal="true" aria-labelledby="live-title">
        <button class="modal-close" id="close-live-modal" aria-label="Close">×</button>
        <span class="live-kicker">DISPOSABLE WALLET · TESTNET ONLY</span>
        <h2 id="live-title">${state.liveSession ? 'Live wallet unlocked' : 'Unlock the live testnet wallet'}</h2>
        ${state.liveSession ? `
          <p>The key and private note state exist only in this browser tab. Keep it open for the complete review. Choose any action and amount, then review every exact TXID before broadcasting.</p>
          <div class="unlocked-address"><span>Testnet address</span><strong>${escapeHtml(state.liveAddress)}</strong></div>
          <button class="primary-button" id="use-live-wallet">Choose an action →</button>
          <button class="secondary-button" id="lock-live-wallet">Lock and clear wallet</button>
        ` : `
          <p>The separately delivered password decrypts the disposable wallet locally. It is never sent to GitHub, Veil, ARC, or WhatsOnChain.</p>
          <label class="field-label" for="live-password">Live-wallet password</label>
          <div class="text-field"><input id="live-password" type="password" autocomplete="current-password" spellcheck="false" /></div>
          <button class="primary-button" id="unlock-live-wallet" ${state.liveUnlocking ? 'disabled' : ''}>
            ${state.liveUnlocking ? '<span class="spinner"></span> Unlocking and checking testnet…' : 'Unlock in this browser →'}
          </button>
        `}
        ${state.liveError ? `<p class="live-error" role="alert">${escapeHtml(state.liveError)}</p>` : ''}
        <p class="live-safety">Anyone with the password controls this disposable testnet wallet. Never use this mode with mainnet funds.</p>
      </section>
    </div>`
}

function tab(action: Action, label: string, icon: string): string {
    return `<button class="action-tab ${state.action === action ? 'active' : ''}" data-action="${action}">${icon}<span>${label}</span></button>`
}

function activityRow(activity: Activity): string {
    const sign = activity.kind === 'shield' ? '+' : activity.kind === 'lock' ? '' : '−'
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

function updateProofProgress(percent: number, label: string): void {
    state.proofProgress = Math.max(1, Math.min(100, Math.round(percent)))
    state.proofProgressLabel = label
    const progress = document.querySelector<HTMLDivElement>('.proof-progress')
    const track = document.querySelector<HTMLSpanElement>('.proof-progress-track span')
    const labelElement = document.querySelector<HTMLSpanElement>('#proof-progress-label')
    const percentElement = document.querySelector<HTMLElement>('#proof-progress-percent')
    if (progress) progress.setAttribute('aria-valuenow', String(state.proofProgress))
    if (track) track.style.width = `${state.proofProgress}%`
    if (labelElement) labelElement.textContent = label
    if (percentElement) percentElement.textContent = `${state.proofProgress}%`
}

async function connectWallet(): Promise<void> {
    if (state.liveSession) {
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
    const input = document.querySelector<HTMLInputElement>('#live-password')
    let password = input?.value ?? ''
    if (input) input.value = ''
    state.liveUnlocking = true
    state.liveError = ''
    render()
    try {
        const wallet = await unlockLiveWallet(password)
        password = ''
        const { LiveVeilSession } = await import('./live-builder')
        const session = await LiveVeilSession.create(wallet, updateProofProgress)
        const height = await testnetHeight()
        state.liveSession = session
        state.liveAddress = wallet.address
        state.connected = true
        state.publicBalance = wallet.funding.satoshis
        state.privateBalance = 0
        state.lockedBalance = 0
        state.currentHeight = height
        state.activities = []
    } catch (error) {
        password = ''
        state.liveError = error instanceof Error ? error.message : 'Could not unlock the live wallet'
    } finally {
        state.liveUnlocking = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
    }
}

function clearLiveWallet(): void {
    state.liveSession = null
    state.liveAddress = ''
    state.connected = false
    state.liveDialogOpen = false
    state.pendingLivePlan = null
    state.liveConfirm = false
    state.liveError = ''
    state.liveBroadcastIndex = -1
    resetDemoState()
    render()
    showToast('Live wallet key cleared from this tab')
}

async function prepareLiveAction(amount: number, unlockHeight: number): Promise<boolean> {
    const session = state.liveSession
    if (!session) return false
    state.busy = true
    state.liveError = ''
    state.proofProgress = 1
    state.proofProgressLabel = 'Preparing exact testnet transaction chain'
    render()
    try {
        const plan = await session.prepare(
            state.action,
            amount,
            state.recipient.trim(),
            unlockHeight,
            updateProofProgress
        )
        state.pendingLivePlan = plan
        state.liveConfirm = false
        state.liveDialogOpen = false
        state.currentHeight = plan.startHeight
        state.busy = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
        return true
    } catch (error) {
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
    state.busy = true
    state.liveError = ''
    render()
    try {
        for (let index = 0; index < plan.transactions.length; index++) {
            state.liveBroadcastIndex = index
            render()
            const transaction = plan.transactions[index]
            await broadcastRawTransaction(transaction.rawHex, transaction.txid)
        }
        session.commit(plan)
        state.privateBalance = plan.newPrivateBalance
        state.lockedBalance = plan.newLockedBalance
        const createsPool = plan.transactions.some((transaction) => transaction.name === 'deploy-v4-pool')
        const returnsToWallet = plan.action === 'withdraw' && plan.recipient === state.liveAddress
        state.publicBalance = Math.max(
            0,
            state.publicBalance -
                plan.totalFees -
                (plan.action === 'shield' ? plan.amount : 0) -
                (createsPool ? 1 : 0) +
                (returnsToWallet ? plan.amount : 0)
        )
        const finalTx = plan.transactions.at(-1)!
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
        state.recipient = ''
        state.unlockHeight = ''
        state.pendingLivePlan = null
        state.liveConfirm = false
        state.liveBroadcastIndex = -1
        state.busy = false
        render()
        showToast('Exact parent-first chain accepted by ARC on testnet')
    } catch (error) {
        state.busy = false
        state.liveError = error instanceof Error ? error.message : 'ARC did not accept the transaction chain'
        render()
    }
}

async function submit(): Promise<boolean> {
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
        !(state.liveSession && state.action === 'send') &&
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
        state.busy = false
        state.proofProgress = 0
        state.proofProgressLabel = ''
        render()
        showToast(error instanceof Error ? error.message : 'Could not create the private proof')
        return false
    }

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
    if (state.liveSession) {
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
    document.querySelectorAll<HTMLButtonElement>('[data-run-demo]').forEach((button) => {
        button.addEventListener('click', runDemo)
    })
    document.querySelectorAll<HTMLButtonElement>('[data-action]').forEach((button) => {
        button.addEventListener('click', () => {
            state.action = button.dataset.action as Action
            state.amount = ''
            state.recipient = ''
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
        await navigator.clipboard?.writeText('veil1qx7kd2v5myu8r3e4psw0c9t6g8f4n')
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
        if (state.busy || state.liveBroadcastIndex >= 0) return
        state.liveDialogOpen = false
        state.pendingLivePlan = null
        state.liveConfirm = false
        state.liveError = ''
        state.liveBroadcastIndex = -1
        render()
    })
    document.querySelector('#live-modal-backdrop')?.addEventListener('click', (event) => {
        if (event.target !== event.currentTarget || state.busy || state.liveBroadcastIndex >= 0) return
        state.liveDialogOpen = false
        state.pendingLivePlan = null
        state.liveConfirm = false
        state.liveError = ''
        state.liveBroadcastIndex = -1
        render()
    })
}

render()
