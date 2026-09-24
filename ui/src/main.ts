import './styles.css'
import { proveAction } from './prover'

type Action = 'shield' | 'send' | 'lock' | 'withdraw'

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
}

const state = {
    action: 'shield' as Action,
    privateBalance: 1_000,
    lockedBalance: 0,
    publicBalance: 25_400,
    currentHeight: 910_000,
    connected: false,
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
    document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
      <div class="shell">
        <header class="topbar">
          <a class="brand" href="#" aria-label="Veil home">
            <span class="brand-mark">${icons.shield}</span>
            <span>Veil</span>
          </a>
          <div class="header-actions">
            <span class="network"><i></i> Testnet demo</span>
            <button class="wallet-button" id="connect-wallet">
              ${state.connected ? '<span class="wallet-dot"></span> Wallet connected' : 'Connect wallet'}
            </button>
          </div>
        </header>

        <main>
          <section class="hero-copy">
            <div class="privacy-pill">${icons.lock} Zero-knowledge privacy</div>
            <h1>Your BSV.<br><em>Nobody else’s business.</em></h1>
            <p>Deposit, pay, and withdraw without revealing your private activity.</p>
          </section>

          <section class="wallet-grid">
            <aside class="balance-card">
              <div class="balance-topline">
                <span>Private balance</span>
                <span class="status-chip">${icons.check} Protected</span>
              </div>
              <div class="balance"><strong>${formatSats(state.privateBalance)}</strong><span>sats</span></div>
              <div class="balance-fiat">≈ £${(state.privateBalance * 0.00042).toFixed(2)}</div>

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
                <span class="demo-label">${state.connected ? 'WALLET' : 'DEMO'}</span>
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
                <p>${active.description}</p>
              </div>

              ${active.recipient ? `
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
                ${state.busy ? '<span class="spinner"></span> Creating private proof…' : `${active.cta} <span>→</span>`}
              </button>
              ${state.busy ? `
                <div class="proof-progress" role="progressbar" aria-valuemin="1" aria-valuemax="100" aria-valuenow="${state.proofProgress}">
                  <div class="proof-progress-track"><span style="width: ${state.proofProgress}%"></span></div>
                  <div class="proof-progress-copy"><span id="proof-progress-label">${state.proofProgressLabel}</span><strong id="proof-progress-percent">${state.proofProgress}%</strong></div>
                </div>
              ` : ''}
              <div class="trust-line">${icons.lock}<span>Keys stay in your wallet. Proofs reveal no private details.</span></div>
            </section>
          </section>

          <section class="activity-section">
            <div class="section-heading"><div><span>RECENT ACTIVITY</span><h2>Private by default</h2></div><button id="proof-info">How it works</button></div>
            <div class="activity-list">
              ${state.activities.map(activityRow).join('')}
            </div>
          </section>
        </main>

        <footer><span>Real proofs, local demo state. No transaction is broadcast.</span><span>Source included with release</span></footer>
        <div class="toast" id="toast" role="status"></div>
      </div>
    `
    wireEvents()
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
    showToast('No BSV wallet found — staying in safe demo mode')
}

async function submit(): Promise<void> {
    const amount = Number.parseInt(state.amount, 10)
    const available = state.action === 'shield' ? state.publicBalance : state.privateBalance
    if (!Number.isSafeInteger(amount) || amount <= 0) {
        showToast('Enter an amount greater than zero')
        return
    }
    if (amount > available) {
        showToast(`You only have ${formatSats(available)} sats available`)
        return
    }
    if (state.action === 'send' && amount === available) {
        showToast('Leave at least 1 sat as private change')
        return
    }
    if (copy[state.action].recipient && state.recipient.trim().length < 4) {
        showToast(state.action === 'send' ? 'Enter a Veil address' : 'Enter a BSV address')
        return
    }
    const unlockHeight = Number.parseInt(state.unlockHeight, 10)
    if (
        state.action === 'lock' &&
        (!Number.isSafeInteger(unlockHeight) ||
            unlockHeight <= state.currentHeight ||
            unlockHeight >= 500_000_000)
    ) {
        showToast(`Choose a block above ${formatSats(state.currentHeight)}`)
        return
    }

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
        return
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
}

function wireEvents(): void {
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
    document.querySelector('#copy-address')?.addEventListener('click', async () => {
        await navigator.clipboard?.writeText('veil1qx7kd2v5myu8r3e4psw0c9t6g8f4n')
        showToast('Private address copied')
    })
    document.querySelector('#max-amount')?.addEventListener('click', () => {
        const maximum =
            state.action === 'shield'
                ? state.publicBalance
                : state.action === 'send'
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
    document.querySelector('#submit-action')?.addEventListener('click', submit)
    document.querySelector('#proof-info')?.addEventListener('click', () => {
        showToast('Notes hide balances. Nullifiers stop double-spends. Block locks are proven privately.')
    })
    document.querySelectorAll<HTMLButtonElement>('[data-proof]').forEach((row) => {
        row.addEventListener('click', () => showToast(`Groth16 statement ${row.dataset.proof} · verified locally`))
    })
}

render()
