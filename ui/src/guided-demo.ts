import { createHash } from '../../src/crypto'
import { RECIPIENT_PROTOCOL, recipientIdentity, type EncryptedPayment } from '../../src/recipient'
import type { PoolSnapshot } from '../../src/recipientState'
import { createReceivingWallet, validateReceivingWallet, type LiveWallet } from './live-wallet'
import { transactionStatus } from './live-network'
import type { LiveVeilSession, PreparedLiveAction } from './live-builder'

export const GUIDED_FORMAT = 'veil-guided-pair-v1-testnet'
export const GUIDED_MARKER = 'veil-v030-guided-pair-created'
export type Role = 'sender' | 'recipient'
export const otherRole = (role: Role): Role => role === 'sender' ? 'recipient' : 'sender'
type Progress = (percent: number | null, label: string) => void
export interface DemoSlot { wallet: LiveWallet; address: string; session: LiveVeilSession | null }
interface PendingHandoff { from: Role; txid: string; snapshot: PoolSnapshot; payment?: EncryptedPayment }

// Proof-chain transaction hex repeats across both snapshots, payment metadata
// and the pending handoff. Store each large string once inside the encryption.
function pack(value: unknown): unknown {
    const strings: string[] = []
    const indices = new Map<string, number>()
    const visit = (v: any): any => {
        if (typeof v === 'string' && v.length > 1024) {
            let index = indices.get(v)
            if (index === undefined) { index = strings.length; strings.push(v); indices.set(v, index) }
            return { $veilString: index }
        }
        if (Array.isArray(v)) return v.map(visit)
        if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, item]) => [k, visit(item)]))
        return v
    }
    const data = visit(value)
    return { format: GUIDED_FORMAT, encoding: 'string-table-v1', strings, data }
}
function unpack(value: any): any {
    if (value?.format !== GUIDED_FORMAT || value.encoding !== 'string-table-v1' || !Array.isArray(value.strings) ||
        value.strings.length > 128 || value.strings.some((s: unknown) => typeof s !== 'string') ||
        value.strings.reduce((sum: number, s: string) => sum + s.length, 0) > 32_000_000) throw new Error('Invalid guided backup encoding')
    let expanded = 0
    const visit = (v: any, depth = 0): any => {
        if (depth > 32) throw new Error('Invalid guided backup nesting')
        if (v && typeof v === 'object' && Object.hasOwn(v, '$veilString')) {
            if (Object.keys(v).length !== 1 || !Number.isInteger(v.$veilString) || v.$veilString < 0 || v.$veilString >= value.strings.length) throw new Error('Invalid guided string reference')
            const s = value.strings[v.$veilString]
            expanded += s.length
            if (expanded > 128_000_000) throw new Error('Guided backup exceeds expansion limit')
            return s
        }
        if (Array.isArray(v)) return v.map(item => visit(item, depth + 1))
        if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, item]) => [k, visit(item, depth + 1)]))
        return v
    }
    return visit(value.data)
}

/** One pool, two independent keys. No method here broadcasts or persists plaintext. */
export class GuidedDemo {
    active: Role = 'sender'
    pending: PendingHandoff | null = null
    private checking = false
    constructor(readonly slots: Record<Role, DemoSlot>) {
        if (slots.sender.address === slots.recipient.address || slots.sender.wallet.address === slots.recipient.wallet.address) {
            throw new Error('Guided demo requires two distinct wallets')
        }
    }
    static async create(wallet: LiveWallet, session: LiveVeilSession | null = null): Promise<GuidedDemo> {
        const receiver = createReceivingWallet()
        const hash = await createHash()
        return new GuidedDemo({
            sender: { wallet, session, address: recipientIdentity(wallet.wif, hash).address },
            recipient: { wallet: receiver, session: null, address: recipientIdentity(receiver.wif, hash).address },
        })
    }
    defaultRecipient(): string { return this.slots[otherRole(this.active)].address }
    assertReady(): void {
        if (this.pending || this.checking) throw new Error('Wait for mining and automatic wallet synchronization before the next action')
    }
    accepted(plan: PreparedLiveAction): void {
        this.assertReady()
        const peer = this.slots[otherRole(this.active)]
        // Custom addresses remain external: never auto-import their payment.
        this.pending = {
            from: this.active, txid: plan.transactions.at(-1)!.txid, snapshot: plan.snapshot,
            payment: plan.payment?.recipient === peer.address ? plan.payment : undefined,
        }
    }
    async poll(progress: Progress, status = transactionStatus): Promise<boolean> {
        if (!this.pending || this.checking) return false
        this.checking = true
        const pending = this.pending
        try {
            const result = await status(pending.txid)
            if (result?.txStatus !== 'MINED') {
                if (result && /REJECT|CONFLICT|DOUBLE_SPEND/.test(result.txStatus)) throw new Error(`Finalizer ${result.txStatus}; stop and review. No automatic resubmission.`)
                if (!result) throw new Error('Finalizer not found by ARC; handoff remains pending. No automatic resubmission.')
                return false
            }
            const peer = this.slots[otherRole(pending.from)]
            if (pending.payment) {
                if (peer.session) await peer.session.importPayment(pending.payment)
                else {
                    const { LiveVeilSession } = await import('./live-builder')
                    peer.session = await LiveVeilSession.receive(peer.wallet, pending.payment, progress)
                }
            } else if (peer.session) await peer.session.importPoolSnapshot(pending.snapshot)
            this.pending = null
            return true
        } finally { this.checking = false }
    }
    backupPayload(): unknown {
        const payload = (role: Role) => {
            const slot = this.slots[role]
            const data = (slot.session?.backupPayload() ?? {
                protocol: RECIPIENT_PROTOCOL, wallet: slot.wallet, pool: null, notes: [],
            }) as any
            // An imported local payment is redundant with the recipient's own
            // notes/snapshot. Retain pending and external deliveries, not an
            // ever-growing pair of obsolete encrypted proof chains.
            if (data.lastPayment?.recipient === this.slots[otherRole(role)].address &&
                !(this.pending?.from === role && this.pending.payment)) delete data.lastPayment
            return data
        }
        return pack({ format: GUIDED_FORMAT, active: this.active, sender: payload('sender'), recipient: payload('recipient'), pending: this.pending })
    }
    static async restore(value: any, progress: Progress): Promise<GuidedDemo> {
        value = unpack(value)
        if (value?.format !== GUIDED_FORMAT || !['sender', 'recipient'].includes(value.active)) throw new Error('Invalid guided backup')
        const hash = await createHash()
        const restore = async (payload: any): Promise<DemoSlot> => {
            if (payload?.protocol !== RECIPIENT_PROTOCOL || !Array.isArray(payload.notes)) throw new Error('Invalid guided wallet payload')
            const wallet = validateReceivingWallet(payload.wallet)
            let session: LiveVeilSession | null = null
            if (payload.pool) {
                const { LiveVeilSession } = await import('./live-builder')
                session = await LiveVeilSession.restoreBackup(payload, progress)
            } else if (payload.notes.length) throw new Error('Notes require a pool')
            return { wallet, session, address: recipientIdentity(wallet.wif, hash).address }
        }
        const pair = new GuidedDemo({ sender: await restore(value.sender), recipient: await restore(value.recipient) })
        pair.active = value.active
        if (value.pending) {
            const p = value.pending
            if (!['sender', 'recipient'].includes(p.from) || !/^[0-9a-f]{64}$/.test(p.txid)) throw new Error('Invalid pending handoff')
            const source = pair.slots[p.from as Role].session
            if (!source || JSON.stringify(source.poolSnapshot()) !== JSON.stringify(p.snapshot)) throw new Error('Handoff does not match source pool')
            const { bsv } = await import('scrypt-ts')
            if (new bsv.Transaction(p.snapshot.rawPoolTx).id !== p.txid ||
                (p.payment && (p.payment.recipient !== pair.slots[otherRole(p.from)].address || JSON.stringify(source.paymentFile()) !== JSON.stringify(p.payment)))) {
                throw new Error('Handoff transaction or recipient mismatch')
            }
            pair.pending = p
        }
        return pair
    }
}
