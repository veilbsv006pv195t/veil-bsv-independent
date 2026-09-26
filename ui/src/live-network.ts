export interface MinerPolicy {
    miningFee: { satoshis: number; bytes: number }
    maxtxsizepolicy: number
    maxscriptsizepolicy: number
}

export interface BroadcastResult {
    txid: string
    txStatus: string
}

const ARCADE = 'https://testnet.arcade.gorillapool.io'
const ARC = 'https://testnet.arc.gorillapool.io'
const ACCEPTED = new Set([
    'QUEUED',
    'RECEIVED',
    'STORED',
    'ANNOUNCED_TO_NETWORK',
    'REQUESTED_BY_NETWORK',
    'SENT_TO_NETWORK',
    'ACCEPTED_BY_NETWORK',
    'SEEN_ON_NETWORK',
    'MINED',
])

async function json<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await fetch(url, { cache: 'no-store', ...init })
    const text = await response.text()
    if (!response.ok) throw new Error(`${response.status} ${text.slice(0, 180)}`)
    return JSON.parse(text) as T
}

export async function testnetPolicy(): Promise<MinerPolicy> {
    const value = await json<{ policy?: Partial<MinerPolicy> }>(`${ARCADE}/policy`)
    const policy = value.policy
    if (
        !policy?.miningFee ||
        !Number.isSafeInteger(policy.miningFee.satoshis) ||
        !Number.isSafeInteger(policy.miningFee.bytes) ||
        !Number.isSafeInteger(policy.maxtxsizepolicy) ||
        !Number.isSafeInteger(policy.maxscriptsizepolicy) ||
        policy.maxscriptsizepolicy !== 500_000
    ) throw new Error('The testnet miner returned an unexpected policy')
    return policy as MinerPolicy
}

export async function testnetHeight(): Promise<number> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 45_000)
    try {
        const value = await json<{ blockHeight?: number }>(`${ARCADE}/health`, { signal: controller.signal })
        if (!Number.isSafeInteger(value.blockHeight) || (value.blockHeight as number) <= 0 || (value.blockHeight as number) >= 500_000_000) {
            throw new Error('The testnet miner returned an invalid block height')
        }
        return value.blockHeight as number
    } finally {
        clearTimeout(timeout)
    }
}

export async function transactionStatus(txid: string): Promise<BroadcastResult | null> {
    const response = await fetch(`${ARC}/v1/tx/${txid}`, { cache: 'no-store' })
    if (response.status === 404) return null
    const text = await response.text()
    if (!response.ok) throw new Error(`Could not check ${txid.slice(0, 12)}…: ${text.slice(0, 160)}`)
    const value = JSON.parse(text) as { txid?: string; txStatus?: string }
    if (value.txid?.toLowerCase() !== txid.toLowerCase() || !value.txStatus) {
        throw new Error('ARC returned an invalid transaction status')
    }
    return { txid: value.txid, txStatus: value.txStatus }
}

export async function broadcastRawTransaction(rawHex: string, expectedTxid: string): Promise<BroadcastResult> {
    const existing = await transactionStatus(expectedTxid)
    if (existing && ACCEPTED.has(existing.txStatus)) return existing
    const response = await fetch(`${ARC}/v1/tx`, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain',
            'X-WaitForStatus': 'SEEN_ON_NETWORK',
        },
        body: rawHex,
    })
    const text = await response.text()
    let value: { txid?: string; txStatus?: string; extraInfo?: string }
    try {
        value = JSON.parse(text) as typeof value
    } catch {
        throw new Error(`ARC returned an unreadable response (${response.status})`)
    }
    if (
        !response.ok ||
        value.txid?.toLowerCase() !== expectedTxid.toLowerCase() ||
        !value.txStatus ||
        !ACCEPTED.has(value.txStatus)
    ) throw new Error(value.extraInfo || `ARC did not accept ${expectedTxid.slice(0, 12)}…`)
    return { txid: value.txid, txStatus: value.txStatus }
}

export function explorerUrl(txid: string): string {
    return `https://test.whatsonchain.com/tx/${txid}`
}
