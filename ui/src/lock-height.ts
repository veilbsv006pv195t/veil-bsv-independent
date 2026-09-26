const MAX_HEIGHT = 500_000_000

export function resolveLockHeight(input: string | number, current: number): number {
    if (!Number.isSafeInteger(current) || current <= 0 || current >= MAX_HEIGHT) {
        throw new Error('Testnet height unavailable. Retry before preparing a lock.')
    }
    const text = String(input).trim()
    // Permit ordinary grouped block heights, but never strip arbitrary input.
    if (!/^\+?(?:\d+|\d{1,3}(?:,\d{3})+)$/.test(text)) {
        throw new Error('Enter +3 for three more blocks, or an absolute height such as 1,760,000.')
    }
    const value = Number(text.replace(/,/g, ''))
    const target = text.startsWith('+') ? current + value : value
    if (!Number.isSafeInteger(value) || !Number.isSafeInteger(target) || target >= MAX_HEIGHT) {
        throw new Error('Unlock height must be a whole block below 500,000,000.')
    }
    if (target <= current) throw new Error(`Choose a height above ${current.toLocaleString('en-GB')}, or use + followed by a positive block count.`)
    return target
}

export function lockHeightLabel(target: number, checkedHeight: number): string {
    return `${target.toLocaleString('en-GB')} (+${(target - checkedHeight).toLocaleString('en-GB')})`
}

// No simulated fallback. Repeated requests share the current fetch; failures clear the value.
export class HeightTracker {
    height: number | null = null
    loading = false
    checkedAt: number | null = null
    private pending: Promise<number | null> | null = null
    constructor(private load: () => Promise<number>, private changed: () => void = () => {}) {}
    refresh(): Promise<number | null> {
        if (this.pending) return this.pending
        this.loading = true
        this.height = null
        this.changed()
        this.pending = Promise.resolve().then(this.load).then(height => {
            if (!Number.isSafeInteger(height) || height <= 0 || height >= MAX_HEIGHT) throw new Error('Invalid testnet height')
            this.height = height
            this.checkedAt = Date.now()
            return height
        }).catch(() => {
            this.height = null
            this.checkedAt = null
            return null
        }).finally(() => {
            this.loading = false
            this.pending = null
            this.changed()
        })
        return this.pending
    }
    async requireFresh(): Promise<number> {
        const height = await this.refresh()
        if (height === null) throw new Error('Testnet height unavailable. Retry before preparing a transaction.')
        return height
    }
}
