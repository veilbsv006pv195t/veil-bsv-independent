export const PRICE_URL = 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin-cash-sv&vs_currencies=usd&include_last_updated_at=true'
export interface UsdQuote { usdPerBsv: number; updatedAt: number }
export function parseUsdQuote(value: any, now = Date.now()): UsdQuote {
    const price = value?.['bitcoin-cash-sv']
    const quote = { usdPerBsv: price?.usd, updatedAt: price?.last_updated_at * 1000 }
    if (!Number.isFinite(quote.usdPerBsv) || quote.usdPerBsv <= 0 || !isFresh(quote, now)) throw new Error('BSV/USD quote unavailable or stale')
    return quote
}
export function isFresh(quote: UsdQuote, now = Date.now()): boolean {
    return Number.isFinite(quote.updatedAt) && quote.updatedAt <= now + 60_000 && now - quote.updatedAt <= 15 * 60_000
}
export function mainnetUsd(sats: number, quote: UsdQuote, now = Date.now()): string {
    if (!Number.isSafeInteger(sats) || sats < 0 || !Number.isFinite(quote.usdPerBsv) || quote.usdPerBsv <= 0 || !isFresh(quote, now)) return 'USD estimate unavailable'
    const usd = sats / 100_000_000 * quote.usdPerBsv
    if (usd > 0 && usd < 0.000001) return '≈ <$0.000001 USD'
    return `≈ $${usd > 0 && usd < 1 ? usd.toFixed(6).replace(/0+$/, '') : usd.toFixed(2)} USD`
}
export async function fetchUsdQuote(): Promise<UsdQuote> {
    const response = await fetch(PRICE_URL, { cache: 'no-store', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15_000) })
    if (!response.ok) throw new Error('USD price provider unavailable')
    return parseUsdQuote(await response.json())
}
