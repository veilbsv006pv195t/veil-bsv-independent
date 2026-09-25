import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseUsdQuote, mainnetUsd, fetchUsdQuote, PRICE_URL } from '../ui/src/usd-price'

const now = 1_790_364_350_000
const quote = { usdPerBsv: 21.4, updatedAt: now }
test('satoshis convert to USD using 100 million sats per BSV', () => {
    assert.equal(mainnetUsd(100_000, quote, now), '≈ $0.0214 USD')
    assert.equal(mainnetUsd(1_000, quote, now), '≈ $0.000214 USD')
    assert.equal(mainnetUsd(100_000, { ...quote, usdPerBsv: 21.48 }, now), '≈ $0.02148 USD')
    assert.equal(mainnetUsd(1_000, { ...quote, usdPerBsv: 42 }, now), '≈ $0.00042 USD')
    assert.equal(mainnetUsd(100_000_000, quote, now), '≈ $21.40 USD')
    assert.equal(mainnetUsd(0, quote, now), '≈ $0.00 USD')
    assert.equal(mainnetUsd(1, quote, now), '≈ <$0.000001 USD')
})
test('missing, stale, invalid and future quotes are not displayed as prices', () => {
    assert.equal(mainnetUsd(100_000, quote, now + 900_001), 'USD estimate unavailable')
    assert.equal(mainnetUsd(-1, quote, now), 'USD estimate unavailable')
    assert.equal(mainnetUsd(1, { ...quote, usdPerBsv: NaN }, now), 'USD estimate unavailable')
    assert.equal(mainnetUsd(1, { ...quote, usdPerBsv: -5 }, now), 'USD estimate unavailable')
    assert.throws(() => parseUsdQuote({}, now), /unavailable/)
    assert.throws(() => parseUsdQuote({ 'bitcoin-cash-sv': { usd: 21.4, last_updated_at: now / 1000 + 61 } }, now), /stale/)
    assert.deepEqual(parseUsdQuote({ 'bitcoin-cash-sv': { usd: 21.4, last_updated_at: now / 1000 } }, now), quote)
})
test('price request contains no wallet data or referrer and fails closed', async () => {
    const original = globalThis.fetch
    try {
        globalThis.fetch = async (url, options) => {
            assert.equal(url, PRICE_URL)
            assert.equal(options?.referrerPolicy, 'no-referrer')
            assert.equal(options?.cache, 'no-store')
            assert.ok(options?.signal)
            return new Response('', { status: 429 })
        }
        await assert.rejects(fetchUsdQuote(), /unavailable/)
    } finally { globalThis.fetch = original }
})
