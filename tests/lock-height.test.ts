import test from 'node:test'
import assert from 'node:assert/strict'
import { HeightTracker, resolveLockHeight, lockHeightLabel } from '../ui/src/lock-height'

test('relative and absolute heights have explicit syntax and the requested review label', () => {
    const tip = 1_759_965
    assert.equal(resolveLockHeight('+3', tip), 1_759_968)
    assert.equal(resolveLockHeight('1,759,968', tip), 1_759_968)
    assert.equal(resolveLockHeight(1_759_968, tip), 1_759_968)
    assert.equal(lockHeightLabel(1_759_968, tip), '1,759,968 (+3)')
    assert.equal(resolveLockHeight(' +1,000 ', tip), tip + 1_000)
    assert.equal(lockHeightLabel(tip + 1_000, tip), '1,760,965 (+1,000)')
})

test('past absolute targets never become offsets; zero, malformed, timestamp and overflowing inputs fail closed', () => {
    for (const input of ['3', '1759962', '1759965', '+0', '0', '-3', '3.5', '+3x', '1e6', '1,75,9968', '++3', '', '500000000', '+500000000', '+9007199254740992']) {
        assert.throws(() => resolveLockHeight(input, 1_759_965), undefined, input)
    }
    assert.throws(() => resolveLockHeight('+3', 0), /unavailable/)
    assert.equal(resolveLockHeight('499999999', 1_759_965), 499_999_999)
})

test('target resolved at preparation stays fixed even if the tip advances during review', () => {
    const target = resolveLockHeight('+3', 1_759_965)
    assert.equal(target, 1_759_968)
    assert.equal(lockHeightLabel(target, 1_759_965), '1,759,968 (+3)')
    assert.equal(resolveLockHeight('+3', 1_759_966), 1_759_969)
    assert.throws(() => resolveLockHeight('1759968', 1_759_968), /above/)
})

test('height starts unknown, shares in-flight requests, refreshes, and clears on failures', async () => {
    let calls = 0, notifications = 0
    let settle!: (value: number) => void
    const tracker = new HeightTracker(() => { calls++; return new Promise(resolve => { settle = resolve }) }, () => notifications++)
    assert.equal(tracker.height, null)
    const first = tracker.refresh()
    assert.equal(tracker.loading, true)
    assert.equal(tracker.height, null)
    assert.equal(tracker.refresh(), first)
    await Promise.resolve()
    settle(1_759_965)
    assert.equal(await first, 1_759_965)
    assert.equal(tracker.height, 1_759_965)
    assert.equal(tracker.loading, false)
    assert.ok(tracker.checkedAt)
    const next = tracker.refresh()
    assert.equal(tracker.height, null)
    await Promise.resolve()
    settle(0)
    assert.equal(await next, null)
    assert.equal(tracker.checkedAt, null)
    assert.equal(calls, 2)
    assert.equal(notifications, 4)
    const broken = new HeightTracker(async () => { throw new Error('offline') })
    await assert.rejects(broken.requireFresh(), /unavailable/)
    assert.equal(broken.loading, false)
    assert.equal(broken.height, null)
})
