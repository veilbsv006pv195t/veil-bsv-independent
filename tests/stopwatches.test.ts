import test from 'node:test'
import assert from 'node:assert/strict'
import { Stopwatches, elapsed } from '../ui/src/stopwatches'
test('independent operation and phase stopwatches include review, retry and mining without double counting', () => {
    let now = 0
    const timers = new Stopwatches(() => now)
    const action = timers.start('Send', 'Proof')
    now = 61_000; timers.phase(action, 'Review')
    now = 70_000; timers.phase(action, 'Broadcast')
    now = 80_000; timers.phase(action, 'Retry wait')
    now = 90_000; timers.phase(action, 'Broadcast')
    now = 100_000; timers.phase(action, 'Mining')
    const backup = timers.start('Two-wallet backup')
    now = 105_000; timers.finish(backup, 'Download offered')
    now = 120_000; timers.finish(action, 'Mined')
    timers.finish(action, 'Should not overwrite')
    const snapshot = timers.snapshot()
    assert.equal(snapshot.operations[0].elapsedMs, 120_000)
    assert.equal(snapshot.operations[0].outcome, 'Mined')
    assert.equal(snapshot.operations[0].phases.reduce((n, p) => n + p.elapsedMs, 0), 120_000)
    assert.equal(snapshot.operations[1].elapsedMs, 5000)
    assert.equal(elapsed(3_661_000), '01:01:01')
    timers.stopOverall(); now = 130_000
    assert.equal(timers.overallMs(), 120_000)
    timers.resetOverall(); now = 131_000
    assert.equal(timers.overallMs(), 1000)
})
