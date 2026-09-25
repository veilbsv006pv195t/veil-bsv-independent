import { test } from 'node:test'
import assert from 'node:assert/strict'
import { GuidedDemo, GUIDED_FORMAT } from '../ui/src/guided-demo'
import { createReceivingWallet } from '../ui/src/live-wallet'
import type { PreparedLiveAction } from '../ui/src/live-builder'
import { encryptBackup, decryptBackup } from '../src/walletBackup'

const progress = () => {}
const txid = 'ab'.repeat(32)
test('combined encrypted backup restores both distinct identities, without rotation', async () => {
    const pair = await GuidedDemo.create(createReceivingWallet())
    assert.notEqual(pair.slots.sender.address, pair.slots.recipient.address)
    assert.equal(pair.defaultRecipient(), pair.slots.recipient.address)
    pair.active = 'recipient'
    assert.equal(pair.defaultRecipient(), pair.slots.sender.address)
    const passphrase = 'synthetic guided backup password only 12345'
    const file = await encryptBackup(pair.backupPayload(), passphrase)
    const restored = await GuidedDemo.restore(await decryptBackup(file, passphrase), progress)
    assert.equal(restored.active, 'recipient')
    assert.equal(restored.slots.sender.address, pair.slots.sender.address)
    assert.equal(restored.slots.recipient.address, pair.slots.recipient.address)
    assert.equal((restored.backupPayload() as any).format, GUIDED_FORMAT)
    await assert.rejects(decryptBackup(file, 'incorrect'), /authentication/)
    const malformed = pair.backupPayload() as any
    malformed.data.active = 'other'
    await assert.rejects(GuidedDemo.restore(malformed, progress), /Invalid/)
    assert.throws(() => new GuidedDemo({ sender: pair.slots.sender, recipient: pair.slots.sender }), /distinct/)
})
test('handoff waits for mining, preserves retry state, and never imports external payments', async () => {
    const pair = await GuidedDemo.create(createReceivingWallet())
    const snapshot = { fixture: true } as any
    const payment = { recipient: pair.slots.recipient.address } as any
    let imports = 0
    let fail = false
    pair.slots.recipient.session = {
        backupPayload: () => ({}),
        importPayment: async (actual: unknown) => { if (fail) throw new Error('temporary read failure'); assert.equal(actual, payment); imports++ },
        importPoolSnapshot: async (actual: unknown) => { assert.equal(actual, snapshot); imports++ },
    } as any
    const plan = { transactions: [{ txid }], snapshot, payment } as PreparedLiveAction
    pair.accepted(plan)
    assert.throws(() => pair.assertReady(), /Wait for mining/)
    assert.equal(await pair.poll(progress, async () => ({ txid, txStatus: 'SEEN_ON_NETWORK' })), false)
    assert.equal(imports, 0)
    await assert.rejects(pair.poll(progress, async () => null), /not found/)
    await assert.rejects(pair.poll(progress, async () => ({ txid, txStatus: 'REJECTED' })), /REJECTED/)
    assert.ok(pair.pending)
    fail = true
    await assert.rejects(pair.poll(progress, async () => ({ txid, txStatus: 'MINED' })), /temporary/)
    assert.ok(pair.pending)
    fail = false
    assert.equal(await pair.poll(progress, async () => ({ txid, txStatus: 'MINED' })), true)
    assert.equal(imports, 1)
    assert.equal(pair.pending, null)
    assert.equal(await pair.poll(progress), false)
    pair.assertReady()
    pair.accepted({ ...plan, payment: { recipient: 'external-recipient' } as any })
    assert.equal((pair.backupPayload() as any).data.pending.payment, undefined)
    await pair.poll(progress, async () => ({ txid, txStatus: 'MINED' }))
    assert.equal(imports, 2, 'external send synchronizes the pool only')
})
