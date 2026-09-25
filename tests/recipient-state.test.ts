import assert from 'node:assert/strict'
import test from 'node:test'
import { createHash, PoolState, recipientOwner } from '../src/crypto'
import { assertMonotonic, decodeNote, encodeNote, restorePool, PoolSnapshot } from '../src/recipientState'
import { RECIPIENT_PROTOCOL } from '../src/recipient'
import { encryptBackup, decryptBackup } from '../src/walletBackup'

test('received note binds owner, amount, commitment, index, and unspent state', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash, true)
    const owner = recipientOwner(hash, 202n)
    const note = pool.build({ mode: 0, publicIn: 100n, outputs: [{ amount: 100n, ownerKey: owner, rho: 99n }] }).outputNotes[0]
    const encoded = encodeNote(note)
    assert.deepEqual(decodeNote(encoded, pool, owner, hash), note)
    assert.throws(() => decodeNote({ ...encoded, amount: '101' }, pool, owner, hash))
    assert.throws(() => decodeNote({ ...encoded, index: 1 }, pool, owner, hash))
    assert.throws(() => decodeNote(encoded, pool, recipientOwner(hash, 101n), hash))
    pool.build({ mode: 2, spend: { note, spendingKey: 202n }, publicOut: 100n, recipient: 1n, outputs: [] })
    assert.throws(() => decodeNote(encoded, pool, owner, hash), /spent/)
})

test('pool snapshots reject another protocol, malformed field encodings and rewritten history', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash, true)
    const owner = recipientOwner(hash, 101n)
    pool.build({ mode: 0, publicIn: 100n, outputs: [{ amount: 100n, ownerKey: owner, rho: 99n }] })
    const snapshot: PoolSnapshot = { protocol: RECIPIENT_PROTOCOL, poolId: '11'.repeat(32), rawPoolTx: '', previousPoolTxid: '22'.repeat(32), chain: Array(7).fill(''), nextIndex: pool.nextIndex, leaves: pool.noteTree.leaves.map(String), nullifiers: pool.nullifierTree.leaves.map(String) }
    const restored = restorePool(snapshot, hash)
    assertMonotonic(pool, restored)
    assert.throws(() => restorePool({ ...snapshot, protocol: 'legacy' as never }, hash))
    assert.throws(() => restorePool({ ...snapshot, nextIndex: 17 }, hash))
    assert.throws(() => restorePool({ ...snapshot, leaves: snapshot.leaves.map((v, i) => i === 0 ? '01' : v) }, hash))
    assert.throws(() => restorePool({ ...snapshot, nullifiers: snapshot.nullifiers.map((v, i) => i === 15 ? '1' : v) }, hash))
    restored.noteTree.set(0, 1n)
    assert.throws(() => assertMonotonic(pool, restored), /rewrites/)
    assert.throws(() => assertMonotonic(pool, new PoolState(hash, true)), /Stale/)
})

test('backup encrypts all secret payload and rejects weak passwords and tampering', async () => {
    const payload = { syntheticSecret: 'not a real key', notes: ['synthetic note'] }
    const password = 'synthetic test backup passphrase 2026'
    await assert.rejects(encryptBackup(payload, 'short'), /24/)
    const backup = await encryptBackup(payload, password)
    assert.ok(!JSON.stringify(backup).includes('syntheticSecret'))
    assert.deepEqual(await decryptBackup(backup, password), payload)
    await assert.rejects(decryptBackup(backup, 'wrong'), /authentication/)
    await assert.rejects(decryptBackup({ ...backup, iterations: 1 }, password), /Unsupported/)
    await assert.rejects(decryptBackup({ ...backup, iv: '00'.repeat(12) }, password), /authentication/)
})
