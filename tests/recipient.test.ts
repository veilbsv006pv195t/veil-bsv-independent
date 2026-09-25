import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { bsv } from 'scrypt-ts'
import { wtns } from 'snarkjs'
import { createHash, PoolState, recipientOwner, RECIPIENT_KEY_DOMAIN } from '../src/crypto'
import { decryptPayment, encryptPayment, parseRecipientAddress, recipientIdentity } from '../src/recipient'

// Synthetic, unfunded test identities. Never use these for real wallets.
const aliceWif = bsv.PrivateKey.fromHex('01'.padStart(64, '0'), bsv.Networks.testnet).toWIF()
const bobWif = bsv.PrivateKey.fromHex('02'.padStart(64, '0'), bsv.Networks.testnet).toWIF()
const WASM = path.resolve('build/recipient/shielded_pool_js/shielded_pool.wasm')
const R1CS = path.resolve('build/recipient/shielded_pool.r1cs')

test('ownership uses a secret MiMC key, not an invertible public-key permutation', async () => {
    const hash = await createHash()
    assert.equal(recipientOwner(hash, 202n), hash(RECIPIENT_KEY_DOMAIN, 202n))
    assert.notEqual(recipientOwner(hash, 202n), hash(202n, RECIPIENT_KEY_DOMAIN))
})

test('recipient addresses are versioned, canonical, checksummed and independent', async () => {
    const hash = await createHash()
    const alice = recipientIdentity(aliceWif, hash)
    const bob = recipientIdentity(bobWif, hash)
    assert.notEqual(alice.address, bob.address)
    assert.equal(parseRecipientAddress(bob.address).owner, bob.owner)
    assert.throws(() => parseRecipientAddress(bob.address.replace('veilt2', 'veilm2')))
    assert.throws(() => parseRecipientAddress(bob.address.slice(0, -1) + (bob.address.endsWith('0') ? '1' : '0')))
    assert.throws(() => parseRecipientAddress(bob.address.toUpperCase()))
    assert.throws(() => recipientIdentity(bsv.PrivateKey.fromHex('03'.padStart(64, '0'), bsv.Networks.mainnet).toWIF(), hash))
})

test('payment handoff decrypts only for the intended wallet and authenticates metadata', async () => {
    const hash = await createHash()
    const bob = recipientIdentity(bobWif, hash)
    const payload = { amount: '600', rho: '20001', index: 1 }
    const envelope = await encryptPayment(bob.address, payload)
    assert.deepEqual(await decryptPayment(envelope, bobWif, hash), payload)
    await assert.rejects(decryptPayment(envelope, aliceWif, hash), /different wallet/)
    await assert.rejects(decryptPayment({ ...envelope, iv: '00'.repeat(12) }, bobWif, hash), /authentication/)
    await assert.rejects(decryptPayment({ ...envelope, protocol: 'mainnet' as never }, bobWif, hash), /format/)
    const second = await encryptPayment(bob.address, payload)
    assert.notEqual(envelope.ciphertext, second.ciphertext)
    assert.notEqual(envelope.ephemeralKey, second.ephemeralKey)
})

test('two-wallet circuit: Alice shields, sends to Bob; only Bob can withdraw', async () => {
    const hash = await createHash()
    const alice = recipientIdentity(aliceWif, hash)
    const bob = recipientIdentity(bobWif, hash)
    const pool = new PoolState(hash, true)
    const deposit = pool.build({ mode: 0, publicIn: 1000n, outputs: [{ amount: 1000n, ownerKey: alice.owner, rho: 10001n }] })
    const send = pool.build({
        mode: 1, spend: { note: deposit.outputNotes[0], spendingKey: alice.spendingKey },
        outputs: [{ amount: 600n, ownerKey: bob.owner, rho: 20001n }, { amount: 400n, ownerKey: alice.owner, rho: 20002n }],
    })
    const received = send.outputNotes[0]
    // Sender knows every plaintext field of this note, but not Bob's spending key.
    assert.throws(() => pool.build({ mode: 2, spend: { note: received, spendingKey: alice.spendingKey }, publicOut: 600n, recipient: 1n, outputs: [] }), /does not own/)
    assert.throws(() => pool.build({ mode: 2, spend: { note: received }, publicOut: 600n, recipient: 1n, outputs: [] }), /does not own/)
    const withdraw = pool.build({ mode: 2, spend: { note: received, spendingKey: bob.spendingKey }, publicOut: 600n, recipient: (1n << 160n) - 1n, outputs: [] })
    const directory = await mkdtemp(path.join(tmpdir(), 'veil-recipient-test-'))
    try {
        for (const [name, built] of [['shield', deposit], ['send', send], ['withdraw', withdraw]] as const) {
            const witness = path.join(directory, `${name}.wtns`)
            await wtns.calculate(built.circuitInput, WASM, witness)
            assert.equal(await wtns.check(R1CS, witness), true)
        }
        // Bypass host checks: the circuit itself must reject sender/zero/public-key possession.
        const calculator = await require('../build/recipient/shielded_pool_js/witness_calculator.js')(await readFile(WASM))
        for (const bad of [alice.spendingKey, 0n, bob.owner]) {
            await assert.rejects(calculator.calculateWitness({ ...withdraw.circuitInput, inputSpendingKey: bad.toString() }, true))
        }
    } finally { await rm(directory, { recursive: true, force: true }) }
})
