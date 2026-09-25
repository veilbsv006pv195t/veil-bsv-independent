import assert from 'node:assert/strict'
import test from 'node:test'
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { bsv } from 'scrypt-ts'
import { createReceivingWallet, unlockLiveWallet } from '../ui/src/live-wallet'

test('published encrypted wallet checks funding locally and against read-only mined status', async () => {
    const wallet = createReceivingWallet()
    const funding = new bsv.Transaction().from({
        txId: '11'.repeat(32), outputIndex: 0,
        script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(), satoshis: 101000,
    }).to(wallet.address, 100000)
    funding.sign(bsv.PrivateKey.fromWIF(wallet.wif))
    wallet.funding = { txid: funding.id, vout: 0, satoshis: 100000 }
    const password = 'synthetic test password for wallet 2026'
    const salt = randomBytes(32), iv = randomBytes(12)
    const key = pbkdf2Sync(password, salt, 600000, 32, 'sha256')
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(wallet)), cipher.final(), cipher.getAuthTag()])
    const envelope = {
        format: 'veil-live-wallet-encrypted-v1', network: 'testnet', address: wallet.address,
        funding: wallet.funding, algorithm: 'AES-256-GCM',
        kdf: { name: 'PBKDF2-SHA-256', iterations: 600000, salt: salt.toString('base64') },
        iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), fundingTransaction: funding.toString(),
    }
    const oldFetch = globalThis.fetch
    const oldDocument = Object.getOwnPropertyDescriptor(globalThis, 'document')
    Object.defineProperty(globalThis, 'document', { configurable: true, value: { baseURI: 'https://veil.invalid/v0.3.0/' } })
    let served: Record<string, unknown> = envelope
    let status = 'MINED'
    let statusCalls = 0
    globalThis.fetch = async (input, init) => {
        assert.ok(!init?.method || init.method === 'GET', 'Unlock must never broadcast')
        const url = String(input)
        if (url === 'https://veil.invalid/v0.3.0/live-wallet/encrypted-wallet.json') return Response.json(served)
        if (url.startsWith('https://testnet.arc.gorillapool.io/v1/tx/')) {
            statusCalls++
            return Response.json({ txid: url.split('/').at(-1), txStatus: status })
        }
        throw new Error('Unexpected request in offline unlock test')
    }
    try {
        const unlocked = await unlockLiveWallet(password)
        assert.equal(unlocked.fundingChecked, true)
        assert.deepEqual(unlocked.wallet.funding, wallet.funding)
        assert.equal(unlocked.wallet.address, wallet.address)
        const beforeWrongPassword = statusCalls
        await assert.rejects(unlockLiveWallet('wrong password'), /did not unlock/)
        assert.equal(statusCalls, beforeWrongPassword)
        status = 'SEEN_ON_NETWORK'
        await assert.rejects(unlockLiveWallet(password), /Wait for funding to be mined/)
        status = 'MINED'
        served = { ...envelope, fundingTransaction: undefined }
        assert.equal((await unlockLiveWallet(password)).fundingChecked, false)
        served = { ...envelope, funding: { ...wallet.funding, satoshis: 99999 } }
        await assert.rejects(unlockLiveWallet(password), /unsupported format/)
        const other = createReceivingWallet()
        const wrongRecipient = new bsv.Transaction(funding.toString())
        wrongRecipient.outputs[0].setScript(bsv.Script.buildPublicKeyHashOut(other.address))
        served = { ...envelope, fundingTransaction: wrongRecipient.toString() }
        await assert.rejects(unlockLiveWallet(password), /not owned by this wallet/)
        const wrongTx = new bsv.Transaction(funding.toString())
        wrongTx.nLockTime = 1
        served = { ...envelope, fundingTransaction: wrongTx.toString() }
        await assert.rejects(unlockLiveWallet(password), /does not match the encrypted wallet/)
        served = { ...envelope, fundingTransaction: 'not hex' }
        await assert.rejects(unlockLiveWallet(password), /unsupported format/)
    } finally {
        globalThis.fetch = oldFetch
        if (oldDocument) Object.defineProperty(globalThis, 'document', oldDocument)
        else Reflect.deleteProperty(globalThis, 'document')
        key.fill(0)
    }
})
