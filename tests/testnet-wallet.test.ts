import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { bsv } from 'scrypt-ts'
import {
    createTestnetWallet,
    readTestnetWallet,
} from '../scripts/testnet-wallet'

test('creates a protected testnet-only wallet without overwriting it', () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'veil-wallet-'))
    const walletFile = path.join(directory, 'private', 'wallet.json')
    try {
        const wallet = createTestnetWallet(walletFile)
        assert.equal(wallet.network, 'testnet')
        assert.equal(
            bsv.PrivateKey.fromWIF(wallet.wif)
                .toAddress(bsv.Networks.testnet)
                .toString(),
            wallet.address
        )
        assert.deepEqual(readTestnetWallet(walletFile), wallet)
        assert.equal(statSync(path.dirname(walletFile)).mode & 0o777, 0o700)
        assert.equal(statSync(walletFile).mode & 0o777, 0o600)
        assert.equal(JSON.parse(readFileSync(walletFile, 'utf8')).network, 'testnet')
        assert.throws(
            () => createTestnetWallet(walletFile),
            /refusing to replace/
        )
    } finally {
        rmSync(directory, { recursive: true, force: true })
    }
})
