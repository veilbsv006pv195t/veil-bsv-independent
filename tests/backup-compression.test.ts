import test from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, pbkdf2Sync } from 'node:crypto'
import { gzipBytes, fromBase64 } from '../src/backupCompression'
import { encryptBackup, decryptBackup, type WalletBackup } from '../src/walletBackup'
import { encodeBackupFile, decodeBackupFile } from '../src/backupFile'

const password = 'synthetic compression test passphrase 2026'
test('compact backup round-trips substantial repetitive transaction data', async () => {
    const payload = { notes: ['synthetic only'], transactionHex: '76a914'.repeat(500_000) }
    const oldBytes = JSON.stringify(payload).length * 2
    const backup = await encryptBackup(payload, password)
    assert.equal(backup.format, 'veil-wallet-backup-v3-gzip-testnet')
    assert.ok(JSON.stringify(backup).length < oldBytes / 100)
    assert.deepEqual(await decryptBackup(backup, password), payload)
    const binary = encodeBackupFile(backup)
    assert.ok(binary.length < JSON.stringify(backup).length)
    assert.deepEqual(await decryptBackup(decodeBackupFile(binary), password), payload)
    const corrupt = binary.slice(); corrupt[corrupt.length - 1] ^= 1
    await assert.rejects(decryptBackup(decodeBackupFile(corrupt), password), /authentication/)
    assert.throws(() => decodeBackupFile(binary.slice(0, 53)), /Truncated/)
    await assert.rejects(decryptBackup({ ...backup, format: 'veil-wallet-backup-v2-testnet' }, password), /authentication/)
    await assert.rejects(decryptBackup({ ...backup, ciphertext: backup.ciphertext.slice(0, -4) }, password), /authentication/)
    assert.throws(() => fromBase64('!!!!'))
})
test('legacy v2 hex backups remain readable, without requiring recompression', async () => {
    const payload = { wallet: 'synthetic legacy wallet', notes: ['synthetic legacy note'] }
    const salt = Buffer.alloc(32, 7), iv = Buffer.alloc(12, 9)
    const format = 'veil-wallet-backup-v2-testnet'
    const key = pbkdf2Sync(password, salt, 600_000, 32, 'sha256')
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(Buffer.from(format))
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final(), cipher.getAuthTag()]).toString('hex')
    const backup: WalletBackup = { format, salt: salt.toString('hex'), iv: iv.toString('hex'), iterations: 600_000, ciphertext }
    assert.deepEqual(await decryptBackup(backup, password), payload)
    assert.deepEqual(await decryptBackup(decodeBackupFile(new TextEncoder().encode(JSON.stringify(backup))), password), payload)
})
test('decompression stops at the bound and malformed gzip is rejected', async () => {
    const compressed = await gzipBytes(new Uint8Array(100_000))
    await assert.rejects(gzipBytes(compressed, true, 1024), /limit/)
    await assert.rejects(gzipBytes(new Uint8Array([1, 2, 3]), true))
    await assert.rejects(gzipBytes(compressed.slice(0, -5), true))
})
