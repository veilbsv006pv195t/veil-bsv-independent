import { MAX_BACKUP_FILE_BYTES, fromBase64, toBase64 } from './backupCompression'
import type { WalletBackup } from './walletBackup'
const magic = new TextEncoder().encode('VEILBK3\n')
const format = 'veil-wallet-backup-v3-gzip-testnet'
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')

/** Fixed versioned header, 32-byte salt, 12-byte IV, then AES-GCM ciphertext/tag. */
export function encodeBackupFile(backup: WalletBackup): Uint8Array {
    if (backup.format !== format || backup.iterations !== 600_000 || !/^[0-9a-f]{64}$/.test(backup.salt) || !/^[0-9a-f]{24}$/.test(backup.iv)) throw new Error('Unsupported compact backup')
    const ciphertext = fromBase64(backup.ciphertext)
    if (ciphertext.length < 16 || ciphertext.length + 52 >= MAX_BACKUP_FILE_BYTES) throw new Error('Backup exceeds safe file size')
    const file = new Uint8Array(52 + ciphertext.length)
    file.set(magic)
    const header = backup.salt + backup.iv
    for (let i = 0; i < 44; i++) file[8 + i] = parseInt(header.slice(i * 2, i * 2 + 2), 16)
    file.set(ciphertext, 52)
    return file
}
export function decodeBackupFile(file: Uint8Array): WalletBackup {
    if (file.length >= MAX_BACKUP_FILE_BYTES) throw new Error('Backup exceeds safe file size')
    if (magic.every((b, i) => file[i] === b)) {
        if (file.length < 68) throw new Error('Truncated compact backup')
        return { format, iterations: 600_000, salt: hex(file.subarray(8, 40)), iv: hex(file.subarray(40, 52)), ciphertext: toBase64(file.subarray(52)) }
    }
    // Legacy v2 JSON and v3 JSON are both accepted; authentication is unchanged.
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(file)) as WalletBackup
}
