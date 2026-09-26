import { gzipBytes, toBase64, fromBase64, MAX_BACKUP_CLEAR_BYTES, MAX_BACKUP_FILE_BYTES } from './backupCompression'
const LEGACY_FORMAT = 'veil-wallet-backup-v2-testnet'
const FORMAT = 'veil-wallet-backup-v3-gzip-testnet'
const ITERATIONS = 600_000
const encoder = new TextEncoder()
const toHex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
function fromHex(value: string): Uint8Array {
    if (!value.length || value.length % 2 || /[^0-9a-f]/.test(value)) throw new Error('Invalid backup encoding')
    const bytes = new Uint8Array(value.length / 2)
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
    return bytes
}
export interface WalletBackup {
    format: typeof FORMAT | typeof LEGACY_FORMAT
    iterations: number
    salt: string
    iv: string
    ciphertext: string
}
async function key(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'])
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
export async function encryptBackup(payload: unknown, password: string): Promise<WalletBackup> {
    if (password.length < 24) throw new Error('Use a unique backup passphrase of at least 24 characters')
    const salt = crypto.getRandomValues(new Uint8Array(32))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const clear = encoder.encode(JSON.stringify(payload))
    let compressed: Uint8Array | undefined
    try {
        if (clear.length > MAX_BACKUP_CLEAR_BYTES) throw new Error('Backup exceeds safe size limit; keep this wallet tab open')
        compressed = await gzipBytes(clear)
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT) }, await key(password, salt), compressed)
        const envelope: WalletBackup = { format: FORMAT, iterations: ITERATIONS, salt: toHex(salt), iv: toHex(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) }
        if (ciphertext.byteLength + 52 >= MAX_BACKUP_FILE_BYTES) throw new Error('Encrypted backup exceeds import limit; keep this wallet tab open')
        return envelope
    } finally { clear.fill(0); compressed?.fill(0) }
}
export async function decryptBackup(envelope: WalletBackup, password: string): Promise<unknown> {
    if (!envelope || ![FORMAT, LEGACY_FORMAT].includes(envelope.format) || envelope.iterations !== ITERATIONS ||
        !/^[0-9a-f]{64}$/.test(envelope.salt) || !/^[0-9a-f]{24}$/.test(envelope.iv) ||
        typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > (envelope.format === FORMAT ? Math.ceil((MAX_BACKUP_FILE_BYTES - 52) / 3) * 4 : MAX_BACKUP_FILE_BYTES)) throw new Error('Unsupported encrypted wallet backup')
    let authenticated: ArrayBuffer
    try {
        authenticated = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(envelope.iv), additionalData: encoder.encode(envelope.format) }, await key(password, fromHex(envelope.salt)), envelope.format === LEGACY_FORMAT ? fromHex(envelope.ciphertext) : fromBase64(envelope.ciphertext))
    } catch { throw new Error('Backup password or authentication is invalid') }
    let clear: Uint8Array | undefined
    try {
        // Authenticate before decompression, and bound decompressed bytes.
        clear = envelope.format === FORMAT ? await gzipBytes(new Uint8Array(authenticated), true) : new Uint8Array(authenticated)
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clear))
    } finally { clear?.fill(0); new Uint8Array(authenticated).fill(0) }
}
