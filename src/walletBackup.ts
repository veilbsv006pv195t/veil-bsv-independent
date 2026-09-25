const FORMAT = 'veil-wallet-backup-v2-testnet'
const ITERATIONS = 600_000
const encoder = new TextEncoder()
const toHex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
function fromHex(value: string): Uint8Array {
    if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error('Invalid backup encoding')
    return Uint8Array.from(value.match(/../g)!, v => parseInt(v, 16))
}
export interface WalletBackup {
    format: typeof FORMAT
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
    try {
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT) }, await key(password, salt), clear)
        return { format: FORMAT, iterations: ITERATIONS, salt: toHex(salt), iv: toHex(iv), ciphertext: toHex(new Uint8Array(ciphertext)) }
    } finally { clear.fill(0) }
}
export async function decryptBackup(envelope: WalletBackup, password: string): Promise<unknown> {
    if (!envelope || envelope.format !== FORMAT || envelope.iterations !== ITERATIONS ||
        !/^[0-9a-f]{64}$/.test(envelope.salt) || !/^[0-9a-f]{24}$/.test(envelope.iv) ||
        typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > 64_000_000) throw new Error('Unsupported encrypted wallet backup')
    let clear: ArrayBuffer
    try {
        clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(envelope.iv), additionalData: encoder.encode(FORMAT) }, await key(password, fromHex(envelope.salt)), fromHex(envelope.ciphertext))
    } catch { throw new Error('Backup password or authentication is invalid') }
    try { return JSON.parse(new TextDecoder().decode(clear)) }
    finally { new Uint8Array(clear).fill(0) }
}
