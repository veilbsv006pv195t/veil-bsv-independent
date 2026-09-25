import { bsv } from 'scrypt-ts'
import { sha256 } from '@noble/hashes/sha256'
import { FIELD, HashFn, recipientOwner } from './crypto'

export const RECIPIENT_PROTOCOL = 'veil-recipient-v2-testnet'
const PREFIX = 'veilt2'
const utf8 = new TextEncoder()
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
function bytes(value: string): Uint8Array {
    if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error('Non-canonical hexadecimal encoding')
    return Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16))
}
function testnetKey(wif: string): bsv.PrivateKey {
    const key = bsv.PrivateKey.fromWIF(wif)
    if (key.network.name !== 'testnet') throw new Error('Only disposable testnet wallets are supported')
    return key
}
function encryptionPrivateKey(wif: string): bsv.PrivateKey {
    const seed = new Uint8Array([...utf8.encode(`${RECIPIENT_PROTOCOL}:encrypt:`), ...testnetKey(wif).toBuffer()])
    const n = BigInt('0x' + bsv.crypto.Point.getN().toString(16))
    const scalar = BigInt('0x' + hex(sha256(seed))) % (n - 1n) + 1n
    seed.fill(0)
    return bsv.PrivateKey.fromHex(scalar.toString(16).padStart(64, '0'), bsv.Networks.testnet)
}
function publicKey(encoded: string): bsv.PublicKey {
    if (!/^(02|03)[0-9a-f]{64}$/.test(encoded)) throw new Error('Invalid compressed encryption key')
    const key = bsv.PublicKey.fromString(encoded)
    key.point.validate()
    if (key.toString() !== encoded) throw new Error('Non-canonical encryption key')
    return key
}

export function recipientIdentity(wif: string, hash: HashFn) {
    const key = testnetKey(wif)
    // Domain separated from transaction signing and encryption. Never exported
    // in a receiving address or payment file.
    const seed = new Uint8Array([...utf8.encode(`${RECIPIENT_PROTOCOL}:spend:`), ...key.toBuffer()])
    const spendingKey = BigInt('0x' + hex(sha256(seed))) % (FIELD - 1n) + 1n
    seed.fill(0)
    const owner = recipientOwner(hash, spendingKey)
    const encryptionKey = new bsv.PublicKey(encryptionPrivateKey(wif).publicKey.point, { compressed: true }).toString()
    const payload = owner.toString(16).padStart(64, '0') + encryptionKey
    const checksum = hex(sha256(utf8.encode(PREFIX + payload))).slice(0, 8)
    return { spendingKey, owner, address: PREFIX + payload + checksum }
}

export function parseRecipientAddress(address: string): { owner: bigint; encryptionKey: string } {
    if (typeof address !== 'string' || !/^veilt2[0-9a-f]{138}$/.test(address)) {
        throw new Error('Enter a complete Veil v2 testnet receiving address')
    }
    const payload = address.slice(PREFIX.length, -8)
    if (hex(sha256(utf8.encode(PREFIX + payload))).slice(0, 8) !== address.slice(-8)) {
        throw new Error('Veil address checksum mismatch')
    }
    const owner = BigInt('0x' + payload.slice(0, 64))
    if (owner <= 0n || owner >= FIELD) throw new Error('Invalid recipient owner identifier')
    const encryptionKey = payload.slice(64)
    publicKey(encryptionKey)
    return { owner, encryptionKey }
}

export interface EncryptedPayment {
    protocol: typeof RECIPIENT_PROTOCOL
    recipient: string
    ephemeralKey: string
    salt: string
    iv: string
    ciphertext: string
}
async function paymentKey(privateKey: bsv.PrivateKey, peer: string, salt: Uint8Array): Promise<CryptoKey> {
    const shared = publicKey(peer).point.mul(privateKey.toBigNumber())
    const secret = bytes(shared.getX().toString(16).padStart(64, '0'))
    const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
    secret.fill(0)
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: utf8.encode(RECIPIENT_PROTOCOL) },
        material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
}
function aad(value: Omit<EncryptedPayment, 'ciphertext'>): Uint8Array {
    return utf8.encode(JSON.stringify([value.protocol, value.recipient, value.ephemeralKey, value.salt, value.iv]))
}
export async function encryptPayment(recipient: string, payload: unknown): Promise<EncryptedPayment> {
    const destination = parseRecipientAddress(recipient)
    const ephemeral = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
    const salt = crypto.getRandomValues(new Uint8Array(32))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const header: Omit<EncryptedPayment, 'ciphertext'> = {
        protocol: RECIPIENT_PROTOCOL, recipient,
        ephemeralKey: new bsv.PublicKey(ephemeral.publicKey.point, { compressed: true }).toString(),
        salt: hex(salt), iv: hex(iv),
    }
    const key = await paymentKey(ephemeral, destination.encryptionKey, salt)
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad(header) }, key, utf8.encode(JSON.stringify(payload))
    )
    return { ...header, ciphertext: hex(new Uint8Array(ciphertext)) }
}
export async function decryptPayment(envelope: EncryptedPayment, wif: string, hash: HashFn): Promise<unknown> {
    if (!envelope || envelope.protocol !== RECIPIENT_PROTOCOL ||
        !/^[0-9a-f]{64}$/.test(envelope.salt) || !/^[0-9a-f]{24}$/.test(envelope.iv) ||
        typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > 32_000_000) {
        throw new Error('Invalid encrypted payment format')
    }
    parseRecipientAddress(envelope.recipient)
    if (recipientIdentity(wif, hash).address !== envelope.recipient) throw new Error('Payment belongs to a different wallet')
    const key = await paymentKey(encryptionPrivateKey(wif), envelope.ephemeralKey, bytes(envelope.salt))
    let clear: ArrayBuffer
    try {
        clear = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: bytes(envelope.iv), additionalData: aad(envelope) }, key, bytes(envelope.ciphertext)
        )
    } catch { throw new Error('Payment authentication failed') }
    try { return JSON.parse(new TextDecoder().decode(clear)) }
    finally { new Uint8Array(clear).fill(0) }
}
