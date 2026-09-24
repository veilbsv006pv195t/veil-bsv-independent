import { bsv } from 'scrypt-ts'

export interface LiveWallet {
    format: 'veil-live-wallet-v1'
    network: 'testnet'
    address: string
    wif: string
    funding: {
        txid: string
        vout: number
        satoshis: number
    }
    createdAt: string
}

interface EncryptedWallet {
    format: 'veil-live-wallet-encrypted-v1'
    network: 'testnet'
    address: string
    funding: {
        txid: string
        vout: number
        satoshis: number
    }
    algorithm: 'AES-256-GCM'
    kdf: {
        name: 'PBKDF2-SHA-256'
        iterations: number
        salt: string
    }
    iv: string
    ciphertext: string
}

const WALLET_PATH = 'live-wallet/encrypted-wallet.json'
const MINIMUM_ITERATIONS = 600_000

function validFunding(value: unknown): value is LiveWallet['funding'] {
    if (!value || typeof value !== 'object') return false
    const funding = value as Partial<LiveWallet['funding']>
    return (
        /^[0-9a-f]{64}$/i.test(funding.txid ?? '') &&
        Number.isSafeInteger(funding.vout) &&
        (funding.vout as number) >= 0 &&
        Number.isSafeInteger(funding.satoshis) &&
        (funding.satoshis as number) > 0
    )
}

function fromBase64(value: string): Uint8Array {
    const binary = atob(value)
    return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function validateEnvelope(value: unknown): EncryptedWallet {
    if (!value || typeof value !== 'object') throw new Error('The encrypted wallet is invalid')
    const wallet = value as Partial<EncryptedWallet>
    if (
        wallet.format !== 'veil-live-wallet-encrypted-v1' ||
        wallet.network !== 'testnet' ||
        wallet.algorithm !== 'AES-256-GCM' ||
        wallet.kdf?.name !== 'PBKDF2-SHA-256' ||
        !Number.isSafeInteger(wallet.kdf.iterations) ||
        wallet.kdf.iterations < MINIMUM_ITERATIONS ||
        typeof wallet.kdf.salt !== 'string' ||
        typeof wallet.iv !== 'string' ||
        typeof wallet.ciphertext !== 'string' ||
        typeof wallet.address !== 'string' ||
        !validFunding(wallet.funding)
    ) throw new Error('The encrypted wallet uses an unsupported format')
    return wallet as EncryptedWallet
}

function validateWallet(
    value: unknown,
    publicAddress: string,
    publicFunding: LiveWallet['funding']
): LiveWallet {
    if (!value || typeof value !== 'object') throw new Error('The decrypted wallet is invalid')
    const wallet = value as Partial<LiveWallet>
    if (
        wallet.format !== 'veil-live-wallet-v1' ||
        wallet.network !== 'testnet' ||
        wallet.address !== publicAddress ||
        !validFunding(wallet.funding) ||
        wallet.funding.txid.toLowerCase() !== publicFunding.txid.toLowerCase() ||
        wallet.funding.vout !== publicFunding.vout ||
        wallet.funding.satoshis !== publicFunding.satoshis ||
        typeof wallet.wif !== 'string' ||
        typeof wallet.createdAt !== 'string'
    ) throw new Error('The decrypted wallet has an unsupported format')
    let key: bsv.PrivateKey
    try {
        key = bsv.PrivateKey.fromWIF(wallet.wif)
    } catch {
        throw new Error('The decrypted wallet does not contain a valid testnet key')
    }
    if (
        key.network.name !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) throw new Error('The decrypted key does not match the published testnet address')
    return wallet as LiveWallet
}

export async function unlockLiveWallet(password: string): Promise<LiveWallet> {
    if (!password) throw new Error('Enter the live-wallet password')
    const response = await fetch(new URL(WALLET_PATH, document.baseURI), { cache: 'no-store' })
    if (response.status === 404) throw new Error('The encrypted live wallet has not been published yet')
    if (!response.ok) throw new Error('The encrypted live wallet is unavailable')
    if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('The encrypted live wallet has not been published yet')
    }
    let payload: unknown
    try {
        payload = await response.json()
    } catch {
        throw new Error('The encrypted live wallet is unreadable')
    }
    const envelope = validateEnvelope(payload)
    const material = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    )
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: fromBase64(envelope.kdf.salt),
            iterations: envelope.kdf.iterations,
            hash: 'SHA-256',
        },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    )
    let cleartext: ArrayBuffer
    try {
        cleartext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: fromBase64(envelope.iv) },
            key,
            fromBase64(envelope.ciphertext)
        )
    } catch {
        throw new Error('That password did not unlock the live wallet')
    }
    return validateWallet(
        JSON.parse(new TextDecoder().decode(cleartext)),
        envelope.address,
        envelope.funding
    )
}
