import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { bsv } from 'scrypt-ts'

interface WalletFile {
    network: 'testnet'
    address: string
    wif: string
    funding: {
        txid: string
        vout: number
        satoshis: number
    }
}

const ITERATIONS = 600_000
const ROOT = path.resolve(__dirname, '..')
const DEFAULT_INPUT = path.join(ROOT, '.private', 'live-demo-wallet.json')
const DEFAULT_OUTPUT = path.join(ROOT, 'ui', 'public', 'live-wallet', 'encrypted-wallet.json')

function validate(value: unknown): WalletFile {
    if (!value || typeof value !== 'object') throw new Error('Wallet file must be an object')
    const wallet = value as Partial<WalletFile>
    if (
        wallet.network !== 'testnet' ||
        typeof wallet.address !== 'string' ||
        typeof wallet.wif !== 'string' ||
        !wallet.funding ||
        !/^[0-9a-f]{64}$/i.test(wallet.funding.txid ?? '') ||
        !Number.isSafeInteger(wallet.funding.vout) ||
        wallet.funding.vout < 0 ||
        !Number.isSafeInteger(wallet.funding.satoshis) ||
        wallet.funding.satoshis <= 0
    ) {
        throw new Error('Wallet file must contain a testnet address, WIF, and public funding outpoint')
    }
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (
        key.network.name !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) throw new Error('Wallet key/address mismatch or non-testnet key')
    return wallet as WalletFile
}

async function hidden(prompt: string): Promise<string> {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error('Run interactively so the password is never recorded in shell history')
    }
    process.stdout.write(prompt)
    process.stdin.setRawMode(true)
    process.stdin.resume()
    process.stdin.setEncoding('utf8')
    let value = ''
    return new Promise((resolve, reject) => {
        const cleanup = (): void => {
            process.stdin.off('data', onData)
            process.stdin.setRawMode(false)
            process.stdin.pause()
        }
        const onData = (characters: string): void => {
            for (const character of characters) {
                if (character === '\u0003') {
                    cleanup()
                    reject(new Error('Cancelled'))
                    return
                }
                if (character === '\r' || character === '\n') {
                    cleanup()
                    process.stdout.write('\n')
                    resolve(value)
                    return
                }
                if (character === '\u007f') {
                    value = value.slice(0, -1)
                } else {
                    value += character
                }
            }
        }
        process.stdin.on('data', onData)
    })
}

async function main(): Promise<void> {
    const input = path.resolve(process.argv[2] ?? DEFAULT_INPUT)
    const output = path.resolve(process.argv[3] ?? DEFAULT_OUTPUT)
    const source = validate(JSON.parse(readFileSync(input, 'utf8')))
    const password = await hidden('New live-wallet password: ')
    if (password.length < 24) throw new Error('Use at least 24 characters of high-entropy text')
    const confirmation = await hidden('Repeat live-wallet password: ')
    if (password !== confirmation) throw new Error('Passwords do not match')

    const cleartext = Buffer.from(JSON.stringify({
        format: 'veil-live-wallet-v1',
        network: 'testnet',
        address: source.address,
        wif: source.wif,
        funding: source.funding,
        createdAt: new Date().toISOString(),
    }))
    const salt = randomBytes(32)
    const iv = randomBytes(12)
    const key = pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256')
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([cipher.update(cleartext), cipher.final(), cipher.getAuthTag()])
    cleartext.fill(0)
    key.fill(0)

    const envelope = {
        format: 'veil-live-wallet-encrypted-v1',
        network: 'testnet',
        address: source.address,
        funding: source.funding,
        algorithm: 'AES-256-GCM',
        kdf: { name: 'PBKDF2-SHA-256', iterations: ITERATIONS, salt: salt.toString('base64') },
        iv: iv.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
    }
    mkdirSync(path.dirname(output), { recursive: true })
    writeFileSync(output, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o644 })
    chmodSync(output, 0o644)
    console.log(`Encrypted the disposable testnet wallet for ${source.address}.`)
    console.log('The password and plaintext WIF were not written to the public package.')
}

void main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
})
