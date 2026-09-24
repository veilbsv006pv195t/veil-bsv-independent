import {
    chmodSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { bsv } from 'scrypt-ts'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')

export interface TestnetWalletFile {
    network: 'testnet'
    address: string
    wif: string
}

function validateWallet(value: unknown): TestnetWalletFile {
    const wallet = value as Partial<TestnetWalletFile>
    if (
        wallet.network !== 'testnet' ||
        typeof wallet.address !== 'string' ||
        typeof wallet.wif !== 'string'
    ) {
        throw new Error('Invalid testnet wallet record')
    }
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (
        key.network.name !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) {
        throw new Error('Wallet key/address mismatch or non-testnet key')
    }
    return wallet as TestnetWalletFile
}

export function createTestnetWallet(walletFile = WALLET_FILE): TestnetWalletFile {
    if (existsSync(walletFile)) {
        throw new Error('A testnet wallet already exists; refusing to replace it')
    }
    const privateDir = path.dirname(walletFile)
    mkdirSync(privateDir, { recursive: true, mode: 0o700 })
    chmodSync(privateDir, 0o700)
    const key = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
    const wallet: TestnetWalletFile = {
        network: 'testnet',
        address: key.toAddress(bsv.Networks.testnet).toString(),
        wif: key.toWIF(),
    }
    writeFileSync(walletFile, `${JSON.stringify(wallet, null, 2)}\n`, {
        flag: 'wx',
        mode: 0o600,
    })
    chmodSync(walletFile, 0o600)
    return validateWallet(JSON.parse(readFileSync(walletFile, 'utf8')))
}

export function readTestnetWallet(walletFile = WALLET_FILE): TestnetWalletFile {
    return validateWallet(JSON.parse(readFileSync(walletFile, 'utf8')))
}

function publicSummary(wallet: TestnetWalletFile): Record<string, unknown> {
    return {
        network: wallet.network,
        address: wallet.address,
        walletFile: '.private/testnet-deployment-wallet.json',
        privateKeyPrinted: false,
    }
}

function main(): void {
    const command = process.argv[2]
    if (command === 'init') {
        const wallet = createTestnetWallet()
        console.log(JSON.stringify(publicSummary(wallet), null, 2))
        console.log('Fund only this testnet address. The private key was not printed.')
        return
    }
    if (command === 'status') {
        if (!existsSync(WALLET_FILE)) {
            console.log(JSON.stringify({
                network: 'testnet',
                initialized: false,
                walletFile: '.private/testnet-deployment-wallet.json',
            }, null, 2))
            return
        }
        console.log(JSON.stringify({
            ...publicSummary(readTestnetWallet()),
            initialized: true,
        }, null, 2))
        return
    }
    throw new Error('Usage: testnet-wallet.ts init|status')
}

if (require.main === module) {
    try {
        main()
    } catch (error: unknown) {
        console.error(error instanceof Error ? error.message : error)
        process.exitCode = 1
    }
}
