#!/usr/bin/env node
'use strict'

// Test only the miner's per-script size policy, not Veil's contract semantics.
// Every remote request uses a localhost Tor SOCKS proxy; there is no direct fallback.
const fs = require('node:fs')
const path = require('node:path')
const { spawnSync } = require('node:child_process')
const { bsv } = require('scrypt-ts')

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-size-probe-wallet.json')
const RECEIPT_FILE = path.join(PRIVATE_DIR, 'testnet-size-probe-receipt.json')
const SOCKS = '127.0.0.1:19050'
const ARC = 'https://testnet.arc.gorillapool.io'
const BITAILS = 'https://test-api.bitails.io'
const SCRIPT_BYTES = 2_071_884
const FEE_PER_KB = 100
const OUTPUT_SATS = 1_000

function torRequest(url, method = 'GET', body) {
    if (!url.startsWith(`${ARC}/`) && !url.startsWith(`${BITAILS}/`)) {
        throw new Error('Remote URL is not on the testnet allowlist')
    }
    const args = [
        '--silent', '--show-error', '--fail-with-body',
        '--socks5-hostname', SOCKS, '--noproxy', '',
        '--proto', '=https', '--connect-timeout', '20',
        '--max-time', method === 'POST' ? '180' : '60',
    ]
    if (method === 'POST') {
        args.push('--request', 'POST', '--header', 'Content-Type: text/plain', '--data-binary', '@-')
    }
    args.push(url)
    const result = spawnSync('curl', args, {
        input: body,
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
        env: {
            ...process.env,
            HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '',
            http_proxy: '', https_proxy: '', all_proxy: '',
            NO_PROXY: '', no_proxy: '',
        },
    })
    if (result.error || result.status !== 0) {
        const detail = (result.stderr || result.error?.message || 'request failed').trim()
        throw new Error(`Tor-only request failed: ${detail}`)
    }
    try {
        return JSON.parse(result.stdout)
    } catch {
        throw new Error('Remote service returned non-JSON data')
    }
}

function initWallet() {
    fs.mkdirSync(PRIVATE_DIR, { recursive: true, mode: 0o700 })
    fs.chmodSync(PRIVATE_DIR, 0o700)
    if (fs.existsSync(WALLET_FILE)) return loadWallet()
    const key = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
    const wallet = {
        network: 'testnet',
        address: key.toAddress(bsv.Networks.testnet).toString(),
        wif: key.toWIF(),
    }
    fs.writeFileSync(WALLET_FILE, JSON.stringify(wallet, null, 2) + '\n', {
        flag: 'wx', mode: 0o600,
    })
    return wallet
}

function loadWallet() {
    const wallet = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'))
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (wallet.network !== 'testnet' || key.network.name !== 'testnet') {
        throw new Error('Refusing a non-testnet private key')
    }
    if (key.toAddress(bsv.Networks.testnet).toString() !== wallet.address) {
        throw new Error('Wallet address does not match private key')
    }
    return wallet
}

function makeLargeScript(address) {
    const p2pkh = bsv.Script.buildPublicKeyHashOut(address).toBuffer()
    // OP_0 OP_IF <small pushes, never executed> OP_ENDIF <P2PKH>.
    // This stays spendable while exercising one locking script's full size.
    const paddingLength = SCRIPT_BYTES - 3 - p2pkh.length
    const chunks = [Buffer.from([0x00, 0x63])]
    let remaining = paddingLength
    while (remaining > 0) {
        if (remaining <= 3) throw new Error('Cannot encode exact script length')
        const dataLength = Math.min(1024, remaining - 3)
        const header = Buffer.alloc(3)
        header[0] = 0x4d // OP_PUSHDATA2
        header.writeUInt16LE(dataLength, 1)
        chunks.push(header, Buffer.alloc(dataLength))
        remaining -= 3 + dataLength
    }
    chunks.push(Buffer.from([0x68]), p2pkh)
    const script = bsv.Script.fromBuffer(Buffer.concat(chunks))
    if (script.toBuffer().length !== SCRIPT_BYTES) throw new Error('Script length mismatch')
    return script
}

function getPolicy() {
    const policy = torRequest(`${ARC}/v1/policy`).policy
    if (!Number.isSafeInteger(policy.maxscriptsizepolicy) ||
        !Number.isSafeInteger(policy.maxtxsizepolicy)) {
        throw new Error('Invalid ARC policy response')
    }
    return policy
}

function getUtxos(address) {
    const response = torRequest(`${BITAILS}/address/${address}/unspent`)
    if (!Array.isArray(response.unspent)) throw new Error('Invalid Bitails UTXO response')
    return response.unspent.filter((u) =>
        /^[0-9a-f]{64}$/i.test(u.txid) &&
        Number.isSafeInteger(u.vout) &&
        Number.isSafeInteger(u.satoshis) &&
        u.confirmations >= 1
    )
}

function fundingOverride() {
    const arg = process.argv.find((value) => value.startsWith('--funding='))
    if (!arg) return null
    const [txid, voutText, satoshisText, blockHeightText] = arg.slice(10).split(':')
    const vout = Number(voutText)
    const satoshis = Number(satoshisText)
    const blockheight = Number(blockHeightText)
    if (!/^[0-9a-f]{64}$/i.test(txid) || !Number.isSafeInteger(vout) || vout < 0 ||
        !Number.isSafeInteger(satoshis) || satoshis <= 0 ||
        !Number.isSafeInteger(blockheight) || blockheight <= 0) {
        throw new Error('Funding override must be txid:vout:satoshis:confirmedBlockHeight')
    }
    return { txid, vout, satoshis, blockheight, confirmations: 1 }
}

function buildTransaction(wallet, utxo, policy) {
    if (policy.maxscriptsizepolicy < SCRIPT_BYTES) {
        throw new Error(`Miner script policy is only ${policy.maxscriptsizepolicy} bytes`)
    }
    const address = bsv.Address.fromString(wallet.address, bsv.Networks.testnet)
    const script = makeLargeScript(address)
    const estimatedFee = Math.ceil((SCRIPT_BYTES + 1_000) * FEE_PER_KB / 1_000) + 1_000
    if (utxo.satoshis < estimatedFee + OUTPUT_SATS + bsv.Transaction.DUST_AMOUNT) {
        throw new Error(`Fund at least ${estimatedFee + OUTPUT_SATS + bsv.Transaction.DUST_AMOUNT} satoshis`)
    }
    const tx = new bsv.Transaction()
    tx.from({
        txId: utxo.txid,
        outputIndex: utxo.vout,
        script: bsv.Script.buildPublicKeyHashOut(address),
        satoshis: utxo.satoshis,
    })
    tx.addOutput(new bsv.Transaction.Output({ script, satoshis: OUTPUT_SATS }))
    tx.fee(estimatedFee)
    tx.change(address)
    tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))
    if (!tx.isFullySigned()) throw new Error('Probe transaction is not signed')
    const raw = tx.toString()
    const bytes = raw.length / 2
    const actualFee = utxo.satoshis - tx.outputs.reduce((sum, out) => sum + out.satoshis, 0)
    if (bytes > policy.maxtxsizepolicy) throw new Error('Transaction exceeds miner tx-size policy')
    if (actualFee < Math.ceil(bytes * FEE_PER_KB / 1_000)) {
        throw new Error('Transaction fee is below probe minimum')
    }
    return { raw, txid: tx.id, bytes, scriptBytes: script.toBuffer().length, fee: actualFee }
}

function main() {
    const command = process.argv[2]
    if (!['init', 'status', 'dry-run', 'send'].includes(command)) {
        throw new Error('Usage: node scripts/tor-size-probe.cjs init|status|dry-run|send [--funding=txid:vout:satoshis:blockheight]')
    }
    if (command === 'init') {
        const wallet = initWallet()
        console.log(`Testnet funding address: ${wallet.address}`)
        console.log(`Private key retained locally in ${WALLET_FILE} (mode 0600); do not share it.`)
        return
    }
    if (!fs.existsSync(WALLET_FILE)) throw new Error('Run init before checking or sending')
    const wallet = loadWallet()
    if (command === 'dry-run') {
        const policy = { maxscriptsizepolicy: 100_000_000, maxtxsizepolicy: 100_000_000 }
        const tx = buildTransaction(wallet, {
            txid: '11'.repeat(32), vout: 0, satoshis: 1_000_000,
        }, policy)
        console.log(JSON.stringify({ scriptBytes: tx.scriptBytes, txBytes: tx.bytes,
            feeSatoshis: tx.fee, signed: true, broadcast: false }))
        return
    }
    const policy = getPolicy()
    const suppliedFunding = fundingOverride()
    const utxos = suppliedFunding ? [suppliedFunding] : getUtxos(wallet.address)
    console.log(`Tor policy: ${policy.maxscriptsizepolicy} script bytes; ${policy.maxtxsizepolicy} tx bytes`)
    console.log(`Confirmed funding UTXOs: ${utxos.length}`)
    if (suppliedFunding) {
        console.log(`Funding override: ${suppliedFunding.txid}:${suppliedFunding.vout} confirmed in block ${suppliedFunding.blockheight}`)
    }
    if (command === 'status') return
    if (fs.existsSync(RECEIPT_FILE)) {
        throw new Error(`A probe was already broadcast; see ${RECEIPT_FILE}`)
    }
    const minimum = Math.ceil((SCRIPT_BYTES + 1_000) * FEE_PER_KB / 1_000) +
        1_000 + OUTPUT_SATS + bsv.Transaction.DUST_AMOUNT
    const utxo = utxos.find((u) => u.satoshis >= minimum)
    if (!utxo) throw new Error(`No confirmed UTXO with at least ${minimum} satoshis`)
    const tx = buildTransaction(wallet, utxo, policy)
    console.log(`Submitting ${tx.bytes} bytes via Tor (${tx.scriptBytes}-byte locking script)`)
    const response = torRequest(`${ARC}/v1/tx`, 'POST', tx.raw)
    const receipt = {
        txid: tx.txid,
        scriptBytes: tx.scriptBytes,
        txBytes: tx.bytes,
        feeSatoshis: tx.fee,
        arcResponse: response,
    }
    fs.writeFileSync(RECEIPT_FILE, JSON.stringify(receipt, null, 2) + '\n', {
        flag: 'wx', mode: 0o600,
    })
    console.log(`ARC response: ${JSON.stringify(response)}`)
    console.log(`Transaction ID: ${tx.txid}`)
}

try {
    main()
} catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
}
