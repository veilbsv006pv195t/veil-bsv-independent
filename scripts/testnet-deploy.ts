import { spawnSync } from 'node:child_process'
import {
    chmodSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { bsv } from 'scrypt-ts'
import { PoolState, createHash } from '../src/crypto'
import { ShieldedPool } from '../src/contracts/shieldedPool'
import {
    SnarkVerificationKey,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')
// Keep the optimized verifier deployment completely separate from the original
// direct-pairing deployment records. This prevents `send` from ever loading the
// already-broadcast legacy transaction after the contract bytecode changed.
const DEPLOYMENT_RECORD_PREFIX = 'testnet-optimized-v3-deployment'
const DRY_RUN_FILE = path.join(PRIVATE_DIR, `${DEPLOYMENT_RECORD_PREFIX}-dry-run.json`)
const SIGNED_TX_FILE = path.join(PRIVATE_DIR, `${DEPLOYMENT_RECORD_PREFIX}-signed.json`)
const RECEIPT_FILE = path.join(PRIVATE_DIR, `${DEPLOYMENT_RECORD_PREFIX}-receipt.json`)
const CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    `${DEPLOYMENT_RECORD_PREFIX}-confirmation.json`
)
const SOCKS = '127.0.0.1:19050'
const ARC = 'https://testnet.arc.gorillapool.io'
const BITAILS = 'https://test-api.bitails.io'
const EXPECTED_SCRIPT_BYTES = 1_097_379
const STATE_ANCHOR_SATS = 1
const CHANGE_DUST_SATS = 546
const FEE_PER_KB = 101
const FEE_SAFETY_SATS = 1_000
const FAKE_FUNDING_SATS = 3_000_000

interface DeploymentWallet {
    network: 'testnet'
    address: string
    wif: string
}

interface FundingUtxo {
    txid: string
    vout: number
    satoshis: number
    confirmations?: number
    blockheight?: number
}

interface FundingOverride extends FundingUtxo {
    blockheight: number
}

interface ArcPolicy {
    maxscriptsizepolicy: number
    maxtxsizepolicy: number
}

export interface DeploymentPlan {
    network: 'testnet'
    broadcast: false
    fundingOutpoint: string
    fundingSatoshis: number
    deploymentTxid: string
    transactionBytes: number
    lockingScriptBytes: number
    lockingScriptSha256: string
    feeRateSatsPerKb: number
    feeSatoshis: number
    poolOutputIndex: 0
    poolOutputSatoshis: number
    changeSatoshis: number
    initialState: {
        noteRoot: string
        nullifierRoot: string
        nextNoteIndex: '0'
    }
}

interface SignedDeployment extends DeploymentPlan {
    createdAt: string
    transactionHex: string
}

interface DeploymentAudit {
    deploymentTxid: string
    transactionBytes: number
    fundingOutpoint: string
    inputCount: number
    outputCount: number
    poolOutputSatoshis: number
    lockingScriptBytes: number
    lockingScriptSha256: string
    changeSatoshis: number
    feeSatoshis: number
}

export interface ArcTransactionResponse {
    status: number
    timestamp?: string
    title?: string
    txStatus: string
    txid: string
    blockHash?: string
    blockHeight?: number
    merklePath?: string
    extraInfo?: string
}

export interface DeploymentReceipt extends Omit<DeploymentPlan, 'broadcast'> {
    broadcast: true
    submittedAt: string
    arcResponse: ArcTransactionResponse
}

interface BuiltDeployment {
    plan: DeploymentPlan
    transactionHex: string
}

function ensurePrivateDirectory(): void {
    mkdirSync(PRIVATE_DIR, { recursive: true, mode: 0o700 })
    chmodSync(PRIVATE_DIR, 0o700)
}

function writePrivateJson(file: string, value: unknown): void {
    ensurePrivateDirectory()
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
    chmodSync(file, 0o600)
}

function writePrivateJsonExclusive(file: string, value: unknown): void {
    ensurePrivateDirectory()
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
        flag: 'wx',
        mode: 0o600,
    })
}

function initWallet(): DeploymentWallet {
    ensurePrivateDirectory()
    if (existsSync(WALLET_FILE)) return loadWallet()
    const key = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
    const wallet: DeploymentWallet = {
        network: 'testnet',
        address: key.toAddress(bsv.Networks.testnet).toString(),
        wif: key.toWIF(),
    }
    writeFileSync(WALLET_FILE, `${JSON.stringify(wallet, null, 2)}\n`, {
        flag: 'wx',
        mode: 0o600,
    })
    return wallet
}

function loadWallet(): DeploymentWallet {
    if (!existsSync(WALLET_FILE)) {
        throw new Error('Run npm run deploy:init before this command')
    }
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as DeploymentWallet
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (wallet.network !== 'testnet' || key.network.name !== 'testnet') {
        throw new Error('Refusing a non-testnet private key')
    }
    if (key.toAddress(bsv.Networks.testnet).toString() !== wallet.address) {
        throw new Error('Deployment wallet address does not match its private key')
    }
    return wallet
}

function torRequest(url: string, method: 'GET' | 'POST' = 'GET', body?: string): unknown {
    if (!url.startsWith(`${ARC}/`) && !url.startsWith(`${BITAILS}/`)) {
        throw new Error('Remote URL is not on the BSV testnet allowlist')
    }
    const args = [
        '--silent',
        '--show-error',
        '--fail-with-body',
        '--socks5-hostname',
        SOCKS,
        '--noproxy',
        '',
        '--proto',
        '=https',
        '--connect-timeout',
        '20',
        '--max-time',
        method === 'POST' ? '180' : '60',
    ]
    if (method === 'POST') {
        args.push(
            '--request',
            'POST',
            '--header',
            'Content-Type: text/plain',
            '--data-binary',
            '@-'
        )
    }
    args.push(url)
    const result = spawnSync(
        'curl',
        args,
        {
            input: body,
            encoding: 'utf8',
            maxBuffer: 8 * 1024 * 1024,
            env: {
                ...process.env,
                HTTP_PROXY: '',
                HTTPS_PROXY: '',
                ALL_PROXY: '',
                http_proxy: '',
                https_proxy: '',
                all_proxy: '',
                NO_PROXY: '',
                no_proxy: '',
            },
        }
    )
    if (result.error || result.status !== 0) {
        const detail = (result.stderr || result.error?.message || 'request failed').trim()
        throw new Error(`Tor-only request failed: ${detail}`)
    }
    try {
        return JSON.parse(result.stdout) as unknown
    } catch {
        throw new Error('Remote service returned non-JSON data')
    }
}

const ARC_SUCCESS_STATUSES = new Set([
    'QUEUED',
    'RECEIVED',
    'STORED',
    'ANNOUNCED_TO_NETWORK',
    'REQUESTED_BY_NETWORK',
    'SENT_TO_NETWORK',
    'ACCEPTED_BY_NETWORK',
    'SEEN_IN_ORPHAN_MEMPOOL',
    'SEEN_ON_NETWORK',
    'MINED_IN_STALE_BLOCK',
    'MINED',
])

export function validateArcResponse(
    value: unknown,
    expectedTxid: string
): ArcTransactionResponse {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('ARC returned an invalid transaction response')
    }
    const response = value as Partial<ArcTransactionResponse>
    if (
        typeof response.txid !== 'string' ||
        !/^[0-9a-f]{64}$/i.test(response.txid) ||
        response.txid.toLowerCase() !== expectedTxid.toLowerCase()
    ) {
        throw new Error('ARC response transaction ID does not match the signed transaction')
    }
    if (
        !Number.isSafeInteger(response.status) ||
        (response.status as number) < 200 ||
        (response.status as number) >= 300
    ) {
        throw new Error(`ARC rejected the transaction with status ${String(response.status)}`)
    }
    if (
        typeof response.txStatus !== 'string' ||
        !ARC_SUCCESS_STATUSES.has(response.txStatus)
    ) {
        throw new Error(`ARC returned a non-success transaction state: ${String(response.txStatus)}`)
    }
    return response as ArcTransactionResponse
}

export function makeBroadcastReceipt(
    plan: DeploymentPlan,
    arcResponse: ArcTransactionResponse,
    submittedAt: string
): DeploymentReceipt {
    const { broadcast: _dryRun, ...details } = plan
    return {
        ...details,
        broadcast: true,
        submittedAt,
        arcResponse,
    }
}

export function validateMinedArcResponse(
    value: unknown,
    expectedTxid: string
): Omit<ArcTransactionResponse, 'status'> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('ARC returned an invalid confirmation response')
    }
    const response = value as Partial<ArcTransactionResponse>
    if (
        response.txid?.toLowerCase() !== expectedTxid.toLowerCase() ||
        response.txStatus !== 'MINED' ||
        !Number.isSafeInteger(response.blockHeight) ||
        (response.blockHeight as number) <= 0 ||
        typeof response.blockHash !== 'string' ||
        !/^[0-9a-f]{64}$/i.test(response.blockHash) ||
        typeof response.merklePath !== 'string' ||
        response.merklePath.length === 0
    ) {
        throw new Error('ARC has not returned valid mined inclusion evidence')
    }
    return response as Omit<ArcTransactionResponse, 'status'>
}

function getPolicy(): ArcPolicy {
    const response = torRequest(`${ARC}/v1/policy`) as { policy?: Partial<ArcPolicy> }
    const policy = response.policy
    if (
        !policy ||
        !Number.isSafeInteger(policy.maxscriptsizepolicy) ||
        !Number.isSafeInteger(policy.maxtxsizepolicy)
    ) {
        throw new Error('Invalid ARC policy response')
    }
    return policy as ArcPolicy
}

function getUtxos(address: string): FundingUtxo[] {
    const response = torRequest(`${BITAILS}/address/${address}/unspent`) as {
        unspent?: FundingUtxo[]
    }
    if (!Array.isArray(response.unspent)) {
        throw new Error('Invalid Bitails UTXO response')
    }
    return response.unspent.filter(
        (utxo) =>
            /^[0-9a-f]{64}$/i.test(utxo.txid) &&
            Number.isSafeInteger(utxo.vout) &&
            utxo.vout >= 0 &&
            Number.isSafeInteger(utxo.satoshis) &&
            utxo.satoshis > 0 &&
            (utxo.confirmations ?? 0) >= 1
    )
}

function fundingOverride(): FundingOverride | null {
    const arg = process.argv.find((value) => value.startsWith('--funding='))
    if (!arg) return null
    const [txid, voutText, satoshisText, blockHeightText] = arg.slice(10).split(':')
    const vout = Number(voutText)
    const satoshis = Number(satoshisText)
    const blockheight = Number(blockHeightText)
    if (
        !/^[0-9a-f]{64}$/i.test(txid) ||
        !Number.isSafeInteger(vout) ||
        vout < 0 ||
        !Number.isSafeInteger(satoshis) ||
        satoshis <= 0 ||
        !Number.isSafeInteger(blockheight) ||
        blockheight <= 0
    ) {
        throw new Error(
            'Funding override must be txid:vout:satoshis:confirmedBlockHeight'
        )
    }
    return { txid, vout, satoshis, blockheight, confirmations: 1 }
}

function validateFundingOverride(funding: FundingOverride): FundingOverride {
    const response = torRequest(`${ARC}/v1/tx/${funding.txid}`) as {
        txid?: string
        txStatus?: string
        blockHeight?: number
    }
    if (
        response.txid?.toLowerCase() !== funding.txid.toLowerCase() ||
        response.txStatus !== 'MINED' ||
        response.blockHeight !== funding.blockheight
    ) {
        throw new Error('ARC did not confirm the supplied funding outpoint in the expected block')
    }
    return funding
}

function loadVerificationKey(): SnarkVerificationKey {
    const candidates = [
        path.join(ROOT, 'build', 'verification_key.json'),
        path.join(ROOT, 'ui', 'public', 'zk', 'verification_key.json'),
    ]
    const file = candidates.find(existsSync)
    if (!file) {
        throw new Error('Verification key is missing; run npm run build:circuit')
    }
    return JSON.parse(readFileSync(file, 'utf8')) as SnarkVerificationKey
}

async function buildDeployment(
    wallet: DeploymentWallet,
    funding: FundingUtxo,
    policy: ArcPolicy
): Promise<BuiltDeployment> {
    const hash = await createHash()
    const state = new PoolState(hash)
    const jsonVkey = loadVerificationKey()

    ShieldedPool.loadArtifact()
    const contract = new ShieldedPool(
        state.noteTree.root(),
        state.nullifierTree.root(),
        0n,
        toPreparedVerifyingKey(jsonVkey)
    )
    const lockingScript = contract.lockingScript
    const lockingScriptBytes = lockingScript.toBuffer().length
    if (lockingScriptBytes !== EXPECTED_SCRIPT_BYTES) {
        throw new Error(
            `Compiled contract is ${lockingScriptBytes} bytes; expected ${EXPECTED_SCRIPT_BYTES}`
        )
    }
    if (lockingScriptBytes > policy.maxscriptsizepolicy) {
        throw new Error(`Contract exceeds miner script policy ${policy.maxscriptsizepolicy}`)
    }

    const address = bsv.Address.fromString(wallet.address, bsv.Networks.testnet)
    const estimatedFee =
        Math.ceil(((lockingScriptBytes + 1_000) * FEE_PER_KB) / 1_000) +
        FEE_SAFETY_SATS
    const minimumFunding =
        estimatedFee + STATE_ANCHOR_SATS + CHANGE_DUST_SATS
    if (funding.satoshis < minimumFunding) {
        throw new Error(`Funding UTXO requires at least ${minimumFunding} satoshis`)
    }

    const tx = new bsv.Transaction()
    tx.from({
        txId: funding.txid,
        outputIndex: funding.vout,
        script: bsv.Script.buildPublicKeyHashOut(address).toHex(),
        satoshis: funding.satoshis,
    })
    tx.addOutput(
        new bsv.Transaction.Output({
            script: lockingScript,
            satoshis: STATE_ANCHOR_SATS,
        })
    )
    tx.fee(estimatedFee)
    tx.change(address)
    tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))
    if (!tx.isFullySigned()) throw new Error('Deployment transaction is not signed')

    const transactionBytes = tx.toString().length / 2
    if (transactionBytes > policy.maxtxsizepolicy) {
        throw new Error(`Deployment exceeds miner transaction policy ${policy.maxtxsizepolicy}`)
    }
    const totalOutput = tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const feeSatoshis = funding.satoshis - totalOutput
    const minimumActualFee = Math.ceil((transactionBytes * FEE_PER_KB) / 1_000)
    if (feeSatoshis < minimumActualFee) {
        throw new Error(`Deployment fee ${feeSatoshis} is below ${minimumActualFee}`)
    }
    if (tx.outputs[0].satoshis !== STATE_ANCHOR_SATS) {
        throw new Error('Pool state anchor is not output zero')
    }

    return {
        transactionHex: tx.toString(),
        plan: {
            network: 'testnet',
            broadcast: false,
            fundingOutpoint: `${funding.txid}:${funding.vout}`,
            fundingSatoshis: funding.satoshis,
            deploymentTxid: tx.id,
            transactionBytes,
            lockingScriptBytes,
            lockingScriptSha256: bsv.crypto.Hash.sha256(lockingScript.toBuffer()).toString('hex'),
            feeRateSatsPerKb: FEE_PER_KB,
            feeSatoshis,
            poolOutputIndex: 0,
            poolOutputSatoshis: STATE_ANCHOR_SATS,
            changeSatoshis: tx.outputs.slice(1).reduce((sum, output) => sum + output.satoshis, 0),
            initialState: {
                noteRoot: state.noteTree.root().toString(),
                nullifierRoot: state.nullifierTree.root().toString(),
                nextNoteIndex: '0',
            },
        },
    }
}

function auditSignedDeployment(signed: SignedDeployment): DeploymentAudit {
    const tx = new bsv.Transaction(signed.transactionHex)
    const fundingParts = signed.fundingOutpoint.split(':')
    const expectedFundingTxid = fundingParts[0]
    const expectedFundingVout = Number(fundingParts[1])
    const actualFundingTxid = tx.inputs[0].prevTxId.toString('hex')
    const changeSatoshis = tx.outputs
        .slice(1)
        .reduce((sum, output) => sum + output.satoshis, 0)
    const totalOutputSatoshis = tx.outputs.reduce(
        (sum, output) => sum + output.satoshis,
        0
    )
    const feeSatoshis = signed.fundingSatoshis - totalOutputSatoshis
    const lockingScriptBytes = tx.outputs[0]?.script.toBuffer().length
    const lockingScriptSha256 = bsv.crypto.Hash.sha256(
        tx.outputs[0]?.script.toBuffer()
    ).toString('hex')

    const checks: Record<string, boolean> = {
        deploymentTxid: tx.id === signed.deploymentTxid,
        transactionBytes: tx.toString().length / 2 === signed.transactionBytes,
        inputCount: tx.inputs.length === 1,
        fundingTxid: actualFundingTxid === expectedFundingTxid,
        fundingVout: tx.inputs[0].outputIndex === expectedFundingVout,
        outputCount: tx.outputs.length === 2,
        poolOutputSatoshis: tx.outputs[0]?.satoshis === signed.poolOutputSatoshis,
        lockingScriptBytes: lockingScriptBytes === signed.lockingScriptBytes,
        lockingScriptSha256: lockingScriptSha256 === signed.lockingScriptSha256,
        changeSatoshis: changeSatoshis === signed.changeSatoshis,
        feeSatoshis: feeSatoshis === signed.feeSatoshis,
    }
    const failedChecks = Object.entries(checks)
        .filter(([, passed]) => !passed)
        .map(([name]) => name)
    if (failedChecks.length > 0) {
        throw new Error(
            `Saved deployment transaction failed audit checks: ${failedChecks.join(', ')}`
        )
    }

    return {
        deploymentTxid: tx.id,
        transactionBytes: tx.toString().length / 2,
        fundingOutpoint: `${actualFundingTxid}:${tx.inputs[0].outputIndex}`,
        inputCount: tx.inputs.length,
        outputCount: tx.outputs.length,
        poolOutputSatoshis: tx.outputs[0].satoshis,
        lockingScriptBytes,
        lockingScriptSha256,
        changeSatoshis,
        feeSatoshis,
    }
}

async function main(): Promise<void> {
    const command = process.argv[2]
    if (!['init', 'status', 'dry-run', 'prepare', 'audit', 'send', 'confirm'].includes(command)) {
        throw new Error(
            'Usage: npm run deploy:init|deploy:status|deploy:dry-run|deploy:prepare|deploy:audit|deploy:send|deploy:confirm'
        )
    }

    if (command === 'init') {
        const wallet = initWallet()
        console.log(`Fresh BSV testnet deployment address: ${wallet.address}`)
        console.log('The private key is local, mode 0600, ignored by Git, and must not be shared.')
        return
    }

    if (command === 'audit') {
        if (!existsSync(SIGNED_TX_FILE)) {
            throw new Error('Run npm run deploy:prepare before auditing a deployment')
        }
        const signed = JSON.parse(readFileSync(SIGNED_TX_FILE, 'utf8')) as SignedDeployment
        console.log(JSON.stringify(auditSignedDeployment(signed), null, 2))
        return
    }

    const wallet = loadWallet()
    if (command === 'status') {
        const policy = getPolicy()
        const supplied = fundingOverride()
        const utxos = supplied ? [validateFundingOverride(supplied)] : getUtxos(wallet.address)
        console.log(
            JSON.stringify(
                {
                    network: 'testnet',
                    address: wallet.address,
                    torOnly: true,
                    policy,
                    confirmedUtxos: utxos.map(({ txid, vout, satoshis, confirmations }) => ({
                        txid,
                        vout,
                        satoshis,
                        confirmations,
                    })),
                    confirmedBalanceSatoshis: utxos.reduce(
                        (sum, utxo) => sum + utxo.satoshis,
                        0
                    ),
                },
                null,
                2
            )
        )
        return
    }

    if (command === 'prepare') {
        if (existsSync(RECEIPT_FILE)) {
            throw new Error(`A deployment was already broadcast; see ${RECEIPT_FILE}`)
        }
        if (existsSync(SIGNED_TX_FILE)) {
            const signed = JSON.parse(readFileSync(SIGNED_TX_FILE, 'utf8')) as SignedDeployment
            throw new Error(
                `A signed deployment already exists for ${signed.deploymentTxid}. ` +
                'Check ARC and a testnet explorer before any retry; the previous result may be uncertain.'
            )
        }

        const policy = getPolicy()
        const supplied = fundingOverride()
        const utxos = supplied ? [validateFundingOverride(supplied)] : getUtxos(wallet.address)
        const estimatedFee =
            Math.ceil(((EXPECTED_SCRIPT_BYTES + 1_000) * FEE_PER_KB) / 1_000) +
            FEE_SAFETY_SATS
        const minimumFunding = estimatedFee + STATE_ANCHOR_SATS + CHANGE_DUST_SATS
        const funding = utxos
            .filter((utxo) => utxo.satoshis >= minimumFunding)
            .sort((left, right) => left.satoshis - right.satoshis)[0]
        if (!funding) {
            throw new Error(
                `No confirmed single UTXO has the required ${minimumFunding} satoshis`
            )
        }

        const built = await buildDeployment(wallet, funding, policy)
        const signed: SignedDeployment = {
            ...built.plan,
            createdAt: new Date().toISOString(),
            transactionHex: built.transactionHex,
        }
        writePrivateJsonExclusive(SIGNED_TX_FILE, signed)
        console.log(JSON.stringify(built.plan, null, 2))
        console.log(`Signed deployment saved for review: ${SIGNED_TX_FILE}`)
        return
    }

    if (command === 'send') {
        if (existsSync(RECEIPT_FILE)) {
            throw new Error(`A deployment was already broadcast; see ${RECEIPT_FILE}`)
        }
        if (!existsSync(SIGNED_TX_FILE)) {
            throw new Error('Run npm run deploy:prepare and review the signed plan first')
        }
        const signed = JSON.parse(readFileSync(SIGNED_TX_FILE, 'utf8')) as SignedDeployment
        auditSignedDeployment(signed)

        const { createdAt: _createdAt, transactionHex: _transactionHex, ...plan } = signed

        let rawResponse: unknown
        try {
            rawResponse = torRequest(`${ARC}/v1/tx`, 'POST', signed.transactionHex)
        } catch (error) {
            const detail = error instanceof Error ? error.message : String(error)
            throw new Error(
                `Deployment submission result is uncertain. ${detail}. ` +
                `Keep ${SIGNED_TX_FILE} and check transaction ${signed.deploymentTxid} before retrying.`
            )
        }
        const arcResponse = validateArcResponse(rawResponse, signed.deploymentTxid)
        const receipt = makeBroadcastReceipt(
            plan,
            arcResponse,
            new Date().toISOString()
        )
        writePrivateJsonExclusive(RECEIPT_FILE, receipt)
        console.log(JSON.stringify(receipt, null, 2))
        console.log(`Deployment receipt: ${RECEIPT_FILE}`)
        return
    }

    if (command === 'confirm') {
        if (!existsSync(RECEIPT_FILE)) {
            throw new Error('No deployment receipt exists; run npm run deploy:send first')
        }
        if (existsSync(CONFIRMATION_FILE)) {
            throw new Error(`Deployment confirmation already exists: ${CONFIRMATION_FILE}`)
        }
        const receipt = JSON.parse(readFileSync(RECEIPT_FILE, 'utf8')) as DeploymentReceipt
        const response = torRequest(`${ARC}/v1/tx/${receipt.deploymentTxid}`)
        const mined = validateMinedArcResponse(response, receipt.deploymentTxid)
        const confirmation = {
            deploymentTxid: receipt.deploymentTxid,
            confirmedAt: new Date().toISOString(),
            ...mined,
        }
        writePrivateJsonExclusive(CONFIRMATION_FILE, confirmation)
        console.log(JSON.stringify(confirmation, null, 2))
        console.log(`Deployment confirmation: ${CONFIRMATION_FILE}`)
        return
    }

    const fakeFunding: FundingUtxo = {
        txid: '11'.repeat(32),
        vout: 0,
        satoshis: FAKE_FUNDING_SATS,
        confirmations: 1,
    }
    const built = await buildDeployment(wallet, fakeFunding, {
        maxscriptsizepolicy: 100_000_000,
        maxtxsizepolicy: 100_000_000,
    })
    writePrivateJson(DRY_RUN_FILE, built.plan)
    console.log(JSON.stringify(built.plan, null, 2))
    console.log(`Dry-run receipt: ${DRY_RUN_FILE}`)
}

if (require.main === module) {
    main().catch((error: unknown) => {
        console.error(error instanceof Error ? error.message : error)
        process.exitCode = 1
    })
}
