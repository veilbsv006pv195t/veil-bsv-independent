import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import {
    chmodSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs'
import path from 'node:path'
import {
    bsv,
    int2ByteString,
    PubKeyHash,
} from 'scrypt-ts'
import { groth16 } from 'snarkjs'
import {
    BuiltTransition,
    FIELD,
    Note,
    PoolState,
    PublicTransition,
    createHash,
} from '../src/crypto'
import { ShieldedPool } from '../src/contracts/shieldedPool'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')
const DEPLOYMENT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-deployment-signed.json'
)
const DEPLOYMENT_CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-deployment-confirmation.json'
)
const SECRETS_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-lifecycle-secrets.json'
)
const SHIELD_SIGNED_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-shield-signed.json'
)
const SHIELD_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-shield-receipt.json'
)
const EVIDENCE_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-lifecycle-evidence.json'
)
const WASM = path.join(ROOT, 'build', 'shielded_pool_js', 'shielded_pool.wasm')
const ZKEY = path.join(ROOT, 'build', 'shielded_pool_final.zkey')
const VKEY = path.join(ROOT, 'build', 'verification_key.json')
const SOCKS = '127.0.0.1:19050'
const ARC = 'https://testnet.arc.gorillapool.io'
const ARCADE = 'https://testnet.arcade.gorillapool.io'
const TRANSITION_FEE = 450_000
const SHIELD_SATS = 100_000n
const RECEIVER_SATS = 60_000n
const SENDER_CHANGE_SATS = 40_000n
const WITHDRAW_SATS = 50_000n
const RECEIVER_CHANGE_SATS = 10_000n
const SCRIPT_NUMBER_POLICY_BYTES = 10_000

interface WalletFile {
    network: 'testnet'
    address: string
    wif: string
}

interface Outpoint {
    txid: string
    vout: number
    satoshis: number
}

interface PoolOutpoint extends Outpoint {
    noteRoot: bigint
    nullifierRoot: bigint
    nextIndex: bigint
}

interface BuiltTx {
    tx: bsv.Transaction
    txid: string
    rawHex: string
    unlockingHex: string
    pool: PoolOutpoint
    wallet: Outpoint
    bytes: number
    fee: number
}

interface ArcStatus {
    txid?: string
    txStatus?: string
    blockHeight?: number
    blockHash?: string
    merklePath?: string
    status?: number
    title?: string
    extraInfo?: string
}

interface HttpResult {
    status: number
    body: unknown
}

interface SavedShield {
    createdAt: string
    deploymentTxid: string
    kind: 'shield'
    txid: string
    transactionBytes: number
    feeSatoshis: number
    poolOutputSatoshis: number
    walletChangeSatoshis: number
    public: Record<string, string>
    rawHex: string
    localValidation: {
        covenantMilliseconds: number
        fundingSignatureAccepted: true
    }
}

interface ShieldAudit {
    shieldTxid: string
    transactionBytes: number
    deploymentInputs: string[]
    outputCount: number
    poolOutputSatoshis: number
    walletChangeSatoshis: number
    feeSatoshis: number
    covenantMilliseconds: number
    maximumScriptNumberBytes: number
    scriptNumberPolicyBytes: number
    fundingSignatureAccepted: true
}

const sleep = (milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds))

function jsonSafe(value: unknown): unknown {
    if (typeof value === 'bigint') return value.toString()
    if (Array.isArray(value)) return value.map(jsonSafe)
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [key, jsonSafe(item)])
        )
    }
    return value
}

function installScriptNumberPolicyMonitor(limit: number): {
    restore: () => void
    maximumBytes: () => number
} {
    const BNClass = bsv.crypto.BN as unknown as {
        fromScriptNumBuffer: (
            buffer: Buffer,
            requireMinimal?: boolean,
            size?: number
        ) => bsv.crypto.BN
    }
    const original = BNClass.fromScriptNumBuffer
    let maximumBytes = 0
    BNClass.fromScriptNumBuffer = function (
        buffer: Buffer,
        requireMinimal?: boolean,
        size?: number
    ): bsv.crypto.BN {
        if (size === undefined) {
            maximumBytes = Math.max(maximumBytes, buffer.length)
            if (buffer.length > limit) {
                throw new Error(
                    `script number overflow: ${buffer.length} bytes exceeds ${limit}`
                )
            }
        }
        return original.call(this, buffer, requireMinimal, size)
    }
    return {
        restore: () => {
            BNClass.fromScriptNumBuffer = original
        },
        maximumBytes: () => maximumBytes,
    }
}

function writePrivate(file: string, value: unknown): void {
    mkdirSync(PRIVATE_DIR, { recursive: true, mode: 0o700 })
    chmodSync(PRIVATE_DIR, 0o700)
    writeFileSync(file, `${JSON.stringify(jsonSafe(value), null, 2)}\n`, {
        flag: 'wx',
        mode: 0o600,
    })
    chmodSync(file, 0o600)
}

function torHttp(url: string, method: 'GET' | 'POST' = 'GET', body?: string): HttpResult {
    if (!url.startsWith(`${ARC}/`) && !url.startsWith(`${ARCADE}/`)) {
        throw new Error('Remote URL is outside the testnet allowlist')
    }
    const marker = '__VEIL_HTTP__:'
    const args = [
        '--silent',
        '--show-error',
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
            '--header',
            'X-WaitForStatus: SEEN_ON_NETWORK',
            '--data-binary',
            '@-'
        )
    }
    args.push('--write-out', `\n${marker}%{http_code}`, url)
    const result = spawnSync('curl', args, {
        input: body,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
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
    })
    if (result.error || result.status !== 0) {
        const detail = (result.stderr || result.error?.message || 'request failed').trim()
        throw new Error(`Tor-only request failed: ${detail}`)
    }
    const split = result.stdout.lastIndexOf(`\n${marker}`)
    if (split < 0) throw new Error('Remote response omitted its HTTP status')
    const status = Number(result.stdout.slice(split + marker.length + 1))
    const text = result.stdout.slice(0, split)
    let parsed: unknown = text
    try {
        parsed = JSON.parse(text)
    } catch {
        // Preserve a non-JSON rejection body as evidence.
    }
    return { status, body: parsed }
}

function currentHeight(): number {
    const result = torHttp(`${ARCADE}/health`)
    const height = (result.body as { blockHeight?: number }).blockHeight
    if (result.status !== 200 || !Number.isSafeInteger(height) || (height as number) <= 0) {
        throw new Error('Arcade returned an invalid testnet chain height')
    }
    return height as number
}

function arcStatus(txid: string): { httpStatus: number; response: ArcStatus } {
    const result = torHttp(`${ARC}/v1/tx/${txid}`)
    return {
        httpStatus: result.status,
        response: result.body as ArcStatus,
    }
}

function submitValid(txid: string, rawHex: string): ArcStatus {
    const result = torHttp(`${ARC}/v1/tx`, 'POST', rawHex)
    const response = result.body as ArcStatus
    const accepted = new Set([
        'QUEUED',
        'RECEIVED',
        'STORED',
        'ANNOUNCED_TO_NETWORK',
        'REQUESTED_BY_NETWORK',
        'SENT_TO_NETWORK',
        'ACCEPTED_BY_NETWORK',
        'SEEN_ON_NETWORK',
        'MINED',
    ])
    if (
        result.status < 200 ||
        result.status >= 300 ||
        response.txid?.toLowerCase() !== txid.toLowerCase() ||
        !response.txStatus ||
        !accepted.has(response.txStatus)
    ) {
        throw new Error(`ARC rejected ${txid}: ${JSON.stringify(result.body)}`)
    }
    return response
}

function submitExpectedRejection(txid: string, rawHex: string): unknown {
    const result = torHttp(`${ARC}/v1/tx`, 'POST', rawHex)
    const response = result.body as ArcStatus
    const unsafe =
        result.status >= 200 &&
        result.status < 300 &&
        response.txid?.toLowerCase() === txid.toLowerCase() &&
        ['QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK', 'SENT_TO_NETWORK',
            'ACCEPTED_BY_NETWORK', 'SEEN_ON_NETWORK', 'MINED'].includes(response.txStatus ?? '')
    if (unsafe) throw new Error(`Expected-invalid transaction ${txid} was accepted by ARC`)
    return { httpStatus: result.status, response: result.body }
}

async function waitForMined(txid: string, timeoutMinutes = 45): Promise<ArcStatus> {
    const deadline = Date.now() + timeoutMinutes * 60_000
    while (Date.now() < deadline) {
        const { httpStatus, response } = arcStatus(txid)
        if (
            httpStatus === 200 &&
            ['REJECTED', 'DOUBLE_SPEND_ATTEMPTED'].includes(response.txStatus ?? '')
        ) {
            throw new Error(
                `ARC rejected ${txid}: ${response.extraInfo || response.txStatus}`
            )
        }
        if (
            httpStatus === 200 &&
            response.txid?.toLowerCase() === txid.toLowerCase() &&
            response.txStatus === 'MINED' &&
            Number.isSafeInteger(response.blockHeight) &&
            (response.blockHeight as number) > 0 &&
            /^[0-9a-f]{64}$/i.test(response.blockHash ?? '') &&
            (response.merklePath?.length ?? 0) > 0
        ) {
            return response
        }
        console.log(`Waiting for ${txid.slice(0, 12)}… to mine; ARC=${response.txStatus ?? httpStatus}`)
        await sleep(20_000)
    }
    throw new Error(`Timed out waiting for ${txid} to mine`)
}

async function waitForHeight(height: number): Promise<void> {
    while (true) {
        const tip = currentHeight()
        if (tip >= height) return
        console.log(`Height lock: tip ${tip}; waiting for ${height}`)
        await sleep(20_000)
    }
}

function randomField(): bigint {
    const value = BigInt(`0x${randomBytes(32).toString('hex')}`) % FIELD
    return value === 0n ? 1n : value
}

function recipientField(address: string): bigint {
    const hash = bsv.Address.fromString(address, bsv.Networks.testnet).hashBuffer
    return BigInt(`0x${Buffer.from(hash).reverse().toString('hex')}`)
}

function instantiate(publicState: Pick<PublicTransition, 'oldNoteRoot' | 'oldNullifierRoot' | 'oldNextIndex'>, vk: ReturnType<typeof toPreparedVerifyingKey>): ShieldedPool {
    ShieldedPool.loadArtifact()
    return new ShieldedPool(
        publicState.oldNoteRoot,
        publicState.oldNullifierRoot,
        publicState.oldNextIndex,
        vk
    )
}

async function prove(transition: BuiltTransition): Promise<ReturnType<typeof toScryptProof>> {
    const { proof } = await groth16.fullProve(transition.circuitInput, WASM, ZKEY)
    return toScryptProof(proof as SnarkProof)
}

function buildTransitionTx(
    transition: BuiltTransition,
    proof: ReturnType<typeof toScryptProof>,
    vk: ReturnType<typeof toPreparedVerifyingKey>,
    pool: PoolOutpoint,
    funding: Outpoint,
    wallet: WalletFile
): BuiltTx {
    const current = instantiate(transition.public, vk)
    if (
        current.noteRoot !== pool.noteRoot ||
        current.nullifierRoot !== pool.nullifierRoot ||
        current.nextIndex !== pool.nextIndex
    ) {
        throw new Error('Local transition does not match the deployed pool state')
    }
    const next = current.next()
    next.noteRoot = transition.public.newNoteRoot
    next.nullifierRoot = transition.public.newNullifierRoot
    next.nextIndex = transition.public.newNextIndex

    const tx = new bsv.Transaction()
    tx.addInput(
        new bsv.Transaction.Input({
            prevTxId: pool.txid,
            outputIndex: pool.vout,
            script: bsv.Script.empty(),
            output: new bsv.Transaction.Output({
                script: current.lockingScript,
                satoshis: pool.satoshis,
            }),
        })
    )
    tx.from({
        txId: funding.txid,
        outputIndex: funding.vout,
        script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(),
        satoshis: funding.satoshis,
    })
    if (transition.public.mode > 0n) {
        tx.lockUntilBlockHeight(Number(transition.public.currentHeight))
    }
    const nextPoolValue =
        BigInt(pool.satoshis) + transition.public.publicIn - transition.public.publicOut
    tx.addOutput(
        new bsv.Transaction.Output({
            script: next.lockingScript,
            satoshis: Number(nextPoolValue),
        })
    )
    if (transition.public.publicOut > 0n) {
        tx.addOutput(
            new bsv.Transaction.Output({
                script: bsv.Script.buildPublicKeyHashOut(wallet.address),
                satoshis: Number(transition.public.publicOut),
            })
        )
    }
    tx.fee(TRANSITION_FEE)
    tx.change(wallet.address)
    current.to = { tx, inputIndex: 0 }
    const pkh = PubKeyHash(int2ByteString(transition.public.recipient, 20n))
    const residueWitness = buildPairingResidueWitness(
        transition.statement,
        proof,
        vk
    )
    const unlocking = current.getUnlockingScript((self) => {
        self.transit(
            proof,
            residueWitness,
            transition.public.mode,
            transition.public.outCount,
            transition.public.newNoteRoot,
            transition.public.newNullifierRoot,
            transition.public.newNextIndex,
            transition.public.nullifier,
            transition.public.outputCommitment0,
            transition.public.outputCommitment1,
            transition.public.publicIn,
            transition.public.publicOut,
            transition.public.recipient,
            transition.public.currentHeight,
            pkh
        )
    })
    if (unlocking instanceof Promise) throw new Error('Unexpected asynchronous unlock builder')
    tx.inputs[0].setScript(unlocking)
    tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))

    const rawHex = tx.toString()
    const bytes = rawHex.length / 2
    const minimumFee = Math.ceil((bytes * 101) / 1_000)
    const outputs = tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const fee = pool.satoshis + funding.satoshis - outputs
    if (fee < minimumFee) throw new Error(`Transition fee ${fee} is below ${minimumFee}`)
    const walletOutputIndex = tx.outputs.length - 1
    if (tx.outputs[walletOutputIndex].script.toAddress(bsv.Networks.testnet).toString() !== wallet.address) {
        throw new Error('Transition change does not return to the deployment wallet')
    }
    return {
        tx,
        txid: tx.id,
        rawHex,
        unlockingHex: unlocking.toHex(),
        bytes,
        fee,
        pool: {
            txid: tx.id,
            vout: 0,
            satoshis: Number(nextPoolValue),
            noteRoot: transition.public.newNoteRoot,
            nullifierRoot: transition.public.newNullifierRoot,
            nextIndex: transition.public.newNextIndex,
        },
        wallet: {
            txid: tx.id,
            vout: walletOutputIndex,
            satoshis: tx.outputs[walletOutputIndex].satoshis,
        },
    }
}

function buildInvalidReplay(
    unlockingHex: string,
    transition: BuiltTransition,
    vk: ReturnType<typeof toPreparedVerifyingKey>,
    pool: PoolOutpoint,
    funding: Outpoint,
    wallet: WalletFile
): { txid: string; rawHex: string; localError: string } {
    const current = new ShieldedPool(pool.noteRoot, pool.nullifierRoot, pool.nextIndex, vk)
    const next = current.next()
    next.noteRoot = transition.public.newNoteRoot
    next.nullifierRoot = transition.public.newNullifierRoot
    next.nextIndex = transition.public.newNextIndex
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: pool.txid,
        outputIndex: pool.vout,
        script: bsv.Script.fromHex(unlockingHex),
        output: new bsv.Transaction.Output({ script: current.lockingScript, satoshis: pool.satoshis }),
    }))
    tx.from({
        txId: funding.txid,
        outputIndex: funding.vout,
        script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(),
        satoshis: funding.satoshis,
    })
    tx.lockUntilBlockHeight(Number(transition.public.currentHeight))
    tx.addOutput(new bsv.Transaction.Output({ script: next.lockingScript, satoshis: pool.satoshis }))
    tx.fee(TRANSITION_FEE)
    tx.change(wallet.address)
    tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))

    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const interpreter = new bsv.Script.Interpreter()
    const accepted = interpreter.verify(
        tx.inputs[0].script,
        current.lockingScript,
        tx,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(pool.satoshis)
    )
    if (accepted) throw new Error('Local Bitcoin Script accepted a reused nullifier proof')
    return {
        txid: tx.id,
        rawHex: tx.toString(),
        localError: interpreter.errstr || 'script verification failed',
    }
}

function signedEvidence(kind: string, built: BuiltTx, transition: BuiltTransition): unknown {
    return {
        kind,
        txid: built.txid,
        transactionBytes: built.bytes,
        feeSatoshis: built.fee,
        poolOutputSatoshis: built.pool.satoshis,
        walletChangeSatoshis: built.wallet.satoshis,
        public: transition.public,
        rawHex: built.rawHex,
    }
}

function auditPreparedShield(): ShieldAudit {
    if (!existsSync(SHIELD_SIGNED_FILE)) {
        throw new Error('No prepared shield exists; run npm run lifecycle:prepare-shield first')
    }
    const saved = JSON.parse(readFileSync(SHIELD_SIGNED_FILE, 'utf8')) as SavedShield
    const tx = new bsv.Transaction(saved.rawHex)
    if (saved.kind !== 'shield' || tx.id !== saved.txid) {
        throw new Error('Prepared shield TXID does not match its signed bytes')
    }
    if (tx.toString() !== saved.rawHex || tx.toString().length / 2 !== saved.transactionBytes) {
        throw new Error('Prepared shield bytes or size no longer match the reviewed record')
    }
    if (tx.inputs.length !== 2 || tx.outputs.length !== 2) {
        throw new Error('Prepared shield must have exactly two inputs and two outputs')
    }
    for (const [index, vout] of [0, 1].entries()) {
        const input = tx.inputs[index]
        if (
            input.prevTxId.toString('hex') !== saved.deploymentTxid ||
            input.outputIndex !== vout
        ) {
            throw new Error(`Prepared shield input ${index} is not the reviewed deployment outpoint`)
        }
    }
    if (
        tx.outputs[0].satoshis !== saved.poolOutputSatoshis ||
        tx.outputs[1].satoshis !== saved.walletChangeSatoshis
    ) {
        throw new Error('Prepared shield outputs do not match the reviewed values')
    }

    const deployment = JSON.parse(readFileSync(DEPLOYMENT_FILE, 'utf8')) as {
        transactionHex: string
        deploymentTxid: string
    }
    if (deployment.deploymentTxid !== saved.deploymentTxid) {
        throw new Error('Prepared shield references a different deployment record')
    }
    const deployTx = new bsv.Transaction(deployment.transactionHex)
    const inputSatoshis = deployTx.outputs[0].satoshis + deployTx.outputs[1].satoshis
    const outputSatoshis = tx.outputs[0].satoshis + tx.outputs[1].satoshis
    const feeSatoshis = inputSatoshis - outputSatoshis
    if (feeSatoshis !== saved.feeSatoshis) {
        throw new Error('Prepared shield fee does not match the reviewed value')
    }

    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    ShieldedPool.loadArtifact()
    const current = new ShieldedPool(
        BigInt(saved.public.oldNoteRoot),
        BigInt(saved.public.oldNullifierRoot),
        BigInt(saved.public.oldNextIndex),
        vk
    )
    if (current.lockingScript.toHex() !== deployTx.outputs[0].script.toHex()) {
        throw new Error('Prepared shield does not spend the reviewed covenant state')
    }
    const next = current.next()
    next.noteRoot = BigInt(saved.public.newNoteRoot)
    next.nullifierRoot = BigInt(saved.public.newNullifierRoot)
    next.nextIndex = BigInt(saved.public.newNextIndex)
    if (next.lockingScript.toHex() !== tx.outputs[0].script.toHex()) {
        throw new Error('Prepared shield successor output does not match its public state')
    }

    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const numberPolicy = installScriptNumberPolicyMonitor(SCRIPT_NUMBER_POLICY_BYTES)
    const covenantInterpreter = new bsv.Script.Interpreter()
    const startedAt = Date.now()
    let covenantAccepted = false
    try {
        covenantAccepted = covenantInterpreter.verify(
            tx.inputs[0].script,
            current.lockingScript,
            tx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(deployTx.outputs[0].satoshis)
        )
    } finally {
        numberPolicy.restore()
    }
    const covenantMilliseconds = Date.now() - startedAt
    if (!covenantAccepted) {
        throw new Error(
            `Strict local Bitcoin Script audit rejected the shield: ${
                covenantInterpreter.errstr || 'script verification failed'
            }`
        )
    }

    const fundingInterpreter = new bsv.Script.Interpreter()
    const fundingSignatureAccepted = fundingInterpreter.verify(
        tx.inputs[1].script,
        deployTx.outputs[1].script,
        tx,
        1,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(deployTx.outputs[1].satoshis)
    )
    if (!fundingSignatureAccepted) {
        throw new Error(
            `Strict local audit rejected the funding signature: ${
                fundingInterpreter.errstr || 'signature verification failed'
            }`
        )
    }

    return {
        shieldTxid: tx.id,
        transactionBytes: tx.toString().length / 2,
        deploymentInputs: tx.inputs.map(
            (input) => `${input.prevTxId.toString('hex')}:${input.outputIndex}`
        ),
        outputCount: tx.outputs.length,
        poolOutputSatoshis: tx.outputs[0].satoshis,
        walletChangeSatoshis: tx.outputs[1].satoshis,
        feeSatoshis,
        covenantMilliseconds,
        maximumScriptNumberBytes: numberPolicy.maximumBytes(),
        scriptNumberPolicyBytes: SCRIPT_NUMBER_POLICY_BYTES,
        fundingSignatureAccepted: true,
    }
}

function sendPreparedShield(): void {
    if (!existsSync(SHIELD_SIGNED_FILE)) {
        throw new Error('No prepared shield exists; run npm run lifecycle:prepare-shield first')
    }
    if (existsSync(SHIELD_RECEIPT_FILE)) {
        throw new Error(`A shield receipt already exists: ${SHIELD_RECEIPT_FILE}`)
    }
    const expectedArg = process.argv.find((value) => value.startsWith('--expect='))
    const expectedTxid = expectedArg?.slice('--expect='.length).toLowerCase()
    if (!expectedTxid || !/^[0-9a-f]{64}$/.test(expectedTxid)) {
        throw new Error('send-shield requires --expect=<reviewed 64-character TXID>')
    }

    const saved = JSON.parse(readFileSync(SHIELD_SIGNED_FILE, 'utf8')) as SavedShield
    const audit = auditPreparedShield()
    const tx = new bsv.Transaction(saved.rawHex)
    if (saved.kind !== 'shield' || tx.id !== saved.txid || tx.id !== expectedTxid) {
        throw new Error('Prepared shield TXID does not match the explicitly reviewed TXID')
    }
    if (!saved.localValidation.fundingSignatureAccepted || !audit.fundingSignatureAccepted) {
        throw new Error('Prepared shield lacks the recorded local signature validation')
    }

    const existing = arcStatus(saved.txid)
    let arcResponse: ArcStatus
    if (existing.httpStatus === 404) {
        arcResponse = submitValid(saved.txid, saved.rawHex)
    } else if (
        existing.httpStatus === 200 &&
        existing.response.txid?.toLowerCase() === saved.txid &&
        ['QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK',
            'REQUESTED_BY_NETWORK', 'SENT_TO_NETWORK', 'ACCEPTED_BY_NETWORK',
            'SEEN_ON_NETWORK', 'MINED'].includes(existing.response.txStatus ?? '')
    ) {
        arcResponse = existing.response
    } else {
        throw new Error(`ARC preflight refused submission: ${JSON.stringify(existing)}`)
    }

    const receipt = {
        network: 'testnet',
        broadcast: true,
        submittedAt: new Date().toISOString(),
        deploymentTxid: saved.deploymentTxid,
        shieldTxid: saved.txid,
        transactionBytes: saved.transactionBytes,
        feeSatoshis: saved.feeSatoshis,
        poolOutputSatoshis: saved.poolOutputSatoshis,
        walletChangeSatoshis: saved.walletChangeSatoshis,
        arcResponse,
    }
    writePrivate(SHIELD_RECEIPT_FILE, receipt)
    console.log(JSON.stringify(receipt, null, 2))
    console.log(`Shield receipt: ${SHIELD_RECEIPT_FILE}`)
}

function verifyBuiltTxLocally(
    built: BuiltTx,
    pool: PoolOutpoint,
    funding: Outpoint,
    wallet: WalletFile,
    vk: ReturnType<typeof toPreparedVerifyingKey>
): { covenantMilliseconds: number; fundingSignatureAccepted: true } {
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER

    const current = new ShieldedPool(
        pool.noteRoot,
        pool.nullifierRoot,
        pool.nextIndex,
        vk
    )
    const covenantInterpreter = new bsv.Script.Interpreter()
    const startedAt = Date.now()
    const covenantAccepted = covenantInterpreter.verify(
        built.tx.inputs[0].script,
        current.lockingScript,
        built.tx,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(pool.satoshis)
    )
    const covenantMilliseconds = Date.now() - startedAt
    if (!covenantAccepted) {
        throw new Error(
            `Local Bitcoin Script rejected the prepared shield: ${
                covenantInterpreter.errstr || 'script verification failed'
            }`
        )
    }

    const fundingInterpreter = new bsv.Script.Interpreter()
    const fundingSignatureAccepted = fundingInterpreter.verify(
        built.tx.inputs[1].script,
        bsv.Script.buildPublicKeyHashOut(wallet.address),
        built.tx,
        1,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(funding.satoshis)
    )
    if (!fundingSignatureAccepted) {
        throw new Error(
            `Local Bitcoin Script rejected the funding signature: ${
                fundingInterpreter.errstr || 'signature verification failed'
            }`
        )
    }
    return { covenantMilliseconds, fundingSignatureAccepted: true }
}

async function main(): Promise<void> {
    const command = process.argv[2] ?? 'run'
    if (!['run', 'prepare-shield', 'audit-shield', 'send-shield'].includes(command)) {
        throw new Error(
            'Usage: testnet-lifecycle.ts prepare-shield | audit-shield | send-shield | run'
        )
    }
    for (const file of [WALLET_FILE, DEPLOYMENT_FILE, DEPLOYMENT_CONFIRMATION_FILE, VKEY, WASM, ZKEY]) {
        if (!existsSync(file)) throw new Error(`Required lifecycle input is missing: ${file}`)
    }
    if (command === 'send-shield') {
        sendPreparedShield()
        return
    }
    if (command === 'audit-shield') {
        console.log(JSON.stringify(auditPreparedShield(), null, 2))
        return
    }
    if (
        existsSync(SECRETS_FILE) ||
        existsSync(SHIELD_SIGNED_FILE) ||
        existsSync(EVIDENCE_FILE)
    ) {
        throw new Error('Lifecycle evidence already exists; inspect it before any rerun')
    }
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (key.toAddress(bsv.Networks.testnet).toString() !== wallet.address) {
        throw new Error('Deployment wallet key/address mismatch')
    }
    const deployment = JSON.parse(readFileSync(DEPLOYMENT_FILE, 'utf8')) as {
        transactionHex: string
        deploymentTxid: string
        initialState: { noteRoot: string; nullifierRoot: string; nextNoteIndex: string }
    }
    const confirmation = JSON.parse(readFileSync(DEPLOYMENT_CONFIRMATION_FILE, 'utf8')) as {
        txStatus: string
        txid: string
    }
    if (confirmation.txStatus !== 'MINED' || confirmation.txid !== deployment.deploymentTxid) {
        throw new Error('Deployment is not confirmed')
    }
    const deployTx = new bsv.Transaction(deployment.transactionHex)
    const hash = await createHash()
    const state = new PoolState(hash)
    const initial = {
        noteRoot: state.noteTree.root(),
        nullifierRoot: state.nullifierTree.root(),
        nextIndex: 0n,
    }
    if (
        initial.noteRoot.toString() !== deployment.initialState.noteRoot ||
        initial.nullifierRoot.toString() !== deployment.initialState.nullifierRoot
    ) throw new Error('Deployment roots do not match an empty local pool')

    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    let pool: PoolOutpoint = {
        txid: deployment.deploymentTxid,
        vout: 0,
        satoshis: deployTx.outputs[0].satoshis,
        ...initial,
    }
    let funding: Outpoint = {
        txid: deployment.deploymentTxid,
        vout: 1,
        satoshis: deployTx.outputs[1].satoshis,
    }
    const secrets = {
        senderKey: randomField(),
        receiverKey: randomField(),
        shieldRho: randomField(),
        receiverRho: randomField(),
        senderChangeRho: randomField(),
        receiverChangeRho: randomField(),
    }
    const privateEvidence: Record<string, unknown> = { secrets, signed: {} }
    const publicEvidence: Record<string, unknown> = {
        network: 'testnet',
        deploymentTxid: deployment.deploymentTxid,
        startedAt: new Date().toISOString(),
        actions: [],
    }

    console.log('Generating shield proof…')
    const shield = state.build({
        mode: 0,
        publicIn: SHIELD_SATS,
        outputs: [{ amount: SHIELD_SATS, ownerKey: secrets.senderKey, rho: secrets.shieldRho }],
    })
    const shieldBuilt = buildTransitionTx(shield, await prove(shield), vk, pool, funding, wallet)
    ;(privateEvidence.signed as Record<string, unknown>).shield = signedEvidence('shield', shieldBuilt, shield)

    if (command === 'prepare-shield') {
        console.log('Executing the complete shield transaction locally…')
        const localValidation = verifyBuiltTxLocally(
            shieldBuilt,
            pool,
            funding,
            wallet,
            vk
        )
        writePrivate(SECRETS_FILE, { secrets })
        writePrivate(SHIELD_SIGNED_FILE, {
            createdAt: new Date().toISOString(),
            deploymentTxid: deployment.deploymentTxid,
            ...signedEvidence('shield', shieldBuilt, shield) as Record<string, unknown>,
            localValidation,
        })
        console.log(JSON.stringify(jsonSafe({
            network: 'testnet',
            broadcast: false,
            deploymentTxid: deployment.deploymentTxid,
            poolInput: `${pool.txid}:${pool.vout}`,
            fundingInput: `${funding.txid}:${funding.vout}`,
            shieldTxid: shieldBuilt.txid,
            transactionBytes: shieldBuilt.bytes,
            feeSatoshis: shieldBuilt.fee,
            publicInSatoshis: SHIELD_SATS,
            poolOutputSatoshis: shieldBuilt.pool.satoshis,
            walletChangeSatoshis: shieldBuilt.wallet.satoshis,
            nextNoteRoot: shield.public.newNoteRoot,
            nextNullifierRoot: shield.public.newNullifierRoot,
            nextNoteIndex: shield.public.newNextIndex,
            localValidation,
            signedTransactionFile: SHIELD_SIGNED_FILE,
        }), null, 2))
        return
    }

    writePrivate(SECRETS_FILE, privateEvidence)
    console.log(`Submitting shield ${shieldBuilt.txid}…`)
    const shieldAccepted = submitValid(shieldBuilt.txid, shieldBuilt.rawHex)
    const shieldMined = await waitForMined(shieldBuilt.txid)
    ;(publicEvidence.actions as unknown[]).push({
        kind: 'shield', txid: shieldBuilt.txid, publicInSatoshis: SHIELD_SATS,
        feeSatoshis: shieldBuilt.fee, accepted: shieldAccepted, mined: shieldMined,
    })
    pool = shieldBuilt.pool
    funding = shieldBuilt.wallet

    const transferHeight = currentHeight()
    const lockHeight = transferHeight + 3
    console.log(`Generating private-transfer proof; receiver note locks until ${lockHeight}…`)
    const transfer = state.build({
        mode: 1,
        spend: { note: shield.outputNotes[0] },
        currentHeight: BigInt(transferHeight),
        outputs: [
            { amount: RECEIVER_SATS, ownerKey: secrets.receiverKey, rho: secrets.receiverRho, lockHeight: BigInt(lockHeight) },
            { amount: SENDER_CHANGE_SATS, ownerKey: secrets.senderKey, rho: secrets.senderChangeRho },
        ],
    })
    const transferBuilt = buildTransitionTx(transfer, await prove(transfer), vk, pool, funding, wallet)
    ;(privateEvidence.signed as Record<string, unknown>).transfer = signedEvidence('transfer', transferBuilt, transfer)
    console.log(`Submitting private transfer ${transferBuilt.txid}…`)
    const transferAccepted = submitValid(transferBuilt.txid, transferBuilt.rawHex)
    const transferMined = await waitForMined(transferBuilt.txid)
    ;(publicEvidence.actions as unknown[]).push({
        kind: 'private-transfer', txid: transferBuilt.txid,
        nullifier: transfer.public.nullifier, feeSatoshis: transferBuilt.fee,
        receiverLockHeight: lockHeight, accepted: transferAccepted, mined: transferMined,
    })
    pool = transferBuilt.pool
    funding = transferBuilt.wallet

    let localReuseError = ''
    try {
        state.build({
            mode: 1,
            spend: { note: shield.outputNotes[0] },
            currentHeight: BigInt(currentHeight()),
            outputs: [{ amount: SHIELD_SATS, ownerKey: secrets.senderKey, rho: randomField() }],
        })
    } catch (error) {
        localReuseError = error instanceof Error ? error.message : String(error)
    }
    if (!localReuseError.includes('already spent')) {
        throw new Error('Local state did not reject nullifier reuse')
    }
    const replay = buildInvalidReplay(
        transferBuilt.unlockingHex,
        transfer,
        vk,
        pool,
        funding,
        wallet
    )
    console.log(`Submitting expected-invalid nullifier replay ${replay.txid}…`)
    const replayRejected = submitExpectedRejection(replay.txid, replay.rawHex)
    ;(publicEvidence.actions as unknown[]).push({
        kind: 'nullifier-reuse-rejection', txid: replay.txid,
        nullifier: transfer.public.nullifier, localError: localReuseError,
        scriptError: replay.localError, arc: replayRejected,
    })

    console.log(`Generating height-locked unshield proof for block ${lockHeight}…`)
    const unshield = state.build({
        mode: 2,
        spend: { note: transfer.outputNotes[0] },
        currentHeight: BigInt(lockHeight),
        publicOut: WITHDRAW_SATS,
        recipient: recipientField(wallet.address),
        outputs: [{
            amount: RECEIVER_CHANGE_SATS,
            ownerKey: secrets.receiverKey,
            rho: secrets.receiverChangeRho,
        }],
    })
    const unshieldBuilt = buildTransitionTx(unshield, await prove(unshield), vk, pool, funding, wallet)
    ;(privateEvidence.signed as Record<string, unknown>).unshield = signedEvidence('unshield', unshieldBuilt, unshield)
    const beforeLock = currentHeight()
    if (beforeLock >= lockHeight) {
        throw new Error(`Height advanced to ${beforeLock} before the early-lock rejection could run`)
    }
    console.log(`Submitting unshield early at tip ${beforeLock}; nLockTime=${lockHeight}…`)
    const earlyRejected = submitExpectedRejection(unshieldBuilt.txid, unshieldBuilt.rawHex)
    ;(publicEvidence.actions as unknown[]).push({
        kind: 'early-unshield-rejection', txid: unshieldBuilt.txid,
        observedTip: beforeLock, requiredHeight: lockHeight, arc: earlyRejected,
    })

    await waitForHeight(lockHeight)
    const statusBeforeMatureSend = arcStatus(unshieldBuilt.txid)
    if (statusBeforeMatureSend.httpStatus !== 404) {
        throw new Error('Early unshield unexpectedly exists in ARC before mature submission')
    }
    console.log(`Height ${lockHeight} reached; submitting the identical unshield transaction…`)
    const unshieldAccepted = submitValid(unshieldBuilt.txid, unshieldBuilt.rawHex)
    const unshieldMined = await waitForMined(unshieldBuilt.txid)
    ;(publicEvidence.actions as unknown[]).push({
        kind: 'unshield', txid: unshieldBuilt.txid,
        publicOutSatoshis: WITHDRAW_SATS, requiredHeight: lockHeight,
        feeSatoshis: unshieldBuilt.fee, accepted: unshieldAccepted, mined: unshieldMined,
    })
    publicEvidence.completedAt = new Date().toISOString()
    publicEvidence.finalPoolSatoshis = unshieldBuilt.pool.satoshis
    publicEvidence.finalWalletChangeSatoshis = unshieldBuilt.wallet.satoshis
    writePrivate(EVIDENCE_FILE, publicEvidence)
    console.log(JSON.stringify(jsonSafe(publicEvidence), null, 2))
    console.log(`Lifecycle evidence: ${EVIDENCE_FILE}`)
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error instanceof Error ? error.message : error)
        process.exit(1)
    }
)
