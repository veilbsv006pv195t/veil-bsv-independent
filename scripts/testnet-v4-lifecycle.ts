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
    hash256,
    int2ByteString,
    PubKeyHash,
    Sha256,
    toByteString,
} from 'scrypt-ts'
import { groth16 } from 'snarkjs'
import { BN256, BN256Pairing, LineFuncRes } from 'scrypt-ts-lib/dist/ec/bn256'
import { FIELD, PoolState, createHash } from '../src/crypto'
import type { Note } from '../src/crypto'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'
import { ShieldedPoolV4 } from '../src/v4/shieldedPoolV4'
import { StagedGroth16 } from '../src/v4/stagedGroth16'
import {
    V4MillerState,
    V4PreparationState,
    V4State,
    V4Transition,
} from '../src/v4/v4State'
import { VeilV4Finalizer } from '../src/v4/veilV4Finalizer'
import { VeilV4Miller0 } from '../src/v4/veilV4Miller0'
import { VeilV4Miller1 } from '../src/v4/veilV4Miller1'
import { VeilV4Miller2 } from '../src/v4/veilV4Miller2'
import { VeilV4Miller3 } from '../src/v4/veilV4Miller3'
import { VeilV4Preparation } from '../src/v4/veilV4Preparation'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')
const DEPLOYMENT_FILE = path.join(PRIVATE_DIR, 'testnet-v4-deployment-signed.json')
const CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-deployment-confirmation.json'
)
const SECRETS_FILE = path.join(PRIVATE_DIR, 'testnet-v4-shield-secrets.json')
const SIGNED_FILE = path.join(PRIVATE_DIR, 'testnet-v4-shield-signed.json')
const SPLIT_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-shield-split-receipt.json'
)
const BEGIN_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-shield-begin-receipt.json'
)
const SHIELD_CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-shield-confirmation.json'
)
const TRANSFER_SECRETS_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-secrets.json'
)
const TRANSFER_SIGNED_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-signed.json'
)
const TRANSFER_SPLIT_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-split-receipt.json'
)
const TRANSFER_BEGIN_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-begin-receipt.json'
)
const TRANSFER_CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-confirmation.json'
)
const WASM = path.join(ROOT, 'build', 'shielded_pool_js', 'shielded_pool.wasm')
const ZKEY = path.join(ROOT, 'build', 'shielded_pool_final.zkey')
const VKEY = path.join(ROOT, 'build', 'verification_key.json')
const SOCKS = '127.0.0.1:19050'
const ARCADE = 'https://testnet.arcade.gorillapool.io'
const ARC = 'https://testnet.arc.gorillapool.io'
const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))
const SCRIPT_POLICY_BYTES = 500_000
const SCRIPT_NUMBER_POLICY_BYTES = 10_000
const SHIELD_SATS = 100_000n
const TRANSFER_RECEIVER_SATS = 60_000n
const TRANSFER_LOCK_DELAY_BLOCKS = 12
const SPLIT_FEE_SATS = 1_000
const ABORT_DELAY_BLOCKS = 144n
const SPONSORS = [
    { name: 'begin', sats: 161_000 },
    { name: 'prepare', sats: 80_000 },
    { name: 'miller-0', sats: 75_000 },
    { name: 'miller-1', sats: 75_000 },
    { name: 'miller-2', sats: 75_000 },
    { name: 'miller-3', sats: 45_000 },
    { name: 'finalize', sats: 21_000 },
    { name: 'abort-reserve', sats: 40_000 },
] as const
const TRANSFER_SPONSORS = [
    { name: 'begin', sats: 61_000 },
    ...SPONSORS.slice(1),
] as const
const DIGITS = [
    1, 0, 1, 0, 0, -1, 0, 1, 1, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1,
    1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 1, 1, 0,
    0, 1, 0, 0, -1, 1, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0,
] as const

export interface WalletFile {
    network: 'testnet'
    address: string
    wif: string
}

export interface Policy {
    miningFee: { satoshis: number; bytes: number }
    maxtxsizepolicy: number
    maxscriptsizepolicy: number
}

export interface SavedStage {
    name: string
    sponsorOutputIndex: number
    txid: string
    rawHex: string
    transactionBytes: number
    feeSatoshis: number
    covenantMilliseconds: number
    maximumScriptNumberBytes: number
}

interface SavedShield {
    format: 'veil-v4-testnet-shield-plan-v1'
    network: 'testnet'
    broadcast: false
    createdAt: string
    deploymentTxid: string
    split: {
        txid: string
        rawHex: string
        transactionBytes: number
        feeSatoshis: number
        changeOutputIndex: number
        changeSatoshis: number
    }
    startHeight: number
    abortHeight: number
    publicInSatoshis: number
    poolOutputSatoshis: number
    nextState: {
        noteRoot: string
        nullifierRoot: string
        nextNoteIndex: string
    }
    livePolicy: Policy
    stages: SavedStage[]
}

interface SavedTransfer {
    format: 'veil-v4-testnet-transfer-plan-v1'
    network: 'testnet'
    broadcast: false
    createdAt: string
    shieldFinalizerTxid: string
    shieldFinalizerBlockHeight: number
    fundingSource: {
        txid: string
        outputIndex: number
        satoshis: number
    }
    split: SavedShield['split']
    startHeight: number
    abortHeight: number
    receiverLockHeight: number
    poolOutputSatoshis: number
    spentCommitment: string
    nullifier: string
    nextState: SavedShield['nextState']
    livePolicy: Policy
    stages: SavedStage[]
    negativeTests: {
        localNullifierReuseRejected: true
        updatedPoolReplayRejected: true
        updatedPoolReplayError: string
    }
}

interface ShieldSecrets {
    note: Note
    ownerKey: string
    shieldRho: string
}

export function jsonSafe(value: unknown): unknown {
    if (typeof value === 'bigint') return value.toString()
    if (Array.isArray(value)) return value.map(jsonSafe)
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [key, jsonSafe(item)])
        )
    }
    return value
}

export function writePrivate(file: string, value: unknown): void {
    mkdirSync(PRIVATE_DIR, { recursive: true, mode: 0o700 })
    chmodSync(PRIVATE_DIR, 0o700)
    writeFileSync(file, `${JSON.stringify(jsonSafe(value), null, 2)}\n`, {
        flag: 'wx',
        mode: 0o600,
    })
    chmodSync(file, 0o600)
}

export function torJson(url: string): unknown {
    if (!url.startsWith(`${ARCADE}/`) && !url.startsWith(`${ARC}/`)) {
        throw new Error('URL outside v4 allowlist')
    }
    const result = spawnSync(
        'curl',
        [
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
            '60',
            url,
        ],
        {
            encoding: 'utf8',
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
        throw new Error(
            `Tor-only request failed: ${(result.stderr || result.error?.message || '').trim()}`
        )
    }
    return JSON.parse(result.stdout) as unknown
}

export function torPostTransaction(
    rawHex: string,
    waitForStatus = 'SEEN_ON_NETWORK'
): { httpStatus: number; response: unknown } {
    const marker = '__VEIL_HTTP__:'
    const result = spawnSync(
        'curl',
        [
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
            '180',
            '--request',
            'POST',
            '--header',
            'Content-Type: text/plain',
            '--header',
            `X-WaitForStatus: ${waitForStatus}`,
            '--data-binary',
            '@-',
            '--write-out',
            `\n${marker}%{http_code}`,
            `${ARC}/v1/tx`,
        ],
        {
            input: rawHex,
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
        }
    )
    if (result.error || result.status !== 0) {
        throw new Error(
            `Tor-only submission failed: ${(result.stderr || result.error?.message || '').trim()}`
        )
    }
    const split = result.stdout.lastIndexOf(`\n${marker}`)
    if (split < 0) throw new Error('ARC response omitted its HTTP status')
    const httpStatus = Number(result.stdout.slice(split + marker.length + 1))
    const text = result.stdout.slice(0, split)
    let response: unknown = text
    try {
        response = JSON.parse(text)
    } catch {
        // Preserve a non-JSON rejection in the private receipt.
    }
    return { httpStatus, response }
}

export function livePolicy(): Policy {
    const value = torJson(`${ARCADE}/policy`) as { policy?: Partial<Policy> }
    const policy = value.policy
    if (
        !policy ||
        !policy.miningFee ||
        !Number.isSafeInteger(policy.miningFee.satoshis) ||
        !Number.isSafeInteger(policy.miningFee.bytes) ||
        !Number.isSafeInteger(policy.maxtxsizepolicy) ||
        !Number.isSafeInteger(policy.maxscriptsizepolicy)
    ) throw new Error('Arcade returned an invalid policy')
    if ((policy.maxscriptsizepolicy as number) !== SCRIPT_POLICY_BYTES) {
        throw new Error(`Unexpected script policy ${policy.maxscriptsizepolicy}`)
    }
    return policy as Policy
}

export function liveHeight(): number {
    const value = torJson(`${ARCADE}/health`) as { blockHeight?: number }
    if (!Number.isSafeInteger(value.blockHeight) || (value.blockHeight as number) <= 0) {
        throw new Error('Arcade returned an invalid testnet height')
    }
    return value.blockHeight as number
}

export function randomField(): bigint {
    const value = BigInt(`0x${randomBytes(32).toString('hex')}`) % FIELD
    return value === 0n ? 1n : value
}

export function loadArtifacts(): void {
    ShieldedPoolV4.loadArtifact('artifacts/src/v4/shieldedPoolV4.json')
    VeilV4Preparation.loadArtifact('artifacts/src/v4/veilV4Preparation.json')
    VeilV4Miller0.loadArtifact('artifacts/src/v4/veilV4Miller0.json')
    VeilV4Miller1.loadArtifact('artifacts/src/v4/veilV4Miller1.json')
    VeilV4Miller2.loadArtifact('artifacts/src/v4/veilV4Miller2.json')
    VeilV4Miller3.loadArtifact('artifacts/src/v4/veilV4Miller3.json')
    VeilV4Finalizer.loadArtifact('artifacts/src/v4/veilV4Finalizer.json')
}

function installScriptNumberPolicyMonitor(limit: number) {
    const BNClass = bsv.crypto.BN as unknown as {
        fromScriptNumBuffer(
            buffer: Buffer,
            requireMinimal?: boolean,
            size?: number
        ): bsv.crypto.BN
    }
    const original = BNClass.fromScriptNumBuffer
    let maximumBytes = 0
    BNClass.fromScriptNumBuffer = function (buffer, requireMinimal, size) {
        if (size === undefined) {
            maximumBytes = Math.max(maximumBytes, buffer.length)
            if (buffer.length > limit) {
                throw new Error(`script number overflow: ${buffer.length} > ${limit}`)
            }
        }
        return original.call(this, buffer, requireMinimal, size)
    }
    return {
        restore: () => (BNClass.fromScriptNumBuffer = original),
        maximumBytes: () => maximumBytes,
    }
}

export function runSlice(
    snapshot: V4MillerState,
    vk: ReturnType<typeof toPreparedVerifyingKey>,
    digitStart: number,
    lineStart: number
): V4MillerState {
    let acc = snapshot.acc
    let r = snapshot.r
    let lineIndex = lineStart
    const qMinus = BN256.negTwistPoint(snapshot.q)
    const addR20 = BN256.squareFQ2(snapshot.q.y)
    let line: LineFuncRes
    for (let i = digitStart; i < digitStart + 16; i++) {
        const digit = DIGITS[i]
        acc = BN256.squareFQ12(acc)
        if (digit === 1) acc = BN256.mulFQ12(acc, snapshot.residueInverse)
        if (digit === -1) acc = BN256.mulFQ12(acc, snapshot.residue)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, vk.gammaLines[lineIndex], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, vk.deltaLines[lineIndex], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        lineIndex++
        if (digit !== 0) {
            line = BN256Pairing.lineFuncAdd(
                r,
                digit === 1 ? snapshot.q : qMinus,
                snapshot.p0,
                addR20
            )
            acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
            acc = StagedGroth16.mulPreparedLine(acc, vk.gammaLines[lineIndex], snapshot.p1)
            acc = StagedGroth16.mulPreparedLine(acc, vk.deltaLines[lineIndex], snapshot.p2)
            r = BN256.modTwistPoint(line.rOut)
            lineIndex++
        }
        acc = BN256.modFQ12(acc)
    }
    return { ...snapshot, acc, r }
}

export function makeStageTx(
    previousTxid: string,
    currentScript: bsv.Script,
    sourceValue: number,
    splitTxid: string,
    sponsorIndex: number,
    sponsorValue: number,
    sponsorScript: bsv.Script,
    nextScript: bsv.Script,
    nextValue: number,
    lockHeight?: number,
    change?: { address: string; feeSatoshis: number }
): bsv.Transaction {
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: previousTxid,
        outputIndex: 0,
        script: bsv.Script.empty(),
        output: new bsv.Transaction.Output({ script: currentScript, satoshis: sourceValue }),
    }))
    tx.from({
        txId: splitTxid,
        outputIndex: sponsorIndex,
        script: sponsorScript.toHex(),
        satoshis: sponsorValue,
    })
    tx.addOutput(new bsv.Transaction.Output({ script: nextScript, satoshis: nextValue }))
    if (lockHeight !== undefined) tx.lockUntilBlockHeight(lockHeight)
    if (change) {
        tx.fee(change.feeSatoshis)
        tx.change(change.address)
    }
    return tx
}

export function completeStage(
    name: string,
    current: any,
    tx: bsv.Transaction,
    sourceValue: number,
    sponsorValue: number,
    walletKey: bsv.PrivateKey,
    feeRate: number,
    unlock: (self: any) => void,
    sponsorOutputIndex: number
): SavedStage {
    current.to = { tx, inputIndex: 0 }
    const unlocking = current.getUnlockingScript(unlock)
    if (unlocking instanceof Promise) throw new Error(`Unexpected async ${name} builder`)
    if (unlocking.toBuffer().length > SCRIPT_POLICY_BYTES) {
        throw new Error(`${name} unlocking script exceeds live policy`)
    }
    tx.inputs[0].setScript(unlocking)
    tx.sign(walletKey)
    const bytes = tx.toString().length / 2
    const outputs = tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const fee = sourceValue + sponsorValue - outputs
    const minimumFee = Math.ceil((bytes * feeRate) / 1_000)
    if (fee < minimumFee) throw new Error(`${name} fee ${fee} is below ${minimumFee}`)
    if (bytes > 10_485_760) throw new Error(`${name} exceeds transaction policy`)

    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const monitor = installScriptNumberPolicyMonitor(SCRIPT_NUMBER_POLICY_BYTES)
    const covenant = new bsv.Script.Interpreter()
    const started = performance.now()
    let accepted = false
    try {
        accepted = covenant.verify(
            tx.inputs[0].script,
            current.lockingScript,
            tx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(sourceValue)
        )
    } finally {
        monitor.restore()
    }
    if (!accepted) throw new Error(`${name} covenant rejected: ${covenant.errstr}`)
    const p2pkh = new bsv.Script.Interpreter()
    const sponsorAccepted = p2pkh.verify(
        tx.inputs[1].script,
        bsv.Script.buildPublicKeyHashOut(walletKey.toAddress(bsv.Networks.testnet)),
        tx,
        1,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(sponsorValue)
    )
    if (!sponsorAccepted) throw new Error(`${name} sponsor signature rejected: ${p2pkh.errstr}`)
    return {
        name,
        sponsorOutputIndex,
        txid: tx.id,
        rawHex: tx.toString(),
        transactionBytes: bytes,
        feeSatoshis: fee,
        covenantMilliseconds: Math.round(performance.now() - started),
        maximumScriptNumberBytes: monitor.maximumBytes(),
    }
}

function auditSaved(saved: SavedShield, policy: Policy): unknown {
    const deployment = JSON.parse(readFileSync(DEPLOYMENT_FILE, 'utf8')) as {
        deploymentTxid: string
        transactionHex: string
    }
    const deploymentTx = new bsv.Transaction(deployment.transactionHex)
    if (
        deployment.deploymentTxid !== saved.deploymentTxid ||
        deploymentTx.id !== saved.deploymentTxid
    ) throw new Error('Saved shield references a different deployment')
    const split = new bsv.Transaction(saved.split.rawHex)
    if (split.id !== saved.split.txid || split.toString().length / 2 !== saved.split.transactionBytes) {
        throw new Error('Funding split bytes do not match the reviewed record')
    }
    if (
        split.inputs.length !== 1 ||
        split.inputs[0].prevTxId.toString('hex') !== saved.deploymentTxid ||
        split.inputs[0].outputIndex !== 1
    ) throw new Error('Funding split does not spend the deployment change output')
    const splitSignature = new bsv.Script.Interpreter()
    if (!splitSignature.verify(
        split.inputs[0].script,
        deploymentTx.outputs[1].script,
        split,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(deploymentTx.outputs[1].satoshis)
    )) throw new Error(`Funding split signature rejected: ${splitSignature.errstr}`)
    const splitFee = deploymentTx.outputs[1].satoshis -
        split.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    if (splitFee !== saved.split.feeSatoshis) throw new Error('Funding split fee changed')

    let previous = deploymentTx
    const results: unknown[] = []
    const expectedNames = ['begin', 'prepare', 'miller-0', 'miller-1', 'miller-2', 'miller-3', 'finalize']
    for (let index = 0; index < saved.stages.length; index++) {
        const record = saved.stages[index]
        if (record.name !== expectedNames[index]) throw new Error('Unexpected v4 stage order')
        const tx = new bsv.Transaction(record.rawHex)
        if (tx.id !== record.txid || tx.toString().length / 2 !== record.transactionBytes) {
            throw new Error(`${record.name} signed bytes changed`)
        }
        const expectedOutputCount =
            record.name === 'begin' || record.name === 'finalize' ? 2 : 1
        if (
            tx.inputs.length !== 2 ||
            tx.outputs.length !== expectedOutputCount ||
            tx.inputs[0].prevTxId.toString('hex') !== previous.id ||
            tx.inputs[0].outputIndex !== 0 ||
            tx.inputs[1].prevTxId.toString('hex') !== split.id ||
            tx.inputs[1].outputIndex !== record.sponsorOutputIndex
        ) throw new Error(`${record.name} outpoint chain changed`)
        const source = previous.outputs[0]
        const sponsor = split.outputs[record.sponsorOutputIndex]
        if (
            expectedOutputCount === 2 &&
            (tx.outputs[1].satoshis !== 1_000 ||
                tx.outputs[1].script.toHex() !== sponsor.script.toHex())
        ) throw new Error(`${record.name} change output changed`)
        const fee = source.satoshis + sponsor.satoshis -
            tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
        const minimumFee = Math.ceil(
            (record.transactionBytes * policy.miningFee.satoshis) /
            policy.miningFee.bytes
        )
        if (fee !== record.feeSatoshis || fee < minimumFee) {
            throw new Error(`${record.name} fee audit failed`)
        }
        const scripts = [
            ...tx.inputs.map((input) => input.script.toBuffer().length),
            ...tx.outputs.map((output) => output.script.toBuffer().length),
        ]
        if (Math.max(...scripts) > policy.maxscriptsizepolicy) {
            throw new Error(`${record.name} exceeds current script policy`)
        }
        const monitor = installScriptNumberPolicyMonitor(SCRIPT_NUMBER_POLICY_BYTES)
        const covenant = new bsv.Script.Interpreter()
        let covenantAccepted = false
        try {
            covenantAccepted = covenant.verify(
                tx.inputs[0].script,
                source.script,
                tx,
                0,
                bsv.Script.Interpreter.DEFAULT_FLAGS,
                new bsv.crypto.BN(source.satoshis)
            )
        } finally {
            monitor.restore()
        }
        if (!covenantAccepted) throw new Error(`${record.name} audit rejected: ${covenant.errstr}`)
        const sponsorCheck = new bsv.Script.Interpreter()
        if (!sponsorCheck.verify(
            tx.inputs[1].script,
            sponsor.script,
            tx,
            1,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(sponsor.satoshis)
        )) throw new Error(`${record.name} sponsor audit rejected: ${sponsorCheck.errstr}`)
        results.push({
            name: record.name,
            txid: record.txid,
            transactionBytes: record.transactionBytes,
            feeSatoshis: fee,
            maximumScriptNumberBytes: monitor.maximumBytes(),
            covenantAccepted: true,
            sponsorSignatureAccepted: true,
        })
        previous = tx
    }
    if (previous.outputs[0].satoshis !== saved.poolOutputSatoshis) {
        throw new Error('Final pool value changed')
    }
    return {
        network: 'testnet',
        broadcast: false,
        deploymentTxid: saved.deploymentTxid,
        splitTxid: saved.split.txid,
        splitSignatureAccepted: true,
        splitFeeSatoshis: splitFee,
        currentPolicy: policy,
        startHeight: saved.startHeight,
        abortHeight: saved.abortHeight,
        publicInSatoshis: saved.publicInSatoshis,
        finalPoolSatoshis: previous.outputs[0].satoshis,
        nextState: saved.nextState,
        stages: results,
    }
}

export function requireMinedStatus(txid: string): {
    txid: string
    txStatus: 'MINED'
    blockHeight: number
    blockHash: string
    merklePath: string
} {
    const status = torJson(`${ARC}/v1/tx/${txid}`) as {
        txid?: string
        txStatus?: string
        blockHeight?: number
        blockHash?: string
        merklePath?: string
    }
    if (
        status.txid?.toLowerCase() !== txid.toLowerCase() ||
        status.txStatus !== 'MINED' ||
        !Number.isSafeInteger(status.blockHeight) ||
        (status.blockHeight as number) <= 0 ||
        !/^[0-9a-f]{64}$/i.test(status.blockHash ?? '') ||
        !status.merklePath
    ) throw new Error(`${txid} lacks mined inclusion evidence`)
    return status as ReturnType<typeof requireMinedStatus>
}

function confirmShield(): void {
    if (!existsSync(SIGNED_FILE)) throw new Error('No prepared v4 shield exists')
    const saved = JSON.parse(readFileSync(SIGNED_FILE, 'utf8')) as SavedShield
    auditSaved(saved, livePolicy())
    const finalizer = saved.stages.at(-1)
    if (!finalizer || finalizer.name !== 'finalize') {
        throw new Error('The saved shield has no finalizer')
    }
    const mined = requireMinedStatus(finalizer.txid)
    const confirmation = {
        format: 'veil-v4-testnet-shield-confirmation-v1',
        network: 'testnet',
        recordedAt: new Date().toISOString(),
        finalizerTxid: mined.txid,
        blockHeight: mined.blockHeight,
        blockHash: mined.blockHash,
        merklePath: mined.merklePath,
        merkleInclusionEvidenceAvailable: true,
        finalPoolSatoshis: saved.poolOutputSatoshis,
        nextState: saved.nextState,
    }
    if (existsSync(SHIELD_CONFIRMATION_FILE)) {
        const existing = JSON.parse(readFileSync(SHIELD_CONFIRMATION_FILE, 'utf8'))
        if (JSON.stringify(existing) !== JSON.stringify(confirmation)) {
            const stableExisting = { ...(existing as Record<string, unknown>) }
            const stableCurrent = { ...confirmation } as Record<string, unknown>
            delete stableExisting.recordedAt
            delete stableCurrent.recordedAt
            if (JSON.stringify(stableExisting) !== JSON.stringify(stableCurrent)) {
                throw new Error('Existing shield confirmation conflicts with live mined evidence')
            }
        }
        console.log(JSON.stringify(existing, null, 2))
        return
    }
    writePrivate(SHIELD_CONFIRMATION_FILE, confirmation)
    console.log(JSON.stringify(confirmation, null, 2))
}

function auditTransferSaved(saved: SavedTransfer, policy: Policy): unknown {
    if (!existsSync(SHIELD_CONFIRMATION_FILE)) {
        throw new Error('Shield confirmation is missing')
    }
    const shield = JSON.parse(readFileSync(SIGNED_FILE, 'utf8')) as SavedShield
    auditSaved(shield, policy)
    const shieldConfirmation = JSON.parse(
        readFileSync(SHIELD_CONFIRMATION_FILE, 'utf8')
    ) as {
        finalizerTxid: string
        blockHeight: number
        blockHash: string
        merklePath: string
    }
    const shieldFinalizer = shield.stages.at(-1)
    if (
        !shieldFinalizer ||
        shieldFinalizer.name !== 'finalize' ||
        shieldFinalizer.txid !== saved.shieldFinalizerTxid ||
        shieldConfirmation.finalizerTxid !== saved.shieldFinalizerTxid ||
        shieldConfirmation.blockHeight !== saved.shieldFinalizerBlockHeight ||
        !shieldConfirmation.merklePath
    ) throw new Error('Transfer source does not match the confirmed shield finalizer')
    const sourceTx = new bsv.Transaction(shieldFinalizer.rawHex)
    if (sourceTx.id !== saved.shieldFinalizerTxid) {
        throw new Error('Shield finalizer bytes changed')
    }
    const shieldSplit = new bsv.Transaction(shield.split.rawHex)
    const fundingOutput = shieldSplit.outputs[saved.fundingSource.outputIndex]
    if (
        shieldSplit.id !== saved.fundingSource.txid ||
        !fundingOutput ||
        fundingOutput.satoshis !== saved.fundingSource.satoshis
    ) throw new Error('Transfer funding source changed')

    const split = new bsv.Transaction(saved.split.rawHex)
    if (split.id !== saved.split.txid || split.toString().length / 2 !== saved.split.transactionBytes) {
        throw new Error('Transfer funding split bytes changed')
    }
    if (
        split.inputs.length !== 1 ||
        split.inputs[0].prevTxId.toString('hex') !== saved.fundingSource.txid ||
        split.inputs[0].outputIndex !== saved.fundingSource.outputIndex
    ) throw new Error('Transfer funding split spends the wrong outpoint')
    const splitSignature = new bsv.Script.Interpreter()
    if (!splitSignature.verify(
        split.inputs[0].script,
        fundingOutput.script,
        split,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(fundingOutput.satoshis)
    )) throw new Error(`Transfer funding signature rejected: ${splitSignature.errstr}`)
    const splitFee = fundingOutput.satoshis -
        split.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    if (splitFee !== saved.split.feeSatoshis) throw new Error('Transfer split fee changed')

    let previous = sourceTx
    const results: unknown[] = []
    const expectedNames = ['begin', 'prepare', 'miller-0', 'miller-1', 'miller-2', 'miller-3', 'finalize']
    for (let index = 0; index < saved.stages.length; index++) {
        const record = saved.stages[index]
        if (record.name !== expectedNames[index]) throw new Error('Unexpected transfer stage order')
        const tx = new bsv.Transaction(record.rawHex)
        if (tx.id !== record.txid || tx.toString().length / 2 !== record.transactionBytes) {
            throw new Error(`${record.name} transfer bytes changed`)
        }
        const expectedOutputCount =
            record.name === 'begin' || record.name === 'finalize' ? 2 : 1
        if (
            tx.inputs.length !== 2 ||
            tx.outputs.length !== expectedOutputCount ||
            tx.inputs[0].prevTxId.toString('hex') !== previous.id ||
            tx.inputs[0].outputIndex !== 0 ||
            tx.inputs[1].prevTxId.toString('hex') !== split.id ||
            tx.inputs[1].outputIndex !== record.sponsorOutputIndex
        ) throw new Error(`${record.name} transfer outpoint chain changed`)
        const source = previous.outputs[0]
        const sponsor = split.outputs[record.sponsorOutputIndex]
        if (
            expectedOutputCount === 2 &&
            (tx.outputs[1].satoshis !== 1_000 ||
                tx.outputs[1].script.toHex() !== sponsor.script.toHex())
        ) throw new Error(`${record.name} transfer change output changed`)
        const fee = source.satoshis + sponsor.satoshis -
            tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
        const minimumFee = Math.ceil(
            (record.transactionBytes * policy.miningFee.satoshis) /
            policy.miningFee.bytes
        )
        if (fee !== record.feeSatoshis || fee < minimumFee) {
            throw new Error(`${record.name} transfer fee audit failed`)
        }
        const scripts = [
            ...tx.inputs.map((input) => input.script.toBuffer().length),
            ...tx.outputs.map((output) => output.script.toBuffer().length),
        ]
        if (Math.max(...scripts) > policy.maxscriptsizepolicy) {
            throw new Error(`${record.name} transfer exceeds current script policy`)
        }
        const monitor = installScriptNumberPolicyMonitor(SCRIPT_NUMBER_POLICY_BYTES)
        const covenant = new bsv.Script.Interpreter()
        let covenantAccepted = false
        try {
            covenantAccepted = covenant.verify(
                tx.inputs[0].script,
                source.script,
                tx,
                0,
                bsv.Script.Interpreter.DEFAULT_FLAGS,
                new bsv.crypto.BN(source.satoshis)
            )
        } finally {
            monitor.restore()
        }
        if (!covenantAccepted) {
            throw new Error(`${record.name} transfer audit rejected: ${covenant.errstr}`)
        }
        const sponsorCheck = new bsv.Script.Interpreter()
        if (!sponsorCheck.verify(
            tx.inputs[1].script,
            sponsor.script,
            tx,
            1,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(sponsor.satoshis)
        )) throw new Error(`${record.name} transfer sponsor rejected: ${sponsorCheck.errstr}`)
        results.push({
            name: record.name,
            txid: record.txid,
            transactionBytes: record.transactionBytes,
            feeSatoshis: fee,
            maximumScriptNumberBytes: monitor.maximumBytes(),
            covenantAccepted: true,
            sponsorSignatureAccepted: true,
        })
        previous = tx
    }
    if (previous.outputs[0].satoshis !== saved.poolOutputSatoshis) {
        throw new Error('Transfer final pool value changed')
    }
    if (
        !saved.negativeTests.localNullifierReuseRejected ||
        !saved.negativeTests.updatedPoolReplayRejected ||
        !saved.negativeTests.updatedPoolReplayError
    ) throw new Error('Transfer nullifier-reuse evidence is incomplete')
    return {
        network: 'testnet',
        broadcast: false,
        kind: 'private-transfer',
        shieldFinalizerTxid: saved.shieldFinalizerTxid,
        shieldFinalizerBlockHeight: saved.shieldFinalizerBlockHeight,
        splitTxid: saved.split.txid,
        splitSignatureAccepted: true,
        splitFeeSatoshis: splitFee,
        currentPolicy: policy,
        startHeight: saved.startHeight,
        abortHeight: saved.abortHeight,
        receiverLockHeight: saved.receiverLockHeight,
        poolSatoshis: saved.poolOutputSatoshis,
        nullifier: saved.nullifier,
        nextState: saved.nextState,
        negativeTests: saved.negativeTests,
        stages: results,
    }
}

async function prepare(): Promise<void> {
    for (const file of [WALLET_FILE, DEPLOYMENT_FILE, CONFIRMATION_FILE, WASM, ZKEY, VKEY]) {
        if (!existsSync(file)) throw new Error(`Required v4 input missing: ${file}`)
    }
    if (existsSync(SECRETS_FILE) || existsSync(SIGNED_FILE)) {
        throw new Error('A v4 shield preparation already exists; audit it instead of replacing it')
    }
    loadArtifacts()
    const policy = livePolicy()
    const startHeight = liveHeight()
    const abortHeight = startHeight + Number(ABORT_DELAY_BLOCKS)
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (
        wallet.network !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) throw new Error('Invalid testnet deployment wallet')
    const deployment = JSON.parse(readFileSync(DEPLOYMENT_FILE, 'utf8')) as {
        deploymentTxid: string
        transactionHex: string
        initialState: { noteRoot: string; nullifierRoot: string; nextNoteIndex: string }
    }
    const confirmation = JSON.parse(readFileSync(CONFIRMATION_FILE, 'utf8')) as {
        deploymentTxid: string
        txStatus: string
    }
    if (
        confirmation.txStatus !== 'MINED' ||
        confirmation.deploymentTxid !== deployment.deploymentTxid
    ) throw new Error('V4 deployment is not confirmed')
    const deploymentTx = new bsv.Transaction(deployment.transactionHex)
    if (deploymentTx.id !== deployment.deploymentTxid || deploymentTx.outputs.length !== 2) {
        throw new Error('V4 deployment bytes do not match the confirmed TXID')
    }

    const state = new PoolState(await createHash())
    if (
        state.noteTree.root().toString() !== deployment.initialState.noteRoot ||
        state.nullifierTree.root().toString() !== deployment.initialState.nullifierRoot ||
        deployment.initialState.nextNoteIndex !== '0'
    ) throw new Error('V4 deployment roots are not the empty local pool')
    const secrets = { ownerKey: randomField(), shieldRho: randomField() }
    const transitionBuilt = state.build({
        mode: 0,
        publicIn: SHIELD_SATS,
        outputs: [{
            amount: SHIELD_SATS,
            ownerKey: secrets.ownerKey,
            rho: secrets.shieldRho,
        }],
    })
    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const { proof } = await groth16.fullProve(transitionBuilt.circuitInput, WASM, ZKEY)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const witness = buildPairingResidueWitness(transitionBuilt.statement, scryptProof, vk)
    const transition: V4Transition = {
        oldNoteRoot: transitionBuilt.public.oldNoteRoot,
        oldNullifierRoot: transitionBuilt.public.oldNullifierRoot,
        oldNextIndex: transitionBuilt.public.oldNextIndex,
        mode: transitionBuilt.public.mode,
        outCount: transitionBuilt.public.outCount,
        newNoteRoot: transitionBuilt.public.newNoteRoot,
        newNullifierRoot: transitionBuilt.public.newNullifierRoot,
        newNextIndex: transitionBuilt.public.newNextIndex,
        nullifier: transitionBuilt.public.nullifier,
        outputCommitment0: transitionBuilt.public.outputCommitment0,
        outputCommitment1: transitionBuilt.public.outputCommitment1,
        publicIn: transitionBuilt.public.publicIn,
        publicOut: transitionBuilt.public.publicOut,
        recipientField: transitionBuilt.public.recipient,
        currentHeight: transitionBuilt.public.currentHeight,
        recipientPkh: PubKeyHash(int2ByteString(transitionBuilt.public.recipient, 20n)),
    }

    const finalizer = new VeilV4Finalizer(
        ZERO_HASH, vk.millerb1a1, vk.root27, vk.root27Squared,
        vk.gammaLines[89], vk.deltaLines[89], vk.gammaLines[90], vk.deltaLines[90]
    )
    const stage3 = new VeilV4Miller3(
        ZERO_HASH, hash256(finalizer.codePart),
        vk.gammaLines.slice(67, 89) as never, vk.deltaLines.slice(67, 89) as never
    )
    const stage2 = new VeilV4Miller2(
        ZERO_HASH, hash256(stage3.codePart),
        vk.gammaLines.slice(44, 67) as never, vk.deltaLines.slice(44, 67) as never
    )
    const stage1 = new VeilV4Miller1(
        ZERO_HASH, hash256(stage2.codePart),
        vk.gammaLines.slice(23, 44) as never, vk.deltaLines.slice(23, 44) as never
    )
    const stage0 = new VeilV4Miller0(
        ZERO_HASH, hash256(stage1.codePart),
        vk.gammaLines.slice(0, 23) as never, vk.deltaLines.slice(0, 23) as never
    )
    const preparation = new VeilV4Preparation(
        ZERO_HASH, hash256(stage0.codePart), vk.gammaAbc[0], vk.gammaAbc[1]
    )
    const pool = new ShieldedPoolV4(
        transition.oldNoteRoot,
        transition.oldNullifierRoot,
        transition.oldNextIndex,
        hash256(preparation.codePart)
    )
    if (pool.lockingScript.toHex() !== deploymentTx.outputs[0].script.toHex()) {
        throw new Error('Prepared v4 shield does not spend the deployed covenant')
    }

    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    const split = new bsv.Transaction()
    split.from({
        txId: deployment.deploymentTxid,
        outputIndex: 1,
        script: deploymentTx.outputs[1].script.toHex(),
        satoshis: deploymentTx.outputs[1].satoshis,
    })
    for (const sponsor of SPONSORS) {
        split.addOutput(new bsv.Transaction.Output({ script: p2pkh, satoshis: sponsor.sats }))
    }
    split.fee(SPLIT_FEE_SATS)
    split.change(wallet.address)
    split.sign(key)
    if (!split.isFullySigned()) throw new Error('Funding split is not fully signed')
    const splitBytes = split.toString().length / 2
    const splitFee = deploymentTx.outputs[1].satoshis -
        split.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const feeRate = Math.ceil(
        (policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes
    )
    if (splitFee < Math.ceil((splitBytes * feeRate) / 1_000)) {
        throw new Error('Funding split fee is below live policy')
    }

    const lockedValue = Number(BigInt(deploymentTx.outputs[0].satoshis) + SHIELD_SATS)
    const preparationState: V4PreparationState = {
        signal: transitionBuilt.statement,
        proof: scryptProof,
        residue: witness.residue,
        residueInverse: witness.residueInverse,
        scale: witness.scale,
        context: {
            transitionHash: V4State.hashTransition(transition),
            poolCodeHash: hash256(pool.codePart),
            lockedValue: BigInt(lockedValue),
            abortHeight: BigInt(abortHeight),
        },
    }
    preparation.stateHash = V4State.hashPreparation(preparationState)
    const stages: SavedStage[] = []
    let tx = makeStageTx(
        deployment.deploymentTxid,
        pool.lockingScript,
        deploymentTx.outputs[0].satoshis,
        split.id,
        0,
        SPONSORS[0].sats,
        p2pkh,
        preparation.lockingScript,
        lockedValue,
        startHeight,
        { address: wallet.address, feeSatoshis: 60_000 }
    )
    stages.push(completeStage(
        'begin', pool, tx, deploymentTx.outputs[0].satoshis, SPONSORS[0].sats,
        key, feeRate,
        (self) => self.begin(
            scryptProof,
            witness,
            transition,
            BigInt(startHeight),
            BigInt(abortHeight),
            preparation.codePart,
            pool.codePart
        ),
        0
    ))

    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(scryptProof.b))
    const negA = { x: scryptProof.a.x, y: -scryptProof.a.y }
    const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
    const scaled = StagedGroth16.mulG1PointBounded(vk.gammaAbc[1], transitionBuilt.statement)
    const p1 = BN256.makeAffineCurvePoint(
        BN256.createCurvePoint(BN256.addG1Points(vk.gammaAbc[0], scaled))
    )
    const p2 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(scryptProof.c))
    let millerState: V4MillerState = {
        q, p0, p1, p2, r: q, acc: witness.residueInverse,
        residue: witness.residue, residueInverse: witness.residueInverse,
        scale: witness.scale, context: preparationState.context,
    }
    stage0.stateHash = V4State.hashMiller(millerState)
    tx = makeStageTx(
        stages.at(-1)!.txid,
        preparation.lockingScript,
        lockedValue,
        split.id,
        1,
        SPONSORS[1].sats,
        p2pkh,
        stage0.lockingScript,
        lockedValue
    )
    stages.push(completeStage(
        'prepare', preparation, tx, lockedValue, SPONSORS[1].sats, key, feeRate,
        (self) => self.prepare(preparationState, stage0.codePart),
        1
    ))

    const templates = [stage0, stage1, stage2, stage3]
    const starts = [0, 23, 44, 67]
    let current: any = stage0
    for (let stage = 0; stage < 4; stage++) {
        const inputState = millerState
        millerState = runSlice(inputState, vk, stage * 16, starts[stage])
        const next = stage === 3 ? finalizer : templates[stage + 1]
        next.stateHash = V4State.hashMiller(millerState)
        const sponsorIndex = stage + 2
        tx = makeStageTx(
            stages.at(-1)!.txid,
            current.lockingScript,
            lockedValue,
            split.id,
            sponsorIndex,
            SPONSORS[sponsorIndex].sats,
            p2pkh,
            next.lockingScript,
            lockedValue
        )
        stages.push(completeStage(
            `miller-${stage}`,
            current,
            tx,
            lockedValue,
            SPONSORS[sponsorIndex].sats,
            key,
            feeRate,
            (self) => self.advance(inputState, next.codePart),
            sponsorIndex
        ))
        current = next
    }

    const nextPool = pool.next()
    nextPool.noteRoot = transition.newNoteRoot
    nextPool.nullifierRoot = transition.newNullifierRoot
    nextPool.nextIndex = transition.newNextIndex
    tx = makeStageTx(
        stages.at(-1)!.txid,
        finalizer.lockingScript,
        lockedValue,
        split.id,
        6,
        SPONSORS[6].sats,
        p2pkh,
        nextPool.lockingScript,
        lockedValue,
        undefined,
        { address: wallet.address, feeSatoshis: 20_000 }
    )
    stages.push(completeStage(
        'finalize', finalizer, tx, lockedValue, SPONSORS[6].sats, key, feeRate,
        (self) => self.finalize(millerState, transition, pool.codePart),
        6
    ))

    const saved: SavedShield = {
        format: 'veil-v4-testnet-shield-plan-v1',
        network: 'testnet',
        broadcast: false,
        createdAt: new Date().toISOString(),
        deploymentTxid: deployment.deploymentTxid,
        split: {
            txid: split.id,
            rawHex: split.toString(),
            transactionBytes: splitBytes,
            feeSatoshis: splitFee,
            changeOutputIndex: split.outputs.length - 1,
            changeSatoshis: split.outputs.at(-1)!.satoshis,
        },
        startHeight,
        abortHeight,
        publicInSatoshis: Number(SHIELD_SATS),
        poolOutputSatoshis: lockedValue,
        nextState: {
            noteRoot: transition.newNoteRoot.toString(),
            nullifierRoot: transition.newNullifierRoot.toString(),
            nextNoteIndex: transition.newNextIndex.toString(),
        },
        livePolicy: policy,
        stages,
    }
    writePrivate(SECRETS_FILE, {
        createdAt: saved.createdAt,
        deploymentTxid: saved.deploymentTxid,
        note: transitionBuilt.outputNotes[0],
        ownerKey: secrets.ownerKey,
        shieldRho: secrets.shieldRho,
    })
    writePrivate(SIGNED_FILE, saved)
    console.log(JSON.stringify(jsonSafe(auditSaved(saved, policy)), null, 2))
    console.log('Signed v4 split and seven-stage shield saved locally; no broadcast command exists.')
}

export function parseSavedNote(value: unknown): Note {
    const note = value as Record<string, unknown>
    const index = Number(note.index)
    if (!Number.isSafeInteger(index) || index < 0) throw new Error('Invalid saved note index')
    return {
        amount: BigInt(String(note.amount)),
        ownerKey: BigInt(String(note.ownerKey)),
        rho: BigInt(String(note.rho)),
        lockHeight: BigInt(String(note.lockHeight)),
        index,
        commitment: BigInt(String(note.commitment)),
    }
}

async function prepareTransfer(): Promise<void> {
    for (const file of [
        WALLET_FILE,
        SIGNED_FILE,
        SECRETS_FILE,
        SHIELD_CONFIRMATION_FILE,
        WASM,
        ZKEY,
        VKEY,
    ]) {
        if (!existsSync(file)) throw new Error(`Required transfer input missing: ${file}`)
    }
    if (existsSync(TRANSFER_SECRETS_FILE) || existsSync(TRANSFER_SIGNED_FILE)) {
        throw new Error('A v4 transfer preparation already exists; audit it instead')
    }
    loadArtifacts()
    const policy = livePolicy()
    const startHeight = liveHeight()
    const abortHeight = startHeight + Number(ABORT_DELAY_BLOCKS)
    const receiverLockHeight = startHeight + TRANSFER_LOCK_DELAY_BLOCKS
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (
        wallet.network !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) throw new Error('Invalid testnet deployment wallet')

    const shield = JSON.parse(readFileSync(SIGNED_FILE, 'utf8')) as SavedShield
    auditSaved(shield, policy)
    const shieldFinalizer = shield.stages.at(-1)
    if (!shieldFinalizer || shieldFinalizer.name !== 'finalize') {
        throw new Error('The shield plan has no finalizer')
    }
    const confirmation = JSON.parse(
        readFileSync(SHIELD_CONFIRMATION_FILE, 'utf8')
    ) as {
        finalizerTxid: string
        blockHeight: number
        blockHash: string
        merklePath: string
    }
    const liveFinalizer = requireMinedStatus(shieldFinalizer.txid)
    if (
        confirmation.finalizerTxid !== shieldFinalizer.txid ||
        confirmation.blockHeight !== liveFinalizer.blockHeight ||
        confirmation.blockHash !== liveFinalizer.blockHash ||
        confirmation.merklePath !== liveFinalizer.merklePath
    ) throw new Error('Saved shield confirmation does not match live mined evidence')
    const sourceTx = new bsv.Transaction(shieldFinalizer.rawHex)
    if (
        sourceTx.id !== shieldFinalizer.txid ||
        sourceTx.outputs[0].satoshis !== shield.poolOutputSatoshis
    ) throw new Error('Confirmed shield finalizer bytes changed')

    const rawSecrets = JSON.parse(
        readFileSync(SECRETS_FILE, 'utf8')
    ) as ShieldSecrets
    const inputNote = parseSavedNote(rawSecrets.note)
    if (
        inputNote.ownerKey !== BigInt(rawSecrets.ownerKey) ||
        inputNote.rho !== BigInt(rawSecrets.shieldRho)
    ) throw new Error('Shield note secrets are internally inconsistent')
    const state = new PoolState(await createHash())
    state.noteTree.set(inputNote.index, inputNote.commitment)
    state.nextIndex = Number(shield.nextState.nextNoteIndex)
    if (
        state.noteTree.root().toString() !== shield.nextState.noteRoot ||
        state.nullifierTree.root().toString() !== shield.nextState.nullifierRoot ||
        state.nextIndex.toString() !== shield.nextState.nextNoteIndex
    ) throw new Error('Local note does not reconstruct the confirmed shield state')

    const receiverKey = randomField()
    const receiverRho = randomField()
    const senderChangeRho = randomField()
    const senderChangeSats = inputNote.amount - TRANSFER_RECEIVER_SATS
    if (senderChangeSats <= 0n) throw new Error('Transfer receiver amount leaves no private change')
    const transferRequest = {
        mode: 1 as const,
        spend: { note: inputNote },
        currentHeight: BigInt(startHeight),
        outputs: [
            {
                amount: TRANSFER_RECEIVER_SATS,
                ownerKey: receiverKey,
                rho: receiverRho,
                lockHeight: BigInt(receiverLockHeight),
            },
            {
                amount: senderChangeSats,
                ownerKey: inputNote.ownerKey,
                rho: senderChangeRho,
                lockHeight: 0n,
            },
        ],
    }
    const transitionBuilt = state.build(transferRequest)
    let localReuseError = ''
    try {
        state.build(transferRequest)
    } catch (error) {
        localReuseError = error instanceof Error ? error.message : String(error)
    }
    if (!localReuseError.includes('already spent')) {
        throw new Error(`Local nullifier reuse was not rejected: ${localReuseError}`)
    }

    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const { proof } = await groth16.fullProve(transitionBuilt.circuitInput, WASM, ZKEY)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const witness = buildPairingResidueWitness(transitionBuilt.statement, scryptProof, vk)
    const transition: V4Transition = {
        oldNoteRoot: transitionBuilt.public.oldNoteRoot,
        oldNullifierRoot: transitionBuilt.public.oldNullifierRoot,
        oldNextIndex: transitionBuilt.public.oldNextIndex,
        mode: transitionBuilt.public.mode,
        outCount: transitionBuilt.public.outCount,
        newNoteRoot: transitionBuilt.public.newNoteRoot,
        newNullifierRoot: transitionBuilt.public.newNullifierRoot,
        newNextIndex: transitionBuilt.public.newNextIndex,
        nullifier: transitionBuilt.public.nullifier,
        outputCommitment0: transitionBuilt.public.outputCommitment0,
        outputCommitment1: transitionBuilt.public.outputCommitment1,
        publicIn: transitionBuilt.public.publicIn,
        publicOut: transitionBuilt.public.publicOut,
        recipientField: transitionBuilt.public.recipient,
        currentHeight: transitionBuilt.public.currentHeight,
        recipientPkh: PubKeyHash(int2ByteString(transitionBuilt.public.recipient, 20n)),
    }

    const finalizer = new VeilV4Finalizer(
        ZERO_HASH, vk.millerb1a1, vk.root27, vk.root27Squared,
        vk.gammaLines[89], vk.deltaLines[89], vk.gammaLines[90], vk.deltaLines[90]
    )
    const stage3 = new VeilV4Miller3(
        ZERO_HASH, hash256(finalizer.codePart),
        vk.gammaLines.slice(67, 89) as never, vk.deltaLines.slice(67, 89) as never
    )
    const stage2 = new VeilV4Miller2(
        ZERO_HASH, hash256(stage3.codePart),
        vk.gammaLines.slice(44, 67) as never, vk.deltaLines.slice(44, 67) as never
    )
    const stage1 = new VeilV4Miller1(
        ZERO_HASH, hash256(stage2.codePart),
        vk.gammaLines.slice(23, 44) as never, vk.deltaLines.slice(23, 44) as never
    )
    const stage0 = new VeilV4Miller0(
        ZERO_HASH, hash256(stage1.codePart),
        vk.gammaLines.slice(0, 23) as never, vk.deltaLines.slice(0, 23) as never
    )
    const preparation = new VeilV4Preparation(
        ZERO_HASH, hash256(stage0.codePart), vk.gammaAbc[0], vk.gammaAbc[1]
    )
    const pool = ShieldedPoolV4.fromTx(sourceTx, 0)
    if (
        pool.noteRoot !== transition.oldNoteRoot ||
        pool.nullifierRoot !== transition.oldNullifierRoot ||
        pool.nextIndex !== transition.oldNextIndex ||
        pool.preparationCodeHash !== hash256(preparation.codePart) ||
        pool.lockingScript.toHex() !== sourceTx.outputs[0].script.toHex()
    ) throw new Error('Mined shield pool state does not match the reconstructed transfer state')

    const shieldSplit = new bsv.Transaction(shield.split.rawHex)
    const fundingIndex = shield.split.changeOutputIndex
    const fundingOutput = shieldSplit.outputs[fundingIndex]
    if (
        shieldSplit.id !== shield.split.txid ||
        !fundingOutput ||
        fundingOutput.satoshis !== shield.split.changeSatoshis
    ) throw new Error('Shield change output is not a valid transfer funding source')
    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    if (fundingOutput.script.toHex() !== p2pkh.toHex()) {
        throw new Error('Transfer funding source is not controlled by the deployment wallet')
    }
    const split = new bsv.Transaction()
    split.from({
        txId: shieldSplit.id,
        outputIndex: fundingIndex,
        script: fundingOutput.script.toHex(),
        satoshis: fundingOutput.satoshis,
    })
    for (const sponsor of TRANSFER_SPONSORS) {
        split.addOutput(new bsv.Transaction.Output({ script: p2pkh, satoshis: sponsor.sats }))
    }
    split.fee(SPLIT_FEE_SATS)
    split.change(wallet.address)
    split.sign(key)
    if (!split.isFullySigned()) throw new Error('Transfer funding split is not fully signed')
    const splitBytes = split.toString().length / 2
    const splitFee = fundingOutput.satoshis -
        split.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const feeRate = Math.ceil(
        (policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes
    )
    if (splitFee < Math.ceil((splitBytes * feeRate) / 1_000)) {
        throw new Error('Transfer funding split fee is below live policy')
    }

    const lockedValue = sourceTx.outputs[0].satoshis
    const preparationState: V4PreparationState = {
        signal: transitionBuilt.statement,
        proof: scryptProof,
        residue: witness.residue,
        residueInverse: witness.residueInverse,
        scale: witness.scale,
        context: {
            transitionHash: V4State.hashTransition(transition),
            poolCodeHash: hash256(pool.codePart),
            lockedValue: BigInt(lockedValue),
            abortHeight: BigInt(abortHeight),
        },
    }
    preparation.stateHash = V4State.hashPreparation(preparationState)
    const stages: SavedStage[] = []
    let tx = makeStageTx(
        sourceTx.id,
        pool.lockingScript,
        lockedValue,
        split.id,
        0,
        TRANSFER_SPONSORS[0].sats,
        p2pkh,
        preparation.lockingScript,
        lockedValue,
        startHeight,
        { address: wallet.address, feeSatoshis: 60_000 }
    )
    stages.push(completeStage(
        'begin', pool, tx, lockedValue, TRANSFER_SPONSORS[0].sats,
        key, feeRate,
        (self) => self.begin(
            scryptProof,
            witness,
            transition,
            BigInt(startHeight),
            BigInt(abortHeight),
            preparation.codePart,
            pool.codePart
        ),
        0
    ))

    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(scryptProof.b))
    const negA = { x: scryptProof.a.x, y: -scryptProof.a.y }
    const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
    const scaled = StagedGroth16.mulG1PointBounded(vk.gammaAbc[1], transitionBuilt.statement)
    const p1 = BN256.makeAffineCurvePoint(
        BN256.createCurvePoint(BN256.addG1Points(vk.gammaAbc[0], scaled))
    )
    const p2 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(scryptProof.c))
    let millerState: V4MillerState = {
        q, p0, p1, p2, r: q, acc: witness.residueInverse,
        residue: witness.residue, residueInverse: witness.residueInverse,
        scale: witness.scale, context: preparationState.context,
    }
    stage0.stateHash = V4State.hashMiller(millerState)
    tx = makeStageTx(
        stages.at(-1)!.txid,
        preparation.lockingScript,
        lockedValue,
        split.id,
        1,
        TRANSFER_SPONSORS[1].sats,
        p2pkh,
        stage0.lockingScript,
        lockedValue
    )
    stages.push(completeStage(
        'prepare', preparation, tx, lockedValue, TRANSFER_SPONSORS[1].sats, key, feeRate,
        (self) => self.prepare(preparationState, stage0.codePart),
        1
    ))

    const templates = [stage0, stage1, stage2, stage3]
    const starts = [0, 23, 44, 67]
    let current: any = stage0
    for (let stage = 0; stage < 4; stage++) {
        const inputState = millerState
        millerState = runSlice(inputState, vk, stage * 16, starts[stage])
        const next = stage === 3 ? finalizer : templates[stage + 1]
        next.stateHash = V4State.hashMiller(millerState)
        const sponsorIndex = stage + 2
        tx = makeStageTx(
            stages.at(-1)!.txid,
            current.lockingScript,
            lockedValue,
            split.id,
            sponsorIndex,
            TRANSFER_SPONSORS[sponsorIndex].sats,
            p2pkh,
            next.lockingScript,
            lockedValue
        )
        stages.push(completeStage(
            `miller-${stage}`,
            current,
            tx,
            lockedValue,
            TRANSFER_SPONSORS[sponsorIndex].sats,
            key,
            feeRate,
            (self) => self.advance(inputState, next.codePart),
            sponsorIndex
        ))
        current = next
    }

    const nextPool = pool.next()
    nextPool.noteRoot = transition.newNoteRoot
    nextPool.nullifierRoot = transition.newNullifierRoot
    nextPool.nextIndex = transition.newNextIndex
    tx = makeStageTx(
        stages.at(-1)!.txid,
        finalizer.lockingScript,
        lockedValue,
        split.id,
        6,
        TRANSFER_SPONSORS[6].sats,
        p2pkh,
        nextPool.lockingScript,
        lockedValue,
        undefined,
        { address: wallet.address, feeSatoshis: 20_000 }
    )
    stages.push(completeStage(
        'finalize', finalizer, tx, lockedValue, TRANSFER_SPONSORS[6].sats, key, feeRate,
        (self) => self.finalize(millerState, transition, pool.codePart),
        6
    ))

    const replaySponsorIndex = split.outputs.length - 1
    const replaySponsor = split.outputs[replaySponsorIndex]
    const replayTx = makeStageTx(
        stages.at(-1)!.txid,
        nextPool.lockingScript,
        lockedValue,
        split.id,
        replaySponsorIndex,
        replaySponsor.satoshis,
        p2pkh,
        preparation.lockingScript,
        lockedValue,
        startHeight,
        { address: wallet.address, feeSatoshis: 60_000 }
    )
    nextPool.to = { tx: replayTx, inputIndex: 0 }
    let replayError = ''
    try {
        const replayUnlocking = nextPool.getUnlockingScript((self) => self.begin(
            scryptProof,
            witness,
            transition,
            BigInt(startHeight),
            BigInt(abortHeight),
            preparation.codePart,
            pool.codePart
        ))
        if (replayUnlocking instanceof Promise) throw new Error('Unexpected async replay builder')
        replayTx.inputs[0].setScript(replayUnlocking)
        replayTx.sign(key)
        const replayInterpreter = new bsv.Script.Interpreter()
        const replayAccepted = replayInterpreter.verify(
            replayUnlocking,
            nextPool.lockingScript,
            replayTx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(lockedValue)
        )
        if (replayAccepted) throw new Error('Updated pool accepted a reused nullifier transition')
        replayError = replayInterpreter.errstr || 'covenant returned false'
    } catch (error) {
        replayError = error instanceof Error ? error.message : String(error)
    }
    if (
        !replayError.includes('wrong old note root') &&
        !replayError.includes('wrong old nullifier root')
    ) throw new Error(`Unexpected updated-pool replay result: ${replayError}`)

    const saved: SavedTransfer = {
        format: 'veil-v4-testnet-transfer-plan-v1',
        network: 'testnet',
        broadcast: false,
        createdAt: new Date().toISOString(),
        shieldFinalizerTxid: shieldFinalizer.txid,
        shieldFinalizerBlockHeight: liveFinalizer.blockHeight,
        fundingSource: {
            txid: shieldSplit.id,
            outputIndex: fundingIndex,
            satoshis: fundingOutput.satoshis,
        },
        split: {
            txid: split.id,
            rawHex: split.toString(),
            transactionBytes: splitBytes,
            feeSatoshis: splitFee,
            changeOutputIndex: split.outputs.length - 1,
            changeSatoshis: split.outputs.at(-1)!.satoshis,
        },
        startHeight,
        abortHeight,
        receiverLockHeight,
        poolOutputSatoshis: lockedValue,
        spentCommitment: inputNote.commitment.toString(),
        nullifier: transition.nullifier.toString(),
        nextState: {
            noteRoot: transition.newNoteRoot.toString(),
            nullifierRoot: transition.newNullifierRoot.toString(),
            nextNoteIndex: transition.newNextIndex.toString(),
        },
        livePolicy: policy,
        stages,
        negativeTests: {
            localNullifierReuseRejected: true,
            updatedPoolReplayRejected: true,
            updatedPoolReplayError: replayError,
        },
    }
    writePrivate(TRANSFER_SECRETS_FILE, {
        createdAt: saved.createdAt,
        sourceShieldFinalizerTxid: saved.shieldFinalizerTxid,
        receiverNote: transitionBuilt.outputNotes[0],
        receiverKey,
        receiverRho,
        senderChangeNote: transitionBuilt.outputNotes[1],
        senderChangeRho,
    })
    writePrivate(TRANSFER_SIGNED_FILE, saved)
    console.log(JSON.stringify(jsonSafe(auditTransferSaved(saved, policy)), null, 2))
    console.log('Signed v4 private-transfer plan saved locally; nothing was broadcast.')
}

export function arcAccepted(
    submitted: { httpStatus: number; response: unknown },
    expectedTxid: string
): boolean {
    const response = submitted.response as { txid?: string; txStatus?: string }
    return (
        submitted.httpStatus >= 200 &&
        submitted.httpStatus < 300 &&
        response.txid?.toLowerCase() === expectedTxid.toLowerCase() &&
        !!response.txStatus &&
        [
            'QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK',
            'REQUESTED_BY_NETWORK', 'SENT_TO_NETWORK',
            'ACCEPTED_BY_NETWORK', 'SEEN_ON_NETWORK', 'MINED',
        ].includes(response.txStatus)
    )
}

function expectedTxid(label: string): string {
    const expected = process.argv
        .find((value) => value.startsWith('--expect='))
        ?.slice('--expect='.length)
        .toLowerCase()
    if (!expected || !/^[0-9a-f]{64}$/.test(expected)) {
        throw new Error(`${label} requires --expect=<exact audited TXID>`)
    }
    return expected
}

function sendTransferSplit(saved: SavedTransfer): void {
    if (existsSync(TRANSFER_SPLIT_RECEIPT_FILE)) {
        throw new Error('A transfer funding-split receipt already exists; refusing to resubmit')
    }
    if (expectedTxid('send-transfer-split') !== saved.split.txid.toLowerCase()) {
        throw new Error('Approved transfer split TXID does not match the audited plan')
    }
    auditTransferSaved(saved, livePolicy())
    requireMinedStatus(saved.fundingSource.txid)
    const submitted = torPostTransaction(saved.split.rawHex)
    const receipt = {
        format: 'veil-v4-testnet-transfer-split-receipt-v1',
        network: 'testnet',
        torOnly: true,
        submittedAt: new Date().toISOString(),
        splitTxid: saved.split.txid,
        fundingSource: saved.fundingSource,
        transactionBytes: saved.split.transactionBytes,
        feeSatoshis: saved.split.feeSatoshis,
        httpStatus: submitted.httpStatus,
        response: submitted.response,
    }
    writePrivate(TRANSFER_SPLIT_RECEIPT_FILE, receipt)
    if (!arcAccepted(submitted, saved.split.txid)) {
        throw new Error(`ARC did not accept the transfer split: ${JSON.stringify(receipt)}`)
    }
    console.log(JSON.stringify(receipt, null, 2))
    console.log('Only the transfer funding split was submitted.')
}

function sendTransferBegin(saved: SavedTransfer): void {
    if (existsSync(TRANSFER_BEGIN_RECEIPT_FILE)) {
        throw new Error('A transfer begin receipt already exists; refusing to resubmit')
    }
    const begin = saved.stages.find((stage) => stage.name === 'begin')
    if (!begin) throw new Error('Prepared transfer has no begin stage')
    if (expectedTxid('send-transfer-begin') !== begin.txid.toLowerCase()) {
        throw new Error('Approved transfer begin TXID does not match the audited plan')
    }
    auditTransferSaved(saved, livePolicy())
    const splitMined = requireMinedStatus(saved.split.txid)
    const submitted = torPostTransaction(begin.rawHex)
    const receipt = {
        format: 'veil-v4-testnet-transfer-begin-receipt-v1',
        network: 'testnet',
        torOnly: true,
        submittedAt: new Date().toISOString(),
        splitTxid: saved.split.txid,
        splitBlockHeight: splitMined.blockHeight,
        beginTxid: begin.txid,
        transactionBytes: begin.transactionBytes,
        feeSatoshis: begin.feeSatoshis,
        startHeight: saved.startHeight,
        abortHeight: saved.abortHeight,
        httpStatus: submitted.httpStatus,
        response: submitted.response,
    }
    writePrivate(TRANSFER_BEGIN_RECEIPT_FILE, receipt)
    if (!arcAccepted(submitted, begin.txid)) {
        throw new Error(`ARC did not accept transfer begin: ${JSON.stringify(receipt)}`)
    }
    console.log(JSON.stringify(receipt, null, 2))
    console.log('Only the transfer begin stage was submitted.')
}

function sendTransferStage(saved: SavedTransfer): void {
    const stageName = process.argv
        .find((value) => value.startsWith('--stage='))
        ?.slice('--stage='.length)
    const allowed = ['prepare', 'miller-0', 'miller-1', 'miller-2', 'miller-3', 'finalize']
    if (!stageName || !allowed.includes(stageName)) {
        throw new Error(`send-transfer-stage requires --stage=${allowed.join('|')}`)
    }
    const stageIndex = saved.stages.findIndex((stage) => stage.name === stageName)
    if (stageIndex < 1) throw new Error('Requested transfer stage is missing or unordered')
    const stage = saved.stages[stageIndex]
    const prior = saved.stages[stageIndex - 1]
    const receiptFile = path.join(
        PRIVATE_DIR,
        `testnet-v4-transfer-${stageName}-receipt.json`
    )
    if (existsSync(receiptFile)) {
        throw new Error(`A transfer ${stageName} receipt already exists; refusing to resubmit`)
    }
    if (expectedTxid('send-transfer-stage') !== stage.txid.toLowerCase()) {
        throw new Error(`Approved transfer ${stageName} TXID does not match the audited plan`)
    }
    auditTransferSaved(saved, livePolicy())
    const priorMined = requireMinedStatus(prior.txid)
    const submitted = torPostTransaction(stage.rawHex)
    const receipt = {
        format: 'veil-v4-testnet-transfer-stage-receipt-v1',
        network: 'testnet',
        torOnly: true,
        submittedAt: new Date().toISOString(),
        stage: stage.name,
        stageTxid: stage.txid,
        priorStage: prior.name,
        priorTxid: prior.txid,
        priorBlockHeight: priorMined.blockHeight,
        transactionBytes: stage.transactionBytes,
        feeSatoshis: stage.feeSatoshis,
        abortHeight: saved.abortHeight,
        httpStatus: submitted.httpStatus,
        response: submitted.response,
    }
    writePrivate(receiptFile, receipt)
    if (!arcAccepted(submitted, stage.txid)) {
        throw new Error(`ARC did not accept transfer ${stageName}: ${JSON.stringify(receipt)}`)
    }
    console.log(JSON.stringify(receipt, null, 2))
    console.log(`Only transfer ${stageName} was submitted.`)
}

function confirmTransfer(): void {
    if (!existsSync(TRANSFER_SIGNED_FILE)) {
        throw new Error('No prepared v4 private transfer exists')
    }
    const saved = JSON.parse(
        readFileSync(TRANSFER_SIGNED_FILE, 'utf8')
    ) as SavedTransfer
    auditTransferSaved(saved, livePolicy())
    const finalizer = saved.stages.at(-1)
    if (!finalizer || finalizer.name !== 'finalize') {
        throw new Error('The saved private transfer has no finalizer')
    }
    const mined = requireMinedStatus(finalizer.txid)
    const confirmation = {
        format: 'veil-v4-testnet-transfer-confirmation-v1',
        network: 'testnet',
        txStatus: mined.txStatus,
        recordedAt: new Date().toISOString(),
        finalizerTxid: mined.txid,
        blockHeight: mined.blockHeight,
        blockHash: mined.blockHash,
        merklePath: mined.merklePath,
        merkleInclusionEvidenceAvailable: true,
        finalPoolSatoshis: saved.poolOutputSatoshis,
        receiverLockHeight: saved.receiverLockHeight,
        nullifier: saved.nullifier,
        nextState: saved.nextState,
    }
    if (existsSync(TRANSFER_CONFIRMATION_FILE)) {
        const existing = JSON.parse(
            readFileSync(TRANSFER_CONFIRMATION_FILE, 'utf8')
        ) as Record<string, unknown>
        const stableExisting = { ...existing }
        const stableCurrent = { ...confirmation } as Record<string, unknown>
        delete stableExisting.recordedAt
        delete stableCurrent.recordedAt
        if (JSON.stringify(stableExisting) !== JSON.stringify(stableCurrent)) {
            throw new Error('Existing transfer confirmation conflicts with live mined evidence')
        }
        console.log(JSON.stringify(existing, null, 2))
        return
    }
    writePrivate(TRANSFER_CONFIRMATION_FILE, confirmation)
    console.log(JSON.stringify(confirmation, null, 2))
}

async function main(): Promise<void> {
    const command = process.argv[2]
    const commands = [
        'prepare-shield', 'audit-shield', 'send-split', 'send-begin', 'send-stage',
        'confirm-shield', 'prepare-transfer', 'audit-transfer',
        'send-transfer-split', 'send-transfer-begin', 'send-transfer-stage',
        'confirm-transfer',
    ]
    if (!commands.includes(command)) {
        throw new Error(`Usage: testnet-v4-lifecycle.ts ${commands.join('|')}`)
    }
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    if (command === 'prepare-shield') {
        await prepare()
        return
    }
    if (command === 'confirm-shield') {
        confirmShield()
        return
    }
    if (command === 'prepare-transfer') {
        await prepareTransfer()
        return
    }
    if (command === 'confirm-transfer') {
        confirmTransfer()
        return
    }
    if (
        command === 'audit-transfer' ||
        command === 'send-transfer-split' ||
        command === 'send-transfer-begin' ||
        command === 'send-transfer-stage'
    ) {
        if (!existsSync(TRANSFER_SIGNED_FILE)) {
            throw new Error('No prepared v4 private transfer exists')
        }
        const transfer = JSON.parse(
            readFileSync(TRANSFER_SIGNED_FILE, 'utf8')
        ) as SavedTransfer
        if (command === 'send-transfer-split') {
            sendTransferSplit(transfer)
            return
        }
        if (command === 'send-transfer-begin') {
            sendTransferBegin(transfer)
            return
        }
        if (command === 'send-transfer-stage') {
            sendTransferStage(transfer)
            return
        }
        console.log(JSON.stringify(auditTransferSaved(transfer, livePolicy()), null, 2))
        return
    }
    if (!existsSync(SIGNED_FILE)) throw new Error('No prepared v4 shield exists')
    const saved = JSON.parse(readFileSync(SIGNED_FILE, 'utf8')) as SavedShield
    if (command === 'send-stage') {
        const stageName = process.argv
            .find((value) => value.startsWith('--stage='))
            ?.slice('--stage='.length)
        const allowed = ['prepare', 'miller-0', 'miller-1', 'miller-2', 'miller-3', 'finalize']
        if (!stageName || !allowed.includes(stageName)) {
            throw new Error(`send-stage requires --stage=${allowed.join('|')}`)
        }
        const stageIndex = saved.stages.findIndex((stage) => stage.name === stageName)
        if (stageIndex < 1) throw new Error('Requested v4 stage is missing or unordered')
        const stage = saved.stages[stageIndex]
        const prior = saved.stages[stageIndex - 1]
        const receiptFile = path.join(
            PRIVATE_DIR,
            `testnet-v4-shield-${stageName}-receipt.json`
        )
        if (existsSync(receiptFile)) {
            throw new Error(`A ${stageName} receipt already exists; refusing to resubmit`)
        }
        const expected = process.argv
            .find((value) => value.startsWith('--expect='))
            ?.slice('--expect='.length)
            .toLowerCase()
        if (!expected || expected !== stage.txid.toLowerCase()) {
            throw new Error(`send-stage requires --expect=<exact audited ${stageName} TXID>`)
        }
        auditSaved(saved, livePolicy())
        const priorStatus = torJson(`${ARC}/v1/tx/${prior.txid}`) as {
            txid?: string
            txStatus?: string
            blockHeight?: number
            blockHash?: string
            merklePath?: string
        }
        if (
            priorStatus.txid?.toLowerCase() !== prior.txid.toLowerCase() ||
            priorStatus.txStatus !== 'MINED' ||
            !Number.isSafeInteger(priorStatus.blockHeight) ||
            (priorStatus.blockHeight as number) <= 0 ||
            !/^[0-9a-f]{64}$/i.test(priorStatus.blockHash ?? '') ||
            !priorStatus.merklePath
        ) throw new Error(`Prior stage ${prior.name} lacks mined inclusion evidence`)
        const submitted = torPostTransaction(stage.rawHex)
        const response = submitted.response as { txid?: string; txStatus?: string }
        const accepted =
            submitted.httpStatus >= 200 &&
            submitted.httpStatus < 300 &&
            response.txid?.toLowerCase() === stage.txid.toLowerCase() &&
            !!response.txStatus &&
            [
                'QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK',
                'REQUESTED_BY_NETWORK', 'SENT_TO_NETWORK',
                'ACCEPTED_BY_NETWORK', 'SEEN_ON_NETWORK', 'MINED',
            ].includes(response.txStatus)
        const receipt = {
            format: 'veil-v4-testnet-shield-stage-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            stage: stage.name,
            stageTxid: stage.txid,
            priorStage: prior.name,
            priorTxid: prior.txid,
            priorBlockHeight: priorStatus.blockHeight,
            transactionBytes: stage.transactionBytes,
            feeSatoshis: stage.feeSatoshis,
            abortHeight: saved.abortHeight,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(receiptFile, receipt)
        if (!accepted) {
            throw new Error(`ARC did not accept ${stageName}: ${JSON.stringify(receipt)}`)
        }
        console.log(JSON.stringify(receipt, null, 2))
        console.log(`Only ${stageName} was submitted; no later v4 stage was broadcast.`)
        return
    }
    if (command === 'send-begin') {
        if (existsSync(BEGIN_RECEIPT_FILE)) {
            throw new Error('A begin receipt already exists; refusing to resubmit')
        }
        const begin = saved.stages.find((stage) => stage.name === 'begin')
        if (!begin) throw new Error('Prepared v4 shield has no begin stage')
        const expected = process.argv
            .find((value) => value.startsWith('--expect='))
            ?.slice('--expect='.length)
            .toLowerCase()
        if (!expected || expected !== begin.txid.toLowerCase()) {
            throw new Error('send-begin requires --expect=<exact audited begin TXID>')
        }
        auditSaved(saved, livePolicy())
        const splitStatus = torJson(`${ARC}/v1/tx/${saved.split.txid}`) as {
            txid?: string
            txStatus?: string
            blockHeight?: number
            blockHash?: string
            merklePath?: string
        }
        if (
            splitStatus.txid?.toLowerCase() !== saved.split.txid.toLowerCase() ||
            splitStatus.txStatus !== 'MINED' ||
            !Number.isSafeInteger(splitStatus.blockHeight) ||
            (splitStatus.blockHeight as number) <= 0 ||
            !/^[0-9a-f]{64}$/i.test(splitStatus.blockHash ?? '') ||
            !splitStatus.merklePath
        ) throw new Error('Funding split lacks mined inclusion evidence')
        const submitted = torPostTransaction(begin.rawHex)
        const response = submitted.response as { txid?: string; txStatus?: string }
        const accepted =
            submitted.httpStatus >= 200 &&
            submitted.httpStatus < 300 &&
            response.txid?.toLowerCase() === begin.txid.toLowerCase() &&
            !!response.txStatus &&
            [
                'QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK',
                'REQUESTED_BY_NETWORK', 'SENT_TO_NETWORK',
                'ACCEPTED_BY_NETWORK', 'SEEN_ON_NETWORK', 'MINED',
            ].includes(response.txStatus)
        const receipt = {
            format: 'veil-v4-testnet-shield-begin-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            splitTxid: saved.split.txid,
            splitBlockHeight: splitStatus.blockHeight,
            beginTxid: begin.txid,
            transactionBytes: begin.transactionBytes,
            feeSatoshis: begin.feeSatoshis,
            startHeight: saved.startHeight,
            abortHeight: saved.abortHeight,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(BEGIN_RECEIPT_FILE, receipt)
        if (!accepted) {
            throw new Error(`ARC did not accept v4 begin: ${JSON.stringify(receipt)}`)
        }
        console.log(JSON.stringify(receipt, null, 2))
        console.log('Only the v4 begin stage was submitted; no later stage was broadcast.')
        return
    }
    if (command === 'send-split') {
        if (existsSync(SPLIT_RECEIPT_FILE)) {
            throw new Error('A funding-split receipt already exists; refusing to resubmit')
        }
        const expected = process.argv
            .find((value) => value.startsWith('--expect='))
            ?.slice('--expect='.length)
            .toLowerCase()
        if (!expected || expected !== saved.split.txid.toLowerCase()) {
            throw new Error('send-split requires --expect=<exact audited split TXID>')
        }
        auditSaved(saved, livePolicy())
        const submitted = torPostTransaction(saved.split.rawHex)
        const response = submitted.response as { txid?: string; txStatus?: string }
        const accepted =
            submitted.httpStatus >= 200 &&
            submitted.httpStatus < 300 &&
            response.txid?.toLowerCase() === saved.split.txid.toLowerCase() &&
            !!response.txStatus &&
            [
                'QUEUED', 'RECEIVED', 'STORED', 'ANNOUNCED_TO_NETWORK',
                'REQUESTED_BY_NETWORK', 'SENT_TO_NETWORK',
                'ACCEPTED_BY_NETWORK', 'SEEN_ON_NETWORK', 'MINED',
            ].includes(response.txStatus)
        const receipt = {
            format: 'veil-v4-testnet-shield-split-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            splitTxid: saved.split.txid,
            transactionBytes: saved.split.transactionBytes,
            feeSatoshis: saved.split.feeSatoshis,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(SPLIT_RECEIPT_FILE, receipt)
        if (!accepted) {
            throw new Error(`ARC did not accept the funding split: ${JSON.stringify(receipt)}`)
        }
        console.log(JSON.stringify(receipt, null, 2))
        console.log('Only the funding split was submitted; no v4 shield stage was broadcast.')
        return
    }
    console.log(JSON.stringify(auditSaved(saved, livePolicy()), null, 2))
}

if (require.main === module) {
    main().catch((error: unknown) => {
        console.error(error instanceof Error ? error.message : error)
        process.exitCode = 1
    })
}
