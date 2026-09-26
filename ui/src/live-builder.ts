import { UnsignedEncoding } from '../../src/unsignedEncoding'
import {
    bsv,
    hash256,
    PubKeyHash,
    Sha256,
    toByteString,
} from 'scrypt-ts'
import { groth16 } from 'snarkjs'
import { BN256, BN256Pairing, LineFuncRes } from 'scrypt-ts-lib/dist/ec/bn256'
import { BuiltTransition, FIELD, HashFn, Note, PoolState, createHash } from '../../src/crypto'
import { SnarkProof, SnarkVerificationKey, toScryptProof } from '../../src/groth16'
import { toPreparedVerifyingKey } from '../../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../../src/pairingResidue'
import { ShieldedPoolV4 } from '../../src/v4/shieldedPoolV4'
import { StagedGroth16 } from '../../src/v4/stagedGroth16'
import { V4MillerState, V4PreparationState, V4State, V4Transition } from '../../src/v4/v4State'
import { VeilV4Finalizer } from '../../src/v4/veilV4Finalizer'
import { VeilV4Miller0 } from '../../src/v4/veilV4Miller0'
import { VeilV4Miller1 } from '../../src/v4/veilV4Miller1'
import { VeilV4Miller2 } from '../../src/v4/veilV4Miller2'
import { VeilV4Miller3 } from '../../src/v4/veilV4Miller3'
import { VeilV4Preparation } from '../../src/v4/veilV4Preparation'
import { RECIPIENT_PROTOCOL, EncryptedPayment, encryptPayment, decryptPayment, parseRecipientAddress, recipientIdentity } from '../../src/recipient'
import { PoolSnapshot, EncodedNote, encodeNote, decodeNote, restorePool, assertMonotonic } from '../../src/recipientState'
import { LiveWallet, validateReceivingWallet } from './live-wallet'
import { MinerPolicy, testnetHeight, testnetPolicy, transactionStatus } from './live-network'
import { resolveLockHeight } from './lock-height'

export type LiveAction = 'shield' | 'send' | 'lock' | 'withdraw'

export interface PreparedTransaction {
    name: string
    txid: string
    rawHex: string
    bytes: number
    feeSatoshis: number
}

export interface PreparedLiveAction {
    action: LiveAction
    amount: number
    recipient?: string
    unlockHeight?: number
    startHeight: number
    oldPrivateBalance: number
    newPrivateBalance: number
    newLockedBalance: number
    totalFees: number
    transactions: PreparedTransaction[]
    warning: string
    payment?: EncryptedPayment
    snapshot: PoolSnapshot
    _next: {
        poolState: PoolState
        notes: Note[]
        poolTx: bsv.Transaction
        pool: ShieldedPoolV4
        funding: LiveWallet['funding']
        deploymentCommitted: boolean
    }
}

export type BuilderProgress = (percent: number | null, label: string) => void

interface FundingSplit {
    txid: string
    rawHex: string
    transactionBytes: number
    feeSatoshis: number
    changeOutputIndex: number
    changeSatoshis: number
}

interface StageRecord extends PreparedTransaction {
    sponsorOutputIndex: number
}

const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))
const SCRIPT_POLICY_BYTES = 500_000
const SCRIPT_NUMBER_POLICY_BYTES = 10_000
const SPLIT_FEE_SATS = 1_000
const ABORT_DELAY_BLOCKS = 144
const STATE_ANCHOR_SATS = 1
const FEE_SAFETY_SATS = 1_000
const DIGITS = [
    1, 0, 1, 0, 0, -1, 0, 1, 1, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1,
    1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 1, 1, 0,
    0, 1, 0, 0, -1, 1, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0,
] as const

function installScriptNumberPolicyMonitor(limit: number) {
    const BNClass = bsv.crypto.BN as unknown as {
        fromScriptNumBuffer(
            buffer: Uint8Array,
            requireMinimal?: boolean,
            size?: number
        ): bsv.crypto.BN
    }
    const original = BNClass.fromScriptNumBuffer
    BNClass.fromScriptNumBuffer = function (buffer, requireMinimal, size) {
        if (size === undefined && buffer.length > limit) {
            throw new Error(`script number overflow: ${buffer.length} > ${limit}`)
        }
        return original.call(this, buffer, requireMinimal, size)
    }
    return () => { BNClass.fromScriptNumBuffer = original }
}

function auditP2pkhInput(
    name: string,
    tx: bsv.Transaction,
    inputIndex: number,
    source: bsv.Transaction.Output
): void {
    const interpreter = new bsv.Script.Interpreter()
    if (!interpreter.verify(
        tx.inputs[inputIndex].script,
        source.script,
        tx,
        inputIndex,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(source.satoshis)
    )) throw new Error(`${name} signature rejected locally: ${interpreter.errstr}`)
}

type PreparedVk = ReturnType<typeof toPreparedVerifyingKey>
type ScryptProof = ReturnType<typeof toScryptProof>

let artifactsPromise: Promise<PreparedVk> | undefined

function asset(path: string): string {
    return new URL(`zk/${path}`, document.baseURI).toString()
}

async function fetchJson<T>(path: string): Promise<T> {
    const response = await fetch(asset(path))
    if (!response.ok) throw new Error(`Required browser artifact is unavailable: ${path}`)
    return response.json() as Promise<T>
}

async function loadArtifacts(): Promise<PreparedVk> {
    artifactsPromise ??= (async () => {
        const [pool, preparation, stage0, stage1, stage2, stage3, finalizer, vkey] = await Promise.all([
            fetchJson<unknown>('contracts/shieldedPoolV4.json'),
            fetchJson<unknown>('contracts/veilV4Preparation.json'),
            fetchJson<unknown>('contracts/veilV4Miller0.json'),
            fetchJson<unknown>('contracts/veilV4Miller1.json'),
            fetchJson<unknown>('contracts/veilV4Miller2.json'),
            fetchJson<unknown>('contracts/veilV4Miller3.json'),
            fetchJson<unknown>('contracts/veilV4Finalizer.json'),
            fetchJson<SnarkVerificationKey>('recipient/verification_key.json'),
        ])
        ShieldedPoolV4.loadArtifact(pool as never)
        VeilV4Preparation.loadArtifact(preparation as never)
        VeilV4Miller0.loadArtifact(stage0 as never)
        VeilV4Miller1.loadArtifact(stage1 as never)
        VeilV4Miller2.loadArtifact(stage2 as never)
        VeilV4Miller3.loadArtifact(stage3 as never)
        VeilV4Finalizer.loadArtifact(finalizer as never)
        return toPreparedVerifyingKey(vkey)
    })()
    return artifactsPromise
}

function randomField(): bigint {
    const bytes = crypto.getRandomValues(new Uint8Array(32))
    let value = 0n
    for (const byte of bytes) value = (value << 8n) + BigInt(byte)
    value %= FIELD
    return value === 0n ? 1n : value
}

function recipientField(address: string): bigint {
    const parsed = bsv.Address.fromString(address, bsv.Networks.testnet)
    if (parsed.network.name !== 'testnet' || parsed.type !== 'pubkeyhash') throw new Error('Withdraw supports testnet P2PKH addresses only')
    const hash = parsed.hashBuffer
    const hex = Array.from(hash).reverse().map((byte) => byte.toString(16).padStart(2, '0')).join('')
    return BigInt(`0x${hex}`)
}

function cloneState(source: PoolState, hash: HashFn): PoolState {
    const clone = new PoolState(hash, source.recipientOwned)
    source.noteTree.leaves.forEach((value, index) => clone.noteTree.set(index, value))
    source.nullifierTree.leaves.forEach((value, index) => clone.nullifierTree.set(index, value))
    clone.nextIndex = source.nextIndex
    return clone
}

function transitionFrom(built: BuiltTransition): V4Transition {
    return {
        oldNoteRoot: built.public.oldNoteRoot,
        oldNullifierRoot: built.public.oldNullifierRoot,
        oldNextIndex: built.public.oldNextIndex,
        mode: built.public.mode,
        outCount: built.public.outCount,
        newNoteRoot: built.public.newNoteRoot,
        newNullifierRoot: built.public.newNullifierRoot,
        newNextIndex: built.public.newNextIndex,
        nullifier: built.public.nullifier,
        outputCommitment0: built.public.outputCommitment0,
        outputCommitment1: built.public.outputCommitment1,
        publicIn: built.public.publicIn,
        publicOut: built.public.publicOut,
        recipientField: built.public.recipient,
        currentHeight: built.public.currentHeight,
        recipientPkh: PubKeyHash(UnsignedEncoding.uint160(built.public.recipient)),
    }
}

function verifierContracts(vk: PreparedVk) {
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
    return { preparation, stage0, stage1, stage2, stage3, finalizer }
}

function runSlice(snapshot: V4MillerState, vk: PreparedVk, digitStart: number, lineStart: number): V4MillerState {
    let acc = snapshot.acc
    let r = snapshot.r
    let lineIndex = lineStart
    const qMinus = BN256.negTwistPoint(snapshot.q)
    const addR20 = BN256.squareFQ2(snapshot.q.y)
    let line: LineFuncRes
    for (let index = digitStart; index < digitStart + 16; index++) {
        const digit = DIGITS[index]
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
            line = BN256Pairing.lineFuncAdd(r, digit === 1 ? snapshot.q : qMinus, snapshot.p0, addR20)
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

function makeStageTx(
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

function completeStage(
    name: string,
    current: any,
    tx: bsv.Transaction,
    sourceValue: number,
    sponsorValue: number,
    walletKey: bsv.PrivateKey,
    feeRate: number,
    unlock: (self: any) => void,
    sponsorOutputIndex: number
): StageRecord {
    current.to = { tx, inputIndex: 0 }
    const unlocking = current.getUnlockingScript(unlock)
    if (unlocking instanceof Promise) throw new Error(`Unexpected async ${name} builder`)
    if (unlocking.toBuffer().length > SCRIPT_POLICY_BYTES) throw new Error(`${name} exceeds script policy`)
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
    const restore = installScriptNumberPolicyMonitor(SCRIPT_NUMBER_POLICY_BYTES)
    const covenant = new bsv.Script.Interpreter()
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
        restore()
    }
    if (!accepted) throw new Error(`${name} covenant rejected locally: ${covenant.errstr}`)
    auditP2pkhInput(
        `${name} sponsor`,
        tx,
        1,
        new bsv.Transaction.Output({
            script: bsv.Script.buildPublicKeyHashOut(walletKey.toAddress(bsv.Networks.testnet)),
            satoshis: sponsorValue,
        })
    )
    return {
        name,
        sponsorOutputIndex,
        txid: tx.id,
        rawHex: tx.toString(),
        bytes,
        feeSatoshis: fee,
    }
}

function buildSplit(
    funding: LiveWallet['funding'],
    sponsors: readonly number[],
    wallet: LiveWallet,
    key: bsv.PrivateKey,
    policy: MinerPolicy
): FundingSplit {
    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    if (funding.satoshis <= sponsors.reduce((a, b) => a + b, 0) + SPLIT_FEE_SATS) throw new Error('Fund this wallet with testnet coins for the action and miner fees first')
    const source = new bsv.Transaction.Output({ script: p2pkh, satoshis: funding.satoshis })
    const tx = new bsv.Transaction()
    tx.from({ txId: funding.txid, outputIndex: funding.vout, script: source.script.toHex(), satoshis: source.satoshis })
    sponsors.forEach((satoshis) => tx.addOutput(new bsv.Transaction.Output({ script: p2pkh, satoshis })))
    tx.fee(SPLIT_FEE_SATS)
    tx.change(wallet.address)
    tx.sign(key)
    if (!tx.isFullySigned()) throw new Error('The funding split is not fully signed')
    auditP2pkhInput('Funding split', tx, 0, source)
    const bytes = tx.toString().length / 2
    const fee = source.satoshis - tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    if (fee < Math.ceil((bytes * policy.miningFee.satoshis) / policy.miningFee.bytes)) {
        throw new Error('The funding split fee is below miner policy')
    }
    return {
        txid: tx.id,
        rawHex: tx.toString(),
        transactionBytes: bytes,
        feeSatoshis: fee,
        changeOutputIndex: tx.outputs.length - 1,
        changeSatoshis: tx.outputs.at(-1)!.satoshis,
    }
}

function buildFinalTx(
    previous: StageRecord,
    finalizer: VeilV4Finalizer,
    lockedValue: number,
    split: bsv.Transaction,
    nextPool: ShieldedPoolV4,
    finalPoolValue: number,
    publicOut: number,
    recipient: string,
    wallet: LiveWallet
): bsv.Transaction {
    const sponsor = split.outputs[6]
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: previous.txid,
        outputIndex: 0,
        script: bsv.Script.empty(),
        output: new bsv.Transaction.Output({ script: finalizer.lockingScript, satoshis: lockedValue }),
    }))
    tx.from({ txId: split.id, outputIndex: 6, script: sponsor.script.toHex(), satoshis: sponsor.satoshis })
    tx.addOutput(new bsv.Transaction.Output({ script: nextPool.lockingScript, satoshis: finalPoolValue }))
    if (publicOut > 0) {
        tx.addOutput(new bsv.Transaction.Output({
            script: bsv.Script.buildPublicKeyHashOut(recipient),
            satoshis: publicOut,
        }))
    }
    tx.fee(20_000)
    tx.change(wallet.address)
    return tx
}

function buildPipeline(
    sourceTx: bsv.Transaction,
    pool: ShieldedPoolV4,
    built: BuiltTransition,
    proof: ScryptProof,
    witness: ReturnType<typeof buildPairingResidueWitness>,
    transition: V4Transition,
    vk: PreparedVk,
    splitRecord: FundingSplit,
    sponsors: readonly number[],
    startHeight: number,
    recipient: string,
    wallet: LiveWallet,
    key: bsv.PrivateKey,
    policy: MinerPolicy,
    progress: BuilderProgress
): { stages: StageRecord[]; nextPool: ShieldedPoolV4; finalTx: bsv.Transaction } {
    const contracts = verifierContracts(vk)
    if (
        pool.noteRoot !== transition.oldNoteRoot ||
        pool.nullifierRoot !== transition.oldNullifierRoot ||
        pool.nextIndex !== transition.oldNextIndex ||
        pool.preparationCodeHash !== hash256(contracts.preparation.codePart) ||
        pool.lockingScript.toHex() !== sourceTx.outputs[0].script.toHex()
    ) throw new Error('The pool source does not match the prepared transition')
    const split = new bsv.Transaction(splitRecord.rawHex)
    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    const feeRate = Math.ceil((policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes)
    const sourceValue = sourceTx.outputs[0].satoshis
    const lockedValue = sourceValue + Number(built.public.publicIn)
    const finalPoolValue = lockedValue - Number(built.public.publicOut)
    const preparationState: V4PreparationState = {
        signal: built.statement,
        proof,
        residue: witness.residue,
        residueInverse: witness.residueInverse,
        scale: witness.scale,
        context: {
            transitionHash: V4State.hashTransition(transition),
            poolCodeHash: hash256(pool.codePart),
            lockedValue: BigInt(lockedValue),
            abortHeight: BigInt(startHeight + ABORT_DELAY_BLOCKS),
        },
    }
    contracts.preparation.stateHash = V4State.hashPreparation(preparationState)
    const stages: StageRecord[] = []
    let tx = makeStageTx(
        sourceTx.id, pool.lockingScript, sourceValue, split.id, 0, sponsors[0], p2pkh,
        contracts.preparation.lockingScript, lockedValue, startHeight,
        { address: wallet.address, feeSatoshis: 60_000 }
    )
    stages.push(completeStage(
        'begin', pool, tx, sourceValue, sponsors[0], key, feeRate,
        (self) => self.begin(
            proof, witness, transition, BigInt(startHeight),
            BigInt(startHeight + ABORT_DELAY_BLOCKS), contracts.preparation.codePart, pool.codePart
        ), 0
    ))
    progress(72, 'Built begin stage')

    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(proof.b))
    const negA = { x: proof.a.x, y: -proof.a.y }
    const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
    const scaled = StagedGroth16.mulG1PointBounded(vk.gammaAbc[1], built.statement)
    const p1 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(BN256.addG1Points(vk.gammaAbc[0], scaled)))
    const p2 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(proof.c))
    let millerState: V4MillerState = {
        q, p0, p1, p2, r: q, acc: witness.residueInverse,
        residue: witness.residue, residueInverse: witness.residueInverse,
        scale: witness.scale, context: preparationState.context,
    }
    contracts.stage0.stateHash = V4State.hashMiller(millerState)
    tx = makeStageTx(
        stages.at(-1)!.txid, contracts.preparation.lockingScript, lockedValue,
        split.id, 1, sponsors[1], p2pkh, contracts.stage0.lockingScript, lockedValue
    )
    stages.push(completeStage(
        'prepare', contracts.preparation, tx, lockedValue, sponsors[1], key, feeRate,
        (self) => self.prepare(preparationState, contracts.stage0.codePart), 1
    ))
    progress(77, 'Built preparation stage')

    const templates = [contracts.stage0, contracts.stage1, contracts.stage2, contracts.stage3]
    const starts = [0, 23, 44, 67]
    let current: any = contracts.stage0
    for (let stage = 0; stage < 4; stage++) {
        const inputState = millerState
        millerState = runSlice(inputState, vk, stage * 16, starts[stage])
        const next = stage === 3 ? contracts.finalizer : templates[stage + 1]
        next.stateHash = V4State.hashMiller(millerState)
        const sponsorIndex = stage + 2
        tx = makeStageTx(
            stages.at(-1)!.txid, current.lockingScript, lockedValue,
            split.id, sponsorIndex, sponsors[sponsorIndex], p2pkh,
            next.lockingScript, lockedValue
        )
        stages.push(completeStage(
            `miller-${stage}`, current, tx, lockedValue, sponsors[sponsorIndex], key, feeRate,
            (self) => self.advance(inputState, next.codePart), sponsorIndex
        ))
        current = next
        progress(82 + stage * 4, `Built Miller stage ${stage}`)
    }

    const nextPool = pool.next()
    nextPool.noteRoot = transition.newNoteRoot
    nextPool.nullifierRoot = transition.newNullifierRoot
    nextPool.nextIndex = transition.newNextIndex
    tx = buildFinalTx(
        stages.at(-1)!, contracts.finalizer, lockedValue, split, nextPool,
        finalPoolValue, Number(built.public.publicOut), recipient, wallet
    )
    stages.push(completeStage(
        'finalize', contracts.finalizer, tx, lockedValue, sponsors[6], key, feeRate,
        (self) => self.finalize(millerState, transition, pool.codePart), 6
    ))
    progress(98, 'Audited finalizer locally')
    return { stages, nextPool, finalTx: tx }
}

export class LiveVeilSession {
    private readonly wallet: LiveWallet
    private readonly key: bsv.PrivateKey
    private readonly hash: HashFn
    private readonly vk: PreparedVk
    private readonly policy: MinerPolicy
    private poolState: PoolState
    private notes: Note[] = []
    private poolTx: bsv.Transaction
    private pool: ShieldedPoolV4
    private funding: LiveWallet['funding']
    private snapshot?: PoolSnapshot
    private poolId: string
    private lastPayment?: EncryptedPayment
    private deployment: PreparedTransaction
    private deploymentCommitted = false

    private constructor(
        wallet: LiveWallet,
        hash: HashFn,
        vk: PreparedVk,
        policy: MinerPolicy,
        poolState: PoolState,
        poolTx: bsv.Transaction,
        pool: ShieldedPoolV4,
        fundingIndex: number,
        deployment: PreparedTransaction
    ) {
        this.wallet = wallet
        this.key = bsv.PrivateKey.fromWIF(wallet.wif)
        this.hash = hash
        this.vk = vk
        this.policy = policy
        this.poolState = poolState
        this.poolTx = poolTx
        this.pool = pool
        this.funding = { txid: poolTx.id, vout: fundingIndex, satoshis: poolTx.outputs[fundingIndex]?.satoshis ?? 0 }
        this.poolId = poolTx.id
        this.deployment = deployment
    }

    static async create(wallet: LiveWallet, progress: BuilderProgress): Promise<LiveVeilSession> {
        validateReceivingWallet(wallet)
        if (wallet.funding.satoshis <= 0) throw new Error('Fund this wallet before creating a new pool')
        progress(2, 'Loading audited contract artifacts')
        const [vk, hash, policy] = await Promise.all([
            loadArtifacts(),
            createHash(),
            testnetPolicy(),
        ])
        const funding = wallet.funding
        progress(8, 'Building fresh v4 pool deployment')
        const poolState = new PoolState(hash, true)
        const contracts = verifierContracts(vk)
        const pool = new ShieldedPoolV4(
            poolState.noteTree.root(), poolState.nullifierTree.root(), 0n,
            hash256(contracts.preparation.codePart)
        )
        if (pool.lockingScript.toBuffer().length > policy.maxscriptsizepolicy) {
            throw new Error('The pool contract exceeds current miner policy')
        }
        const feeRate = Math.ceil((policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes)
        const estimatedFee = Math.ceil(((pool.lockingScript.toBuffer().length + 1_000) * feeRate) / 1_000) + FEE_SAFETY_SATS
        const tx = new bsv.Transaction()
        tx.from({
            txId: funding.txid,
            outputIndex: funding.vout,
            script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(),
            satoshis: funding.satoshis,
        })
        tx.addOutput(new bsv.Transaction.Output({ script: pool.lockingScript, satoshis: STATE_ANCHOR_SATS }))
        tx.fee(estimatedFee)
        tx.change(wallet.address)
        tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))
        if (!tx.isFullySigned() || tx.outputs.length !== 2) throw new Error('Could not sign a fresh v4 deployment')
        auditP2pkhInput(
            'Pool deployment',
            tx,
            0,
            new bsv.Transaction.Output({
                script: bsv.Script.buildPublicKeyHashOut(wallet.address),
                satoshis: funding.satoshis,
            })
        )
        const actualFee = funding.satoshis - tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
        const deployment = {
            name: 'deploy-v4-pool',
            txid: tx.id,
            rawHex: tx.toString(),
            bytes: tx.toString().length / 2,
            feeSatoshis: actualFee,
        }
        progress(10, 'Fresh pool deployment prepared')
        return new LiveVeilSession(wallet, hash, vk, policy, poolState, tx, pool, 1, deployment)
    }

    privateBalance(): number {
        return this.notes.reduce((sum, note) => sum + Number(note.amount), 0)
    }

    receivingAddress(): string { return recipientIdentity(this.wallet.wif, this.hash).address }
    publicAddress(): string { return this.wallet.address }
    fundingBalance(): number { return this.funding.satoshis }
    paymentFile(): EncryptedPayment | undefined { return this.lastPayment }
    poolSnapshot(): PoolSnapshot {
        if (!this.snapshot) throw new Error('Complete an action before exporting pool state')
        return this.snapshot
    }
    backupPayload(): unknown {
        return {
            protocol: RECIPIENT_PROTOCOL,
            wallet: { ...this.wallet, funding: this.deploymentCommitted ? this.funding : this.wallet.funding },
            pool: this.snapshot ?? null,
            notes: this.notes.map(encodeNote),
            lastPayment: this.lastPayment,
        }
    }

    // A snapshot is not trusted merely because it decrypted. Bind its trees to
    // the exact new-verifier contract, link every stage, and require ARC MINED.
    private static async checkedSnapshot(snapshot: PoolSnapshot, hash: HashFn, vk: PreparedVk) {
        const state = restorePool(snapshot, hash)
        const raw = [snapshot.rawPoolTx, ...snapshot.chain]
        if (raw.some(value => typeof value !== 'string' || value.length > 22_000_000 || !/^(?:[0-9a-f]{2})+$/.test(value))) throw new Error('Invalid transaction encoding in snapshot')
        const tx = new bsv.Transaction(snapshot.rawPoolTx)
        const contracts = verifierContracts(vk)
        // Constructor constants remain bound to the empty genesis state even
        // when the mutable state roots advance. Reconstruct the same code part.
        const empty = new PoolState(hash, true)
        const pool = new ShieldedPoolV4(empty.noteTree.root(), empty.nullifierTree.root(), 0n, hash256(contracts.preparation.codePart)).next()
        pool.noteRoot = state.noteTree.root()
        pool.nullifierRoot = state.nullifierTree.root()
        pool.nextIndex = BigInt(state.nextIndex)
        if (!tx.outputs[0] || tx.outputs[0].satoshis < STATE_ANCHOR_SATS || tx.outputs[0].script.toHex() !== pool.lockingScript.toHex()) throw new Error('Pool state does not match the recipient-owned on-chain contract')
        let previous = snapshot.previousPoolTxid
        for (const stage of snapshot.chain) {
            const child = new bsv.Transaction(stage)
            if (child.inputs[0]?.prevTxId.toString('hex') !== previous || child.inputs[0]?.outputIndex !== 0) throw new Error('Broken pool transaction lineage')
            previous = child.id
        }
        if (previous !== tx.id || snapshot.chain.at(-1) !== snapshot.rawPoolTx) throw new Error('Pool finalizer mismatch')
        const status = await transactionStatus(tx.id)
        if (status?.txStatus !== 'MINED') throw new Error('Wait until the pool finalizer is MINED before importing this file')
        return { state, tx, pool }
    }

    static async receive(walletInput: LiveWallet, envelope: EncryptedPayment, progress: BuilderProgress): Promise<LiveVeilSession> {
        const wallet = validateReceivingWallet(walletInput)
        const [hash, vk, policy] = await Promise.all([createHash(), loadArtifacts(), testnetPolicy()])
        progress(null, 'Authenticating received payment and checking its mined pool')
        const packet = await decryptPayment(envelope, wallet.wif, hash) as { protocol: string; pool: PoolSnapshot; note: EncodedNote }
        if (packet?.protocol !== RECIPIENT_PROTOCOL) throw new Error('Unsupported payment protocol')
        const checked = await this.checkedSnapshot(packet.pool, hash, vk)
        const identity = recipientIdentity(wallet.wif, hash)
        const note = decodeNote(packet.note, checked.state, identity.owner, hash)
        if (BigInt(checked.tx.outputs[0].satoshis) < note.amount + 1n) throw new Error('Pool output cannot cover the received note')
        const session = new LiveVeilSession(wallet, hash, vk, policy, checked.state, checked.tx, checked.pool, 0, { name: 'imported-pool', txid: checked.tx.id, rawHex: checked.tx.toString(), bytes: checked.tx.toString().length / 2, feeSatoshis: 0 })
        session.funding = wallet.funding
        session.poolId = packet.pool.poolId
        session.snapshot = packet.pool
        session.deploymentCommitted = true
        session.notes = [note]
        return session
    }

    async importPayment(envelope: EncryptedPayment): Promise<void> {
        const packet = await decryptPayment(envelope, this.wallet.wif, this.hash) as { protocol: string; pool: PoolSnapshot; note: EncodedNote }
        if (packet?.protocol !== RECIPIENT_PROTOCOL) throw new Error('Unsupported payment protocol')
        const checked = await LiveVeilSession.checkedSnapshot(packet.pool, this.hash, this.vk)
        this.checkSuccessor(packet.pool, checked.state, checked.tx)
        const note = decodeNote(packet.note, checked.state, recipientIdentity(this.wallet.wif, this.hash).owner, this.hash)
        if (this.notes.some(existing => existing.commitment === note.commitment)) throw new Error('This payment has already been imported')
        const notes = this.notes.filter(existing => checked.state.nullifierTree.leaves[existing.index] === 0n).concat(note)
        if (notes.reduce((sum, n) => sum + n.amount, 1n) > BigInt(checked.tx.outputs[0].satoshis)) throw new Error('Notes exceed pool backing')
        this.acceptSnapshot(packet.pool, checked, notes)
    }

    private checkSuccessor(snapshot: PoolSnapshot, state: PoolState, tx: bsv.Transaction): void {
        if (snapshot.poolId !== this.poolId) throw new Error('This file belongs to another pool; use a separate wallet session')
        if (tx.id !== this.poolTx.id && snapshot.previousPoolTxid !== this.poolTx.id) throw new Error('Import the missing intermediate pool updates first; stale or unrelated state is not accepted')
        assertMonotonic(this.poolState, state)
    }
    private acceptSnapshot(snapshot: PoolSnapshot, checked: { state: PoolState; tx: bsv.Transaction; pool: ShieldedPoolV4 }, notes: Note[]): void {
        this.poolState = checked.state
        this.poolTx = checked.tx
        this.pool = checked.pool
        this.snapshot = snapshot
        this.notes = notes
    }
    async importPoolSnapshot(snapshot: PoolSnapshot): Promise<void> {
        const checked = await LiveVeilSession.checkedSnapshot(snapshot, this.hash, this.vk)
        this.checkSuccessor(snapshot, checked.state, checked.tx)
        this.acceptSnapshot(snapshot, checked, this.notes.filter(note => checked.state.nullifierTree.leaves[note.index] === 0n))
    }
    async bindFunding(rawHex: string, vout: number): Promise<void> {
        if (!this.deploymentCommitted) throw new Error('The prepared fresh deployment has fixed funding; finish it before replacing the tracked fee output')
        if (!Number.isSafeInteger(vout) || vout < 0 || rawHex.length > 22_000_000 || !/^(?:[0-9a-f]{2})+$/.test(rawHex)) throw new Error('Invalid funding transaction or output index')
        const tx = new bsv.Transaction(rawHex)
        const output = tx.outputs[vout]
        if (!output || output.script.toHex() !== bsv.Script.buildPublicKeyHashOut(this.wallet.address).toHex()) throw new Error('Funding output is not owned by this wallet')
        if ((await transactionStatus(tx.id))?.txStatus !== 'MINED') throw new Error('Wait for funding to be mined')
        this.funding = { txid: tx.id, vout, satoshis: output.satoshis }
    }
    static async restoreBackup(value: any, progress: BuilderProgress): Promise<LiveVeilSession> {
        if (value?.protocol !== RECIPIENT_PROTOCOL || !Array.isArray(value.notes)) throw new Error('Unsupported wallet backup')
        const wallet = validateReceivingWallet(value.wallet)
        if (!value.pool) {
            if (value.notes.length) throw new Error('Backup has notes without pool state')
            return this.create(wallet, progress)
        }
        const [hash, vk, policy] = await Promise.all([createHash(), loadArtifacts(), testnetPolicy()])
        const checked = await this.checkedSnapshot(value.pool, hash, vk)
        const identity = recipientIdentity(wallet.wif, hash)
        const notes = value.notes.map((note: EncodedNote) => decodeNote(note, checked.state, identity.owner, hash))
        if (new Set(notes.map((note: Note) => note.index)).size !== notes.length || notes.reduce((sum: bigint, n: Note) => sum + n.amount, 1n) > BigInt(checked.tx.outputs[0].satoshis)) throw new Error('Invalid note collection')
        const session = new LiveVeilSession(wallet, hash, vk, policy, checked.state, checked.tx, checked.pool, 0, { name: 'restored-pool', txid: checked.tx.id, rawHex: checked.tx.toString(), bytes: checked.tx.toString().length / 2, feeSatoshis: 0 })
        session.funding = wallet.funding
        session.poolId = value.pool.poolId
        session.snapshot = value.pool
        session.deploymentCommitted = true
        session.notes = notes
        session.lastPayment = value.lastPayment
        return session
    }

    lockedBalance(height: number): number {
        return this.notes
            .filter((note) => Number(note.lockHeight) > height)
            .reduce((sum, note) => sum + Number(note.amount), 0)
    }

    async prepare(
        action: LiveAction,
        amount: number,
        recipient: string,
        unlockHeight: number | string,
        progress: BuilderProgress,
        readHeight: () => Promise<number> = testnetHeight
    ): Promise<PreparedLiveAction> {
        if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('Enter a positive whole-satoshi amount')
        progress(1, 'Checking current testnet block height')
        const startHeight = await readHeight()
        const resolvedUnlockHeight = action === 'lock' ? resolveLockHeight(unlockHeight, startHeight) : 0
        const stagedState = cloneState(this.poolState, this.hash)
        const identity = recipientIdentity(this.wallet.wif, this.hash)
        const ownedKey = identity.owner
        const destination = action === 'send' ? parseRecipientAddress(recipient) : undefined
        if (action === 'send' && recipient === identity.address) throw new Error('Use another wallet’s Veil address for Send; use Lock to create a self-owned locked note')
        const oldPrivateBalance = this.privateBalance()
        let built: BuiltTransition
        let spent: Note | undefined
        let publicRecipient = this.wallet.address
        progress(12, 'Constructing private state transition')

        if (action === 'shield') {
            built = stagedState.build({
                mode: 0,
                publicIn: BigInt(amount),
                outputs: [{ amount: BigInt(amount), ownerKey: ownedKey, rho: randomField() }],
            })
        } else {
            spent = this.notes.find((note) => Number(note.amount) >= amount && Number(note.lockHeight) <= startHeight)
            if (!spent) throw new Error('No mature private note is large enough for that amount')
            const change = Number(spent.amount) - amount
            if ((action === 'send' || action === 'lock') && change <= 0) {
                throw new Error('Send and lock must leave at least 1 sat of private change')
            }
            if (action === 'withdraw') {
                publicRecipient = recipient || this.wallet.address
                bsv.Address.fromString(publicRecipient, bsv.Networks.testnet)
                built = stagedState.build({
                    mode: 2,
                    spend: { note: spent, spendingKey: identity.spendingKey },
                    currentHeight: BigInt(startHeight),
                    publicOut: BigInt(amount),
                    recipient: recipientField(publicRecipient),
                    outputs: change > 0
                        ? [{ amount: BigInt(change), ownerKey: ownedKey, rho: randomField() }]
                        : [],
                })
            } else {
                const lockHeight = resolvedUnlockHeight
                if (action === 'lock' && (!Number.isSafeInteger(lockHeight) || lockHeight <= startHeight)) {
                    throw new Error(`Choose an unlock height above ${startHeight}`)
                }
                built = stagedState.build({
                    mode: 1,
                    spend: { note: spent, spendingKey: identity.spendingKey },
                    currentHeight: BigInt(startHeight),
                    outputs: [
                        {
                            amount: BigInt(amount),
                            ownerKey: destination?.owner ?? ownedKey,
                            rho: randomField(),
                            lockHeight: BigInt(lockHeight),
                        },
                        { amount: BigInt(change), ownerKey: ownedKey, rho: randomField() },
                    ],
                })
            }
        }

        // Validate canonical recipient bytes before doing expensive proof work.
        const transition = transitionFrom(built)
        progress(null, 'Loading Groth16 proof artifacts…')
        const [wasm, zkey] = await Promise.all(['shielded_pool.wasm', 'shielded_pool_final.zkey'].map(async name => {
            const response = await fetch(asset(`recipient/${name}`))
            if (!response.ok) throw new Error(`Required recipient proof artifact is unavailable: ${name}`)
            return new Uint8Array(await response.arrayBuffer())
        }))
        progress(null, 'Generating Groth16 proof…')
        const { proof } = await groth16.fullProve(
            built.circuitInput,
            wasm,
            zkey
        )
        progress(58, 'Preparing on-chain verifier witness')
        const converted = toScryptProof(proof as SnarkProof)
        const witness = buildPairingResidueWitness(built.statement, converted, this.vk)
        const sponsors = [
            action === 'shield' ? amount + 61_000 : 61_000,
            80_000, 75_000, 75_000, 75_000, 45_000, 21_000, 40_000,
        ]
        const split = buildSplit(
            this.funding, sponsors,
            this.wallet, this.key, this.policy
        )
        progress(66, 'Funding and fee split signed locally')
        const pipeline = buildPipeline(
            this.poolTx, this.pool, built, converted, witness, transition, this.vk,
            split, sponsors, startHeight, publicRecipient,
            this.wallet, this.key, this.policy, progress
        )
        const splitTx = new bsv.Transaction(split.rawHex)
        const newNotes = this.notes.filter((note) => note !== spent).concat(built.outputNotes.filter(note => note.ownerKey === ownedKey))
        const transactions: PreparedTransaction[] = [
            ...(this.deploymentCommitted ? [] : [this.deployment]),
            {
                name: 'funding-split',
                txid: split.txid,
                rawHex: split.rawHex,
                bytes: split.transactionBytes,
                feeSatoshis: split.feeSatoshis,
            },
            ...pipeline.stages,
        ]
        const newPrivateBalance = newNotes.reduce((sum, note) => sum + Number(note.amount), 0)
        const newLockedBalance = newNotes
            .filter((note) => Number(note.lockHeight) > startHeight)
            .reduce((sum, note) => sum + Number(note.amount), 0)
        const snapshot: PoolSnapshot = {
            protocol: RECIPIENT_PROTOCOL, poolId: this.poolId,
            rawPoolTx: pipeline.finalTx.toString(), previousPoolTxid: this.poolTx.id,
            chain: pipeline.stages.map(stage => stage.rawHex),
            nextIndex: stagedState.nextIndex,
            leaves: stagedState.noteTree.leaves.map(String), nullifiers: stagedState.nullifierTree.leaves.map(String),
        }
        const payment = action === 'send'
            ? await encryptPayment(recipient, { protocol: RECIPIENT_PROTOCOL, pool: snapshot, note: encodeNote(built.outputNotes[0]) })
            : undefined
        progress(100, 'Exact transaction chain ready for review')
        return {
            action,
            amount,
            recipient: action === 'withdraw' ? publicRecipient : action === 'send' ? recipient : undefined,
            unlockHeight: action === 'lock' ? resolvedUnlockHeight : undefined,
            startHeight,
            oldPrivateBalance,
            newPrivateBalance,
            newLockedBalance,
            totalFees: transactions.reduce((sum, tx) => sum + tx.feeSatoshis, 0),
            transactions,
            warning: 'These exact testnet transactions are signed but have not been broadcast. Send requires delivering the encrypted payment file after mining.',
            payment,
            snapshot,
            _next: {
                poolState: stagedState,
                notes: newNotes,
                poolTx: pipeline.finalTx,
                pool: pipeline.nextPool,
                funding: { txid: splitTx.id, vout: split.changeOutputIndex, satoshis: split.changeSatoshis },
                deploymentCommitted: true,
            },
        }
    }

    commit(plan: PreparedLiveAction): void {
        this.poolState = plan._next.poolState
        this.notes = plan._next.notes
        this.poolTx = plan._next.poolTx
        this.pool = plan._next.pool
        this.funding = plan._next.funding
        this.snapshot = plan.snapshot
        this.lastPayment = plan.payment ?? this.lastPayment
        this.deploymentCommitted = plan._next.deploymentCommitted
    }
}
