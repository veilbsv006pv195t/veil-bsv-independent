import { createHash as createNodeHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
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
import { BN256, BN256Pairing } from 'scrypt-ts-lib/dist/ec/bn256'
import { PoolState, createHash } from '../src/crypto'
import type { BuiltTransition, Note } from '../src/crypto'
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
import {
    completeStage,
    arcAccepted,
    jsonSafe,
    liveHeight,
    livePolicy,
    loadArtifacts,
    makeStageTx,
    parseSavedNote,
    randomField,
    requireMinedStatus,
    runSlice,
    torJson,
    torPostTransaction,
    writePrivate,
} from './testnet-v4-lifecycle'
import type {
    Policy,
    SavedStage,
    WalletFile,
} from './testnet-v4-lifecycle'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')
const SHIELD_SECRETS_FILE = path.join(PRIVATE_DIR, 'testnet-v4-shield-secrets.json')
const TRANSFER_SIGNED_FILE = path.join(PRIVATE_DIR, 'testnet-v4-transfer-signed.json')
const TRANSFER_SECRETS_FILE = path.join(PRIVATE_DIR, 'testnet-v4-transfer-secrets.json')
const TRANSFER_CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-transfer-confirmation.json'
)
const LOCK_PLAN_FILE = path.join(PRIVATE_DIR, 'testnet-v4-lock-test-signed.json')
const LOCK_SECRETS_FILE = path.join(PRIVATE_DIR, 'testnet-v4-lock-test-secrets.json')
const UNSHIELD_SPLIT_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-lock-unshield-split-receipt.json'
)
const EARLY_REJECTION_RECEIPT_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-lock-unshield-early-rejection.json'
)
const MATURE_UNSHIELD_RECEIPT_PREFIX = path.join(
    PRIVATE_DIR,
    'testnet-v4-lock-unshield-mature'
)
const WASM = path.join(ROOT, 'build', 'shielded_pool_js', 'shielded_pool.wasm')
const ZKEY = path.join(ROOT, 'build', 'shielded_pool_final.zkey')
const VKEY = path.join(ROOT, 'build', 'verification_key.json')
const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))
const LOCKED_SATS = 10_000n
const LOCK_DELAY_BLOCKS = 24
const SPLIT_FEE_SATS = 1_000
const ABORT_DELAY_BLOCKS = 144
const SCRIPT_NUMBER_POLICY_BYTES = 10_000
const LOCK_SHIELD_SPONSORS = [71_000, 80_000, 75_000, 75_000, 75_000, 45_000, 21_000, 40_000]
const UNSHIELD_SPONSORS = [61_000, 80_000, 75_000, 75_000, 75_000, 45_000, 21_000, 40_000]

interface ExistingTransfer {
    split: {
        txid: string
        rawHex: string
        changeOutputIndex: number
        changeSatoshis: number
    }
    poolOutputSatoshis: number
    nullifier: string
    nextState: {
        noteRoot: string
        nullifierRoot: string
        nextNoteIndex: string
    }
    stages: SavedStage[]
}

interface FundingSplit {
    sourceTxid: string
    sourceOutputIndex: number
    sourceSatoshis: number
    txid: string
    rawHex: string
    transactionBytes: number
    feeSatoshis: number
    changeOutputIndex: number
    changeSatoshis: number
}

interface PipelinePlan {
    kind: 'locked-shield' | 'locked-unshield'
    sourcePoolTxid: string
    sourcePoolSatoshis: number
    split: FundingSplit
    startHeight: number
    abortHeight: number
    publicInSatoshis: number
    publicOutSatoshis: number
    finalPoolSatoshis: number
    nextState: {
        noteRoot: string
        nullifierRoot: string
        nextNoteIndex: string
    }
    stages: SavedStage[]
}

interface LockTestPlan {
    format: 'veil-v4-testnet-height-lock-plan-v1'
    network: 'testnet'
    broadcast: false
    createdAt: string
    sourceTransferFinalizerTxid: string
    sourceTransferBlockHeight: number
    lockHeight: number
    lockDelayBlocks: number
    lockedSatoshis: number
    livePolicy: Policy
    lockedShield: PipelinePlan
    lockedUnshield: PipelinePlan
    negativeTests: {
        localEarlyUnshieldRejected: true
        localEarlyUnshieldError: string
        networkEarlyRejectionPending: true
        matureTransactionUsesIdenticalTxid: true
    }
}

type PreparedVk = ReturnType<typeof toPreparedVerifyingKey>
type ScryptProof = ReturnType<typeof toScryptProof>

function recipientField(address: string): bigint {
    const hash = bsv.Address.fromString(address, bsv.Networks.testnet).hashBuffer
    return BigInt(`0x${Buffer.from(hash).reverse().toString('hex')}`)
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
        recipientPkh: PubKeyHash(int2ByteString(built.public.recipient, 20n)),
    }
}

async function prove(
    built: BuiltTransition,
    vk: PreparedVk
): Promise<{
    proof: ScryptProof
    witness: ReturnType<typeof buildPairingResidueWitness>
    transition: V4Transition
}> {
    const { proof } = await groth16.fullProve(built.circuitInput, WASM, ZKEY)
    const converted = toScryptProof(proof as SnarkProof)
    return {
        proof: converted,
        witness: buildPairingResidueWitness(built.statement, converted, vk),
        transition: transitionFrom(built),
    }
}

function buildSplit(
    sourceTx: bsv.Transaction,
    sourceOutputIndex: number,
    sponsors: readonly number[],
    wallet: WalletFile,
    key: bsv.PrivateKey,
    policy: Policy
): FundingSplit {
    const source = sourceTx.outputs[sourceOutputIndex]
    if (!source) throw new Error('Funding source output is missing')
    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    if (source.script.toHex() !== p2pkh.toHex()) {
        throw new Error('Funding source is not controlled by the deployment wallet')
    }
    const tx = new bsv.Transaction()
    tx.from({
        txId: sourceTx.id,
        outputIndex: sourceOutputIndex,
        script: source.script.toHex(),
        satoshis: source.satoshis,
    })
    for (const sats of sponsors) {
        tx.addOutput(new bsv.Transaction.Output({ script: p2pkh, satoshis: sats }))
    }
    tx.fee(SPLIT_FEE_SATS)
    tx.change(wallet.address)
    tx.sign(key)
    if (!tx.isFullySigned()) throw new Error('Height-lock funding split is not fully signed')
    const bytes = tx.toString().length / 2
    const fee = source.satoshis - tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const minimumFee = Math.ceil(
        (bytes * policy.miningFee.satoshis) / policy.miningFee.bytes
    )
    if (fee < minimumFee) throw new Error('Height-lock funding split fee is below policy')
    return {
        sourceTxid: sourceTx.id,
        sourceOutputIndex,
        sourceSatoshis: source.satoshis,
        txid: tx.id,
        rawHex: tx.toString(),
        transactionBytes: bytes,
        feeSatoshis: fee,
        changeOutputIndex: tx.outputs.length - 1,
        changeSatoshis: tx.outputs.at(-1)!.satoshis,
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

function buildFinalTx(
    previous: SavedStage,
    finalizer: VeilV4Finalizer,
    lockedValue: number,
    split: bsv.Transaction,
    sponsorIndex: number,
    nextPool: ShieldedPoolV4,
    finalPoolValue: number,
    publicOut: number,
    wallet: WalletFile
): bsv.Transaction {
    const sponsor = split.outputs[sponsorIndex]
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: previous.txid,
        outputIndex: 0,
        script: bsv.Script.empty(),
        output: new bsv.Transaction.Output({
            script: finalizer.lockingScript,
            satoshis: lockedValue,
        }),
    }))
    tx.from({
        txId: split.id,
        outputIndex: sponsorIndex,
        script: sponsor.script.toHex(),
        satoshis: sponsor.satoshis,
    })
    tx.addOutput(new bsv.Transaction.Output({
        script: nextPool.lockingScript,
        satoshis: finalPoolValue,
    }))
    if (publicOut > 0) {
        tx.addOutput(new bsv.Transaction.Output({
            script: bsv.Script.buildPublicKeyHashOut(wallet.address),
            satoshis: publicOut,
        }))
    }
    tx.fee(20_000)
    tx.change(wallet.address)
    return tx
}

function buildPipeline(
    kind: PipelinePlan['kind'],
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
    abortHeight: number,
    wallet: WalletFile,
    key: bsv.PrivateKey,
    policy: Policy
): PipelinePlan {
    if (
        pool.noteRoot !== transition.oldNoteRoot ||
        pool.nullifierRoot !== transition.oldNullifierRoot ||
        pool.nextIndex !== transition.oldNextIndex ||
        pool.lockingScript.toHex() !== sourceTx.outputs[0].script.toHex()
    ) throw new Error(`${kind} source pool does not match its transition`)
    const contracts = verifierContracts(vk)
    if (pool.preparationCodeHash !== hash256(contracts.preparation.codePart)) {
        throw new Error(`${kind} source uses a different verifier chain`)
    }
    const split = new bsv.Transaction(splitRecord.rawHex)
    if (split.id !== splitRecord.txid) throw new Error(`${kind} split bytes changed`)
    const p2pkh = bsv.Script.buildPublicKeyHashOut(wallet.address)
    const feeRate = Math.ceil(
        (policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes
    )
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
            abortHeight: BigInt(abortHeight),
        },
    }
    contracts.preparation.stateHash = V4State.hashPreparation(preparationState)
    const stages: SavedStage[] = []
    let tx = makeStageTx(
        sourceTx.id,
        pool.lockingScript,
        sourceValue,
        split.id,
        0,
        sponsors[0],
        p2pkh,
        contracts.preparation.lockingScript,
        lockedValue,
        startHeight,
        { address: wallet.address, feeSatoshis: 60_000 }
    )
    stages.push(completeStage(
        'begin', pool, tx, sourceValue, sponsors[0], key, feeRate,
        (self) => self.begin(
            proof,
            witness,
            transition,
            BigInt(startHeight),
            BigInt(abortHeight),
            contracts.preparation.codePart,
            pool.codePart
        ),
        0
    ))

    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(proof.b))
    const negA = { x: proof.a.x, y: -proof.a.y }
    const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
    const scaled = StagedGroth16.mulG1PointBounded(vk.gammaAbc[1], built.statement)
    const p1 = BN256.makeAffineCurvePoint(
        BN256.createCurvePoint(BN256.addG1Points(vk.gammaAbc[0], scaled))
    )
    const p2 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(proof.c))
    let millerState: V4MillerState = {
        q, p0, p1, p2, r: q, acc: witness.residueInverse,
        residue: witness.residue, residueInverse: witness.residueInverse,
        scale: witness.scale, context: preparationState.context,
    }
    contracts.stage0.stateHash = V4State.hashMiller(millerState)
    tx = makeStageTx(
        stages.at(-1)!.txid,
        contracts.preparation.lockingScript,
        lockedValue,
        split.id,
        1,
        sponsors[1],
        p2pkh,
        contracts.stage0.lockingScript,
        lockedValue
    )
    stages.push(completeStage(
        'prepare', contracts.preparation, tx, lockedValue, sponsors[1], key, feeRate,
        (self) => self.prepare(preparationState, contracts.stage0.codePart),
        1
    ))

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
            stages.at(-1)!.txid,
            current.lockingScript,
            lockedValue,
            split.id,
            sponsorIndex,
            sponsors[sponsorIndex],
            p2pkh,
            next.lockingScript,
            lockedValue
        )
        stages.push(completeStage(
            `miller-${stage}`,
            current,
            tx,
            lockedValue,
            sponsors[sponsorIndex],
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
    tx = buildFinalTx(
        stages.at(-1)!,
        contracts.finalizer,
        lockedValue,
        split,
        6,
        nextPool,
        finalPoolValue,
        Number(built.public.publicOut),
        wallet
    )
    stages.push(completeStage(
        'finalize', contracts.finalizer, tx, lockedValue, sponsors[6], key, feeRate,
        (self) => self.finalize(millerState, transition, pool.codePart),
        6
    ))
    return {
        kind,
        sourcePoolTxid: sourceTx.id,
        sourcePoolSatoshis: sourceValue,
        split: splitRecord,
        startHeight,
        abortHeight,
        publicInSatoshis: Number(built.public.publicIn),
        publicOutSatoshis: Number(built.public.publicOut),
        finalPoolSatoshis: finalPoolValue,
        nextState: {
            noteRoot: built.public.newNoteRoot.toString(),
            nullifierRoot: built.public.newNullifierRoot.toString(),
            nextNoteIndex: built.public.newNextIndex.toString(),
        },
        stages,
    }
}

function auditPipeline(
    plan: PipelinePlan,
    sourceTx: bsv.Transaction,
    fundingSourceTx: bsv.Transaction,
    policy: Policy,
    wallet: WalletFile
) {
    if (
        sourceTx.id !== plan.sourcePoolTxid ||
        sourceTx.outputs[0].satoshis !== plan.sourcePoolSatoshis
    ) throw new Error(`${plan.kind} source transaction changed`)
    const split = new bsv.Transaction(plan.split.rawHex)
    const fundingSource = fundingSourceTx.outputs[plan.split.sourceOutputIndex]
    if (
        fundingSourceTx.id !== plan.split.sourceTxid ||
        !fundingSource ||
        fundingSource.satoshis !== plan.split.sourceSatoshis ||
        split.id !== plan.split.txid ||
        split.inputs[0].prevTxId.toString('hex') !== fundingSourceTx.id ||
        split.inputs[0].outputIndex !== plan.split.sourceOutputIndex
    ) throw new Error(`${plan.kind} funding chain changed`)
    const splitCheck = new bsv.Script.Interpreter()
    if (!splitCheck.verify(
        split.inputs[0].script,
        fundingSource.script,
        split,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(fundingSource.satoshis)
    )) throw new Error(`${plan.kind} split signature rejected: ${splitCheck.errstr}`)
    const splitFee = fundingSource.satoshis -
        split.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    if (splitFee !== plan.split.feeSatoshis) throw new Error(`${plan.kind} split fee changed`)

    let previous = sourceTx
    const expectedNames = ['begin', 'prepare', 'miller-0', 'miller-1', 'miller-2', 'miller-3', 'finalize']
    const results: unknown[] = []
    for (let index = 0; index < plan.stages.length; index++) {
        const record = plan.stages[index]
        const tx = new bsv.Transaction(record.rawHex)
        const isFinal = record.name === 'finalize'
        const expectedOutputs = isFinal
            ? (plan.publicOutSatoshis > 0 ? 3 : 2)
            : (record.name === 'begin' ? 2 : 1)
        if (
            record.name !== expectedNames[index] ||
            tx.id !== record.txid ||
            tx.toString().length / 2 !== record.transactionBytes ||
            tx.inputs.length !== 2 ||
            tx.outputs.length !== expectedOutputs ||
            tx.inputs[0].prevTxId.toString('hex') !== previous.id ||
            tx.inputs[0].outputIndex !== 0 ||
            tx.inputs[1].prevTxId.toString('hex') !== split.id ||
            tx.inputs[1].outputIndex !== record.sponsorOutputIndex
        ) throw new Error(`${plan.kind} ${record.name} transaction chain changed`)
        if (record.name === 'begin' && tx.nLockTime !== plan.startHeight) {
            throw new Error(`${plan.kind} begin locktime changed`)
        }
        const source = previous.outputs[0]
        const sponsor = split.outputs[record.sponsorOutputIndex]
        const fee = source.satoshis + sponsor.satoshis -
            tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
        const minimumFee = Math.ceil(
            (record.transactionBytes * policy.miningFee.satoshis) /
            policy.miningFee.bytes
        )
        if (fee !== record.feeSatoshis || fee < minimumFee) {
            throw new Error(`${plan.kind} ${record.name} fee audit failed`)
        }
        const covenant = new bsv.Script.Interpreter()
        if (!covenant.verify(
            tx.inputs[0].script,
            source.script,
            tx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(source.satoshis)
        )) throw new Error(`${plan.kind} ${record.name} covenant rejected: ${covenant.errstr}`)
        const sponsorCheck = new bsv.Script.Interpreter()
        if (!sponsorCheck.verify(
            tx.inputs[1].script,
            sponsor.script,
            tx,
            1,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(sponsor.satoshis)
        )) throw new Error(`${plan.kind} ${record.name} sponsor rejected: ${sponsorCheck.errstr}`)
        if (isFinal) {
            if (tx.outputs[0].satoshis !== plan.finalPoolSatoshis) {
                throw new Error(`${plan.kind} final pool value changed`)
            }
            if (plan.publicOutSatoshis > 0) {
                if (
                    tx.outputs[1].satoshis !== plan.publicOutSatoshis ||
                    tx.outputs[1].script.toHex() !==
                        bsv.Script.buildPublicKeyHashOut(wallet.address).toHex()
                ) throw new Error(`${plan.kind} transparent withdrawal changed`)
            }
        }
        results.push({
            name: record.name,
            txid: record.txid,
            transactionBytes: record.transactionBytes,
            feeSatoshis: record.feeSatoshis,
            covenantAccepted: true,
            sponsorSignatureAccepted: true,
        })
        previous = tx
    }
    return {
        kind: plan.kind,
        sourcePoolTxid: plan.sourcePoolTxid,
        splitTxid: plan.split.txid,
        splitSignatureAccepted: true,
        splitFeeSatoshis: splitFee,
        startHeight: plan.startHeight,
        abortHeight: plan.abortHeight,
        publicInSatoshis: plan.publicInSatoshis,
        publicOutSatoshis: plan.publicOutSatoshis,
        finalPoolSatoshis: plan.finalPoolSatoshis,
        nextState: plan.nextState,
        stages: results,
    }
}

function auditPlan(plan: LockTestPlan, policy: Policy) {
    const transfer = JSON.parse(readFileSync(TRANSFER_SIGNED_FILE, 'utf8')) as ExistingTransfer
    const transferFinalizer = transfer.stages.at(-1)
    if (!transferFinalizer || transferFinalizer.txid !== plan.sourceTransferFinalizerTxid) {
        throw new Error('Height-lock plan references a different transfer finalizer')
    }
    const transferFinalizerTx = new bsv.Transaction(transferFinalizer.rawHex)
    const transferSplitTx = new bsv.Transaction(transfer.split.rawHex)
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const lockedShield = auditPipeline(
        plan.lockedShield,
        transferFinalizerTx,
        transferSplitTx,
        policy,
        wallet
    )
    const lockedShieldFinalizer = new bsv.Transaction(
        plan.lockedShield.stages.at(-1)!.rawHex
    )
    const lockedShieldSplit = new bsv.Transaction(plan.lockedShield.split.rawHex)
    const lockedUnshield = auditPipeline(
        plan.lockedUnshield,
        lockedShieldFinalizer,
        lockedShieldSplit,
        policy,
        wallet
    )
    if (
        !plan.negativeTests.localEarlyUnshieldRejected ||
        !plan.negativeTests.localEarlyUnshieldError.includes('locked until block') ||
        plan.lockedUnshield.startHeight !== plan.lockHeight ||
        plan.lockedUnshield.stages[0].txid !==
            new bsv.Transaction(plan.lockedUnshield.stages[0].rawHex).id
    ) throw new Error('Height-lock negative-test evidence is incomplete')
    return {
        network: 'testnet',
        broadcast: false,
        sourceTransferFinalizerTxid: plan.sourceTransferFinalizerTxid,
        sourceTransferBlockHeight: plan.sourceTransferBlockHeight,
        lockHeight: plan.lockHeight,
        lockDelayBlocks: plan.lockDelayBlocks,
        lockedSatoshis: plan.lockedSatoshis,
        currentPolicy: policy,
        negativeTests: plan.negativeTests,
        lockedShieldManifestHash: manifestHash(plan.lockedShield),
        lockedShield,
        lockedUnshield,
    }
}

function manifestTransactions(plan: PipelinePlan): Array<{
    name: string
    txid: string
    rawHex: string
    transactionBytes: number
    feeSatoshis: number
}> {
    return [
        {
            name: 'split',
            txid: plan.split.txid,
            rawHex: plan.split.rawHex,
            transactionBytes: plan.split.transactionBytes,
            feeSatoshis: plan.split.feeSatoshis,
        },
        ...plan.stages.map((stage) => ({
            name: stage.name,
            txid: stage.txid,
            rawHex: stage.rawHex,
            transactionBytes: stage.transactionBytes,
            feeSatoshis: stage.feeSatoshis,
        })),
    ]
}

function manifestHash(plan: PipelinePlan): string {
    const canonical = manifestTransactions(plan)
        .map(({ name, txid }) => `${name}:${txid}`)
        .join('\n')
    return createNodeHash('sha256').update(canonical).digest('hex')
}

function receiptFile(entry: { name: string }): string {
    return path.join(
        PRIVATE_DIR,
        `testnet-v4-lock-shield-${entry.name}-receipt.json`
    )
}

function waitForSeen(txid: string): unknown {
    const deadline = Date.now() + 120_000
    let last: unknown
    while (Date.now() < deadline) {
        last = torJson(`https://testnet.arc.gorillapool.io/v1/tx/${txid}`)
        const status = last as { txid?: string; txStatus?: string; extraInfo?: string }
        if (status.txid?.toLowerCase() !== txid.toLowerCase()) {
            throw new Error(`ARC status returned the wrong TXID for ${txid}`)
        }
        if (status.txStatus === 'SEEN_ON_NETWORK' || status.txStatus === 'MINED') {
            return last
        }
        if (['REJECTED', 'DOUBLE_SPEND_ATTEMPTED'].includes(status.txStatus ?? '')) {
            throw new Error(`ARC rejected ${txid}: ${status.extraInfo ?? status.txStatus}`)
        }
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2_000)
    }
    throw new Error(`ARC did not report SEEN_ON_NETWORK for ${txid}: ${JSON.stringify(last)}`)
}

function recoverLockedShieldEntry(plan: LockTestPlan): void {
    const expected = process.argv
        .find((value) => value.startsWith('--expect-manifest='))
        ?.slice('--expect-manifest='.length)
        .toLowerCase()
    const actual = manifestHash(plan.lockedShield)
    if (expected !== actual) throw new Error('Recovery manifest approval does not match')
    const name = process.argv
        .find((value) => value.startsWith('--name='))
        ?.slice('--name='.length)
    const entries = manifestTransactions(plan.lockedShield)
    const index = entries.findIndex((entry) => entry.name === name)
    if (index < 0) throw new Error('Recovery entry is not in the approved manifest')
    const entry = entries[index]
    const file = receiptFile(entry)
    if (existsSync(file)) throw new Error(`Receipt already exists: ${file}`)
    const status = waitForSeen(entry.txid)
    const receipt = {
        format: 'veil-v4-testnet-lock-shield-chain-receipt-v1',
        network: 'testnet',
        torOnly: true,
        recoveredAt: new Date().toISOString(),
        recoveredFromArcStatus: true,
        manifestHash: actual,
        manifestIndex: index,
        manifestLength: entries.length,
        name: entry.name,
        txid: entry.txid,
        transactionBytes: entry.transactionBytes,
        feeSatoshis: entry.feeSatoshis,
        httpStatus: 200,
        response: status,
    }
    writePrivate(file, receipt)
    console.log(JSON.stringify(receipt, null, 2))
}

function sendLockedShieldChain(plan: LockTestPlan): void {
    const expected = process.argv
        .find((value) => value.startsWith('--expect-manifest='))
        ?.slice('--expect-manifest='.length)
        .toLowerCase()
    const actual = manifestHash(plan.lockedShield)
    if (!expected || !/^[0-9a-f]{64}$/.test(expected) || expected !== actual) {
        throw new Error('send-locked-shield-chain requires --expect-manifest=<exact audited hash>')
    }
    auditPlan(plan, livePolicy())
    requireMinedStatus(plan.sourceTransferFinalizerTxid)
    const tip = liveHeight()
    if (tip >= plan.lockHeight - 2) {
        throw new Error(
            `Only ${plan.lockHeight - tip} blocks remain before the lock; regenerate the plan`
        )
    }
    const entries = manifestTransactions(plan.lockedShield)
    const receiptFiles = entries.map(receiptFile)
    for (let index = 0; index < entries.length; index++) {
        const entry = entries[index]
        if (existsSync(receiptFiles[index])) {
            const existing = JSON.parse(readFileSync(receiptFiles[index], 'utf8')) as {
                manifestHash?: string
                manifestIndex?: number
                name?: string
                txid?: string
                httpStatus?: number
                response?: unknown
            }
            if (
                existing.manifestHash !== actual ||
                existing.manifestIndex !== index ||
                existing.name !== entry.name ||
                existing.txid !== entry.txid ||
                !arcAccepted({
                    httpStatus: existing.httpStatus ?? 0,
                    response: existing.response,
                }, entry.txid)
            ) throw new Error(`Existing ${entry.name} receipt does not match the manifest`)
            waitForSeen(entry.txid)
            continue
        }
        const submitted = torPostTransaction(entry.rawHex, 'RECEIVED')
        const receipt = {
            format: 'veil-v4-testnet-lock-shield-chain-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            manifestHash: actual,
            manifestIndex: index,
            manifestLength: entries.length,
            name: entry.name,
            txid: entry.txid,
            transactionBytes: entry.transactionBytes,
            feeSatoshis: entry.feeSatoshis,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(receiptFiles[index], receipt)
        if (!arcAccepted(submitted, entry.txid)) {
            throw new Error(
                `ARC did not accept locked-shield ${entry.name}; chain stopped: ${JSON.stringify(receipt)}`
            )
        }
        console.log(JSON.stringify(receipt, null, 2))
        waitForSeen(entry.txid)
    }
    console.log('The exact locked-shield manifest was submitted parent-first through Tor; no unshield was sent.')
}

function sendEarlyUnshield(plan: LockTestPlan): void {
    const begin = plan.lockedUnshield.stages[0]
    const expected = process.argv
        .find((value) => value.startsWith('--expect='))
        ?.slice('--expect='.length)
        .toLowerCase()
    if (!expected || expected !== begin.txid.toLowerCase()) {
        throw new Error('send-early-unshield requires --expect=<exact audited begin TXID>')
    }
    if (existsSync(EARLY_REJECTION_RECEIPT_FILE)) {
        throw new Error('Early-unshield rejection evidence already exists; refusing to resubmit')
    }
    auditPlan(plan, livePolicy())
    const lockedShieldFinalizer = plan.lockedShield.stages.at(-1)
    if (!lockedShieldFinalizer) throw new Error('Locked-shield finalizer is missing')
    const mined = requireMinedStatus(lockedShieldFinalizer.txid)
    const tip = liveHeight()
    if (tip >= plan.lockHeight) {
        throw new Error(`Height lock already matured at ${plan.lockHeight}; early test is no longer possible`)
    }
    const beginTx = new bsv.Transaction(begin.rawHex)
    if (beginTx.id !== begin.txid || beginTx.nLockTime !== plan.lockHeight) {
        throw new Error('Audited early-unshield transaction or nLockTime changed')
    }

    const splitEntry = {
        name: 'unshield-split',
        txid: plan.lockedUnshield.split.txid,
        rawHex: plan.lockedUnshield.split.rawHex,
        transactionBytes: plan.lockedUnshield.split.transactionBytes,
        feeSatoshis: plan.lockedUnshield.split.feeSatoshis,
    }
    if (existsSync(UNSHIELD_SPLIT_RECEIPT_FILE)) {
        const existing = JSON.parse(
            readFileSync(UNSHIELD_SPLIT_RECEIPT_FILE, 'utf8')
        ) as { httpStatus?: number; response?: unknown; txid?: string }
        if (
            existing.txid !== splitEntry.txid ||
            !arcAccepted({
                httpStatus: existing.httpStatus ?? 0,
                response: existing.response,
            }, splitEntry.txid)
        ) throw new Error('Existing unshield-split receipt is invalid')
        waitForSeen(splitEntry.txid)
    } else {
        const submittedSplit = torPostTransaction(splitEntry.rawHex, 'RECEIVED')
        const splitReceipt = {
            format: 'veil-v4-testnet-lock-unshield-split-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            sourceLockedShieldFinalizerTxid: lockedShieldFinalizer.txid,
            sourceLockedShieldBlockHeight: mined.blockHeight,
            txid: splitEntry.txid,
            transactionBytes: splitEntry.transactionBytes,
            feeSatoshis: splitEntry.feeSatoshis,
            httpStatus: submittedSplit.httpStatus,
            response: submittedSplit.response,
        }
        writePrivate(UNSHIELD_SPLIT_RECEIPT_FILE, splitReceipt)
        if (!arcAccepted(submittedSplit, splitEntry.txid)) {
            throw new Error(`ARC did not accept unshield funding split: ${JSON.stringify(splitReceipt)}`)
        }
        waitForSeen(splitEntry.txid)
    }

    const beforeSubmit = liveHeight()
    if (beforeSubmit >= plan.lockHeight) {
        throw new Error(`Height advanced to ${beforeSubmit}; refusing a no-longer-early submission`)
    }
    const submitted = torPostTransaction(begin.rawHex, 'RECEIVED')
    const unsafe = arcAccepted(submitted, begin.txid)
    const receipt = {
        format: 'veil-v4-testnet-lock-unshield-early-rejection-v1',
        network: 'testnet',
        torOnly: true,
        submittedAt: new Date().toISOString(),
        txid: begin.txid,
        identicalMatureTxid: begin.txid,
        transactionBytes: begin.transactionBytes,
        feeSatoshis: begin.feeSatoshis,
        observedTip: beforeSubmit,
        requiredHeight: plan.lockHeight,
        nLockTime: beginTx.nLockTime,
        sourceLockedShieldFinalizerTxid: lockedShieldFinalizer.txid,
        sourceLockedShieldBlockHeight: mined.blockHeight,
        httpStatus: submitted.httpStatus,
        response: submitted.response,
        accepted: unsafe,
        expectedRejected: !unsafe,
    }
    writePrivate(EARLY_REJECTION_RECEIPT_FILE, receipt)
    if (unsafe) {
        throw new Error(`Expected-early unshield was unexpectedly accepted: ${JSON.stringify(receipt)}`)
    }
    console.log(JSON.stringify(receipt, null, 2))
    console.log('The exact unshield begin was rejected before maturity; no later unshield stage was submitted.')
}

function matureUnshieldReceiptFile(entry: { name: string }): string {
    return `${MATURE_UNSHIELD_RECEIPT_PREFIX}-${entry.name}-receipt.json`
}

function sendMatureUnshieldChain(plan: LockTestPlan): void {
    const begin = plan.lockedUnshield.stages[0]
    const finalizer = plan.lockedUnshield.stages.at(-1)
    const expectedBegin = process.argv
        .find((value) => value.startsWith('--expect-begin='))
        ?.slice('--expect-begin='.length)
        .toLowerCase()
    const expectedFinalizer = process.argv
        .find((value) => value.startsWith('--expect-finalizer='))
        ?.slice('--expect-finalizer='.length)
        .toLowerCase()
    if (
        !finalizer ||
        expectedBegin !== begin.txid.toLowerCase() ||
        expectedFinalizer !== finalizer.txid.toLowerCase()
    ) {
        throw new Error(
            'send-mature-unshield-chain requires exact --expect-begin and --expect-finalizer TXIDs'
        )
    }

    auditPlan(plan, livePolicy())
    const minedBegin = requireMinedStatus(begin.txid)
    if (minedBegin.blockHeight < plan.lockHeight) {
        throw new Error(
            `Unshield begin mined prematurely at ${minedBegin.blockHeight}; refusing descendants`
        )
    }
    const beginTx = new bsv.Transaction(begin.rawHex)
    if (beginTx.id !== begin.txid || beginTx.nLockTime !== plan.lockHeight) {
        throw new Error('Audited mature-unshield begin transaction or nLockTime changed')
    }

    const entries = plan.lockedUnshield.stages.slice(1).map((stage) => ({
        name: stage.name,
        txid: stage.txid,
        rawHex: stage.rawHex,
        transactionBytes: stage.transactionBytes,
        feeSatoshis: stage.feeSatoshis,
    }))
    if (entries.length !== 6 || entries.at(-1)?.txid !== finalizer.txid) {
        throw new Error('Mature-unshield descendant manifest is incomplete')
    }

    for (let index = 0; index < entries.length; index++) {
        const entry = entries[index]
        const file = matureUnshieldReceiptFile(entry)
        if (existsSync(file)) {
            const existing = JSON.parse(readFileSync(file, 'utf8')) as {
                beginTxid?: string
                finalizerTxid?: string
                manifestIndex?: number
                name?: string
                txid?: string
                httpStatus?: number
                response?: unknown
            }
            if (
                existing.beginTxid !== begin.txid ||
                existing.finalizerTxid !== finalizer.txid ||
                existing.manifestIndex !== index ||
                existing.name !== entry.name ||
                existing.txid !== entry.txid ||
                !arcAccepted({
                    httpStatus: existing.httpStatus ?? 0,
                    response: existing.response,
                }, entry.txid)
            ) throw new Error(`Existing mature-unshield ${entry.name} receipt is invalid`)
            waitForSeen(entry.txid)
            continue
        }

        const submitted = torPostTransaction(entry.rawHex, 'RECEIVED')
        const receipt = {
            format: 'veil-v4-testnet-lock-unshield-mature-chain-receipt-v1',
            network: 'testnet',
            torOnly: true,
            submittedAt: new Date().toISOString(),
            beginTxid: begin.txid,
            beginBlockHeight: minedBegin.blockHeight,
            requiredHeight: plan.lockHeight,
            finalizerTxid: finalizer.txid,
            manifestIndex: index,
            manifestLength: entries.length,
            name: entry.name,
            txid: entry.txid,
            transactionBytes: entry.transactionBytes,
            feeSatoshis: entry.feeSatoshis,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(file, receipt)
        if (!arcAccepted(submitted, entry.txid)) {
            throw new Error(
                `ARC did not accept mature-unshield ${entry.name}; chain stopped: ${JSON.stringify(receipt)}`
            )
        }
        console.log(JSON.stringify(receipt, null, 2))
        waitForSeen(entry.txid)
    }
    console.log('The six exact mature-unshield descendants were submitted parent-first through Tor.')
}

async function prepare(): Promise<void> {
    for (const file of [
        WALLET_FILE,
        SHIELD_SECRETS_FILE,
        TRANSFER_SIGNED_FILE,
        TRANSFER_SECRETS_FILE,
        TRANSFER_CONFIRMATION_FILE,
        WASM,
        ZKEY,
        VKEY,
    ]) if (!existsSync(file)) throw new Error(`Required height-lock input missing: ${file}`)
    if (existsSync(LOCK_PLAN_FILE) || existsSync(LOCK_SECRETS_FILE)) {
        throw new Error('A height-lock plan already exists; audit it instead of replacing it')
    }
    loadArtifacts()
    const policy = livePolicy()
    const tip = liveHeight()
    const lockHeight = tip + LOCK_DELAY_BLOCKS
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (key.toAddress(bsv.Networks.testnet).toString() !== wallet.address) {
        throw new Error('Invalid testnet deployment wallet')
    }
    const transfer = JSON.parse(readFileSync(TRANSFER_SIGNED_FILE, 'utf8')) as ExistingTransfer
    const transferFinalizer = transfer.stages.at(-1)
    if (!transferFinalizer || transferFinalizer.name !== 'finalize') {
        throw new Error('Private transfer has no finalizer')
    }
    const confirmation = JSON.parse(
        readFileSync(TRANSFER_CONFIRMATION_FILE, 'utf8')
    ) as {
        finalizerTxid: string
        txStatus: string
        blockHeight: number
        blockHash: string
        merklePath: string
    }
    const mined = requireMinedStatus(transferFinalizer.txid)
    if (
        confirmation.finalizerTxid !== mined.txid ||
        confirmation.txStatus !== 'MINED' ||
        confirmation.blockHeight !== mined.blockHeight ||
        confirmation.blockHash !== mined.blockHash ||
        confirmation.merklePath !== mined.merklePath
    ) throw new Error('Transfer confirmation does not match live mined evidence')
    const sourceTx = new bsv.Transaction(transferFinalizer.rawHex)
    if (
        sourceTx.id !== transferFinalizer.txid ||
        sourceTx.outputs[0].satoshis !== transfer.poolOutputSatoshis
    ) throw new Error('Mined transfer finalizer bytes changed')

    const shieldSecrets = JSON.parse(
        readFileSync(SHIELD_SECRETS_FILE, 'utf8')
    ) as { note: unknown }
    const transferSecrets = JSON.parse(
        readFileSync(TRANSFER_SECRETS_FILE, 'utf8')
    ) as { receiverNote: unknown; senderChangeNote: unknown }
    const shieldNote = parseSavedNote(shieldSecrets.note)
    const receiverNote = parseSavedNote(transferSecrets.receiverNote)
    const senderChangeNote = parseSavedNote(transferSecrets.senderChangeNote)
    const state = new PoolState(await createHash())
    for (const note of [shieldNote, receiverNote, senderChangeNote]) {
        state.noteTree.set(note.index, note.commitment)
    }
    state.nullifierTree.set(shieldNote.index, BigInt(transfer.nullifier))
    state.nextIndex = Number(transfer.nextState.nextNoteIndex)
    if (
        state.noteTree.root().toString() !== transfer.nextState.noteRoot ||
        state.nullifierTree.root().toString() !== transfer.nextState.nullifierRoot ||
        state.nextIndex.toString() !== transfer.nextState.nextNoteIndex
    ) throw new Error('Private notes do not reconstruct the mined transfer state')

    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const lockOwnerKey = randomField()
    const lockRho = randomField()
    const lockedShieldBuilt = state.build({
        mode: 0,
        publicIn: LOCKED_SATS,
        outputs: [{
            amount: LOCKED_SATS,
            ownerKey: lockOwnerKey,
            rho: lockRho,
            lockHeight: BigInt(lockHeight),
        }],
    })
    const lockedNote = lockedShieldBuilt.outputNotes[0]
    const lockedShieldProof = await prove(lockedShieldBuilt, vk)
    const sourcePool = ShieldedPoolV4.fromTx(sourceTx, 0)
    const transferSplitTx = new bsv.Transaction(transfer.split.rawHex)
    const lockedShieldSplit = buildSplit(
        transferSplitTx,
        transfer.split.changeOutputIndex,
        LOCK_SHIELD_SPONSORS,
        wallet,
        key,
        policy
    )
    const lockedShieldPlan = buildPipeline(
        'locked-shield',
        sourceTx,
        sourcePool,
        lockedShieldBuilt,
        lockedShieldProof.proof,
        lockedShieldProof.witness,
        lockedShieldProof.transition,
        vk,
        lockedShieldSplit,
        LOCK_SHIELD_SPONSORS,
        tip,
        tip + ABORT_DELAY_BLOCKS,
        wallet,
        key,
        policy
    )

    let earlyError = ''
    try {
        state.build({
            mode: 2,
            spend: { note: lockedNote },
            currentHeight: BigInt(lockHeight - 1),
            publicOut: LOCKED_SATS,
            recipient: recipientField(wallet.address),
            outputs: [],
        })
    } catch (error) {
        earlyError = error instanceof Error ? error.message : String(error)
    }
    if (!earlyError.includes(`locked until block ${lockHeight}`)) {
        throw new Error(`Early unshield was not rejected locally: ${earlyError}`)
    }
    const lockedUnshieldBuilt = state.build({
        mode: 2,
        spend: { note: lockedNote },
        currentHeight: BigInt(lockHeight),
        publicOut: LOCKED_SATS,
        recipient: recipientField(wallet.address),
        outputs: [],
    })
    const lockedUnshieldProof = await prove(lockedUnshieldBuilt, vk)
    const lockedShieldFinalizerTx = new bsv.Transaction(
        lockedShieldPlan.stages.at(-1)!.rawHex
    )
    const lockedShieldPool = ShieldedPoolV4.fromTx(lockedShieldFinalizerTx, 0)
    const lockedShieldSplitTx = new bsv.Transaction(lockedShieldPlan.split.rawHex)
    const lockedUnshieldSplit = buildSplit(
        lockedShieldSplitTx,
        lockedShieldPlan.split.changeOutputIndex,
        UNSHIELD_SPONSORS,
        wallet,
        key,
        policy
    )
    const lockedUnshieldPlan = buildPipeline(
        'locked-unshield',
        lockedShieldFinalizerTx,
        lockedShieldPool,
        lockedUnshieldBuilt,
        lockedUnshieldProof.proof,
        lockedUnshieldProof.witness,
        lockedUnshieldProof.transition,
        vk,
        lockedUnshieldSplit,
        UNSHIELD_SPONSORS,
        lockHeight,
        lockHeight + ABORT_DELAY_BLOCKS,
        wallet,
        key,
        policy
    )
    const plan: LockTestPlan = {
        format: 'veil-v4-testnet-height-lock-plan-v1',
        network: 'testnet',
        broadcast: false,
        createdAt: new Date().toISOString(),
        sourceTransferFinalizerTxid: transferFinalizer.txid,
        sourceTransferBlockHeight: mined.blockHeight,
        lockHeight,
        lockDelayBlocks: LOCK_DELAY_BLOCKS,
        lockedSatoshis: Number(LOCKED_SATS),
        livePolicy: policy,
        lockedShield: lockedShieldPlan,
        lockedUnshield: lockedUnshieldPlan,
        negativeTests: {
            localEarlyUnshieldRejected: true,
            localEarlyUnshieldError: earlyError,
            networkEarlyRejectionPending: true,
            matureTransactionUsesIdenticalTxid: true,
        },
    }
    const audited = auditPlan(plan, policy)
    writePrivate(LOCK_SECRETS_FILE, {
        createdAt: plan.createdAt,
        lockedNote,
        lockOwnerKey,
        lockRho,
    })
    writePrivate(LOCK_PLAN_FILE, plan)
    console.log(JSON.stringify(jsonSafe(audited), null, 2))
    console.log('Height-lock shield and identical early/mature unshield are signed locally; nothing was broadcast.')
}

async function main(): Promise<void> {
    const command = process.argv[2]
    if (![
        'prepare',
        'audit',
        'recover-locked-shield-entry',
        'send-locked-shield-chain',
        'send-early-unshield',
        'send-mature-unshield-chain',
    ].includes(command)) {
        throw new Error('Usage: testnet-v4-lock-test.ts prepare|audit|recover-locked-shield-entry|send-locked-shield-chain|send-early-unshield|send-mature-unshield-chain')
    }
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    if (command === 'prepare') {
        await prepare()
        return
    }
    if (!existsSync(LOCK_PLAN_FILE)) throw new Error('No prepared height-lock plan exists')
    loadArtifacts()
    const plan = JSON.parse(readFileSync(LOCK_PLAN_FILE, 'utf8')) as LockTestPlan
    if (command === 'recover-locked-shield-entry') {
        recoverLockedShieldEntry(plan)
        return
    }
    if (command === 'send-locked-shield-chain') {
        sendLockedShieldChain(plan)
        return
    }
    if (command === 'send-early-unshield') {
        sendEarlyUnshield(plan)
        return
    }
    if (command === 'send-mature-unshield-chain') {
        sendMatureUnshieldChain(plan)
        return
    }
    console.log(JSON.stringify(jsonSafe(auditPlan(plan, livePolicy())), null, 2))
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
})
