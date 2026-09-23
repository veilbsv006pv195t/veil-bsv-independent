import { readFile } from 'node:fs/promises'
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
import {
    BN256,
    BN256Pairing,
    LineFuncRes,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { PoolState, createHash } from '../src/crypto'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'
import { ShieldedPoolV4 } from '../src/v4/shieldedPoolV4'
import { StagedGroth16 } from '../src/v4/stagedGroth16'
import { V4MillerState, V4PreparationState, V4State, V4Transition } from '../src/v4/v4State'
import { VeilV4Finalizer } from '../src/v4/veilV4Finalizer'
import { VeilV4Miller0 } from '../src/v4/veilV4Miller0'
import { VeilV4Miller1 } from '../src/v4/veilV4Miller1'
import { VeilV4Miller2 } from '../src/v4/veilV4Miller2'
import { VeilV4Miller3 } from '../src/v4/veilV4Miller3'
import { VeilV4Preparation } from '../src/v4/veilV4Preparation'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')
const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))
const DIGITS = [
    1, 0, 1, 0, 0, -1, 0, 1, 1, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1,
    1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 1, 1, 0,
    0, 1, 0, 0, -1, 1, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0,
] as const

function installScriptNumberPolicyMonitor(limit: number) {
    const BNClass = bsv.crypto.BN as unknown as {
        fromScriptNumBuffer(buffer: Buffer, requireMinimal?: boolean, size?: number): bsv.crypto.BN
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
    return { restore: () => (BNClass.fromScriptNumBuffer = original), maximumBytes: () => maximumBytes }
}

function runSlice(
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

function makeTx(
    current: { lockingScript: bsv.Script },
    sourceValue: number,
    nextScript: bsv.Script,
    nextValue: number,
    lockHeight?: number,
    extraInputValue = 0
): bsv.Transaction {
    const tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: Buffer.alloc(32),
        outputIndex: 0,
        script: bsv.Script.empty(),
        output: new bsv.Transaction.Output({ script: current.lockingScript, satoshis: sourceValue }),
    }))
    if (extraInputValue > 0) {
        tx.addInput(new bsv.Transaction.Input({
            prevTxId: Buffer.alloc(32, 1),
            outputIndex: 0,
            script: bsv.Script.empty(),
            output: new bsv.Transaction.Output({
                script: bsv.Script.buildPublicKeyHashOut(
                    bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet)
                ),
                satoshis: extraInputValue,
            }),
        }))
    }
    tx.addOutput(new bsv.Transaction.Output({ script: nextScript, satoshis: nextValue }))
    if (lockHeight !== undefined) tx.lockUntilBlockHeight(lockHeight)
    return tx
}

function execute(
    name: string,
    current: any,
    tx: bsv.Transaction,
    sourceValue: number,
    unlock: (self: any) => void
): {
    seconds: number
    maximumScriptNumber: number
    unlockingBytes: number
    transactionBytes: number
} {
    current.to = { tx, inputIndex: 0 }
    const unlocking = current.getUnlockingScript(unlock)
    if (unlocking instanceof Promise) throw new Error(`unexpected async ${name} builder`)
    const unlockingBytes = unlocking.toBuffer().length
    if (unlockingBytes > 500_000) {
        throw new Error(`${name}: unlocking script ${unlockingBytes} exceeds 500,000 bytes`)
    }
    tx.inputs[0].setScript(unlocking)
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const monitor = installScriptNumberPolicyMonitor(10_000)
    const interpreter = new bsv.Script.Interpreter()
    const started = performance.now()
    let accepted = false
    try {
        accepted = interpreter.verify(
            unlocking,
            current.lockingScript,
            tx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(sourceValue)
        )
    } finally {
        monitor.restore()
    }
    if (!accepted) throw new Error(`${name}: ${interpreter.errstr}`)
    return {
        seconds: (performance.now() - started) / 1000,
        maximumScriptNumber: monitor.maximumBytes(),
        unlockingBytes,
        transactionBytes: tx.toString().length / 2,
    }
}

function expectReject(name: string, action: () => unknown, expected: string): void {
    let message = ''
    try {
        action()
    } catch (error) {
        message = error instanceof Error ? error.message : String(error)
    }
    if (!message.includes(expected)) {
        throw new Error(
            `${name}: expected rejection containing "${expected}", received "${message}"`
        )
    }
    console.log(`✓ ${name} rejected: ${expected}`)
}

async function main(): Promise<void> {
    ShieldedPoolV4.loadArtifact('artifacts/src/v4/shieldedPoolV4.json')
    VeilV4Preparation.loadArtifact('artifacts/src/v4/veilV4Preparation.json')
    VeilV4Miller0.loadArtifact('artifacts/src/v4/veilV4Miller0.json')
    VeilV4Miller1.loadArtifact('artifacts/src/v4/veilV4Miller1.json')
    VeilV4Miller2.loadArtifact('artifacts/src/v4/veilV4Miller2.json')
    VeilV4Miller3.loadArtifact('artifacts/src/v4/veilV4Miller3.json')
    VeilV4Finalizer.loadArtifact('artifacts/src/v4/veilV4Finalizer.json')

    const publicState = new PoolState(await createHash())
    const built = publicState.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: 101n, rho: 10_001n }],
    })
    const jsonVkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const { proof } = await groth16.fullProve(built.circuitInput, WASM, ZKEY)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const witness = buildPairingResidueWitness(built.statement, scryptProof, vk)
    const recipientPkh = PubKeyHash(int2ByteString(built.public.recipient, 20n))
    const transition: V4Transition = {
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
        recipientPkh,
    }

    const finalTemplate = new VeilV4Finalizer(
        ZERO_HASH, vk.millerb1a1, vk.root27, vk.root27Squared,
        vk.gammaLines[89], vk.deltaLines[89], vk.gammaLines[90], vk.deltaLines[90]
    )
    const s3Template = new VeilV4Miller3(
        ZERO_HASH, hash256(finalTemplate.codePart),
        vk.gammaLines.slice(67, 89) as never, vk.deltaLines.slice(67, 89) as never
    )
    const s2Template = new VeilV4Miller2(
        ZERO_HASH, hash256(s3Template.codePart),
        vk.gammaLines.slice(44, 67) as never, vk.deltaLines.slice(44, 67) as never
    )
    const s1Template = new VeilV4Miller1(
        ZERO_HASH, hash256(s2Template.codePart),
        vk.gammaLines.slice(23, 44) as never, vk.deltaLines.slice(23, 44) as never
    )
    const s0Template = new VeilV4Miller0(
        ZERO_HASH, hash256(s1Template.codePart),
        vk.gammaLines.slice(0, 23) as never, vk.deltaLines.slice(0, 23) as never
    )
    const prepTemplate = new VeilV4Preparation(
        ZERO_HASH, hash256(s0Template.codePart), vk.gammaAbc[0], vk.gammaAbc[1]
    )
    const pool = new ShieldedPoolV4(
        transition.oldNoteRoot,
        transition.oldNullifierRoot,
        transition.oldNextIndex,
        hash256(prepTemplate.codePart)
    )
    const startHeight = 900_000n
    const abortHeight = startHeight + 12n
    const preparationState: V4PreparationState = {
        signal: built.statement,
        proof: scryptProof,
        residue: witness.residue,
        residueInverse: witness.residueInverse,
        scale: witness.scale,
        context: {
            transitionHash: V4State.hashTransition(transition),
            poolCodeHash: hash256(pool.codePart),
            lockedValue: 1_001n,
            abortHeight,
        },
    }
    const prep = prepTemplate
    prep.stateHash = V4State.hashPreparation(preparationState)
    const beginTx = makeTx(pool, 1, prep.lockingScript, 1_001, Number(startHeight), 1_000)
    beginTx.change(bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet))
    const results: Array<{
        name: string
        seconds: number
        maximumScriptNumber: number
        unlockingBytes: number
        transactionBytes: number
    }> = []
    results.push({ name: 'begin', ...execute('begin', pool, beginTx, 1, (self) => self.begin(
        scryptProof, witness, transition, startHeight, abortHeight, prep.codePart, pool.codePart
    )) })

    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(scryptProof.b))
    const negA = { x: scryptProof.a.x, y: -scryptProof.a.y }
    const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
    const scaled = StagedGroth16.mulG1PointBounded(vk.gammaAbc[1], built.statement)
    const p1 = BN256.makeAffineCurvePoint(
        BN256.createCurvePoint(BN256.addG1Points(vk.gammaAbc[0], scaled))
    )
    const p2 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(scryptProof.c))
    let millerState: V4MillerState = {
        q, p0, p1, p2, r: q, acc: witness.residueInverse,
        residue: witness.residue, residueInverse: witness.residueInverse,
        scale: witness.scale, context: preparationState.context,
    }
    const stage0 = s0Template
    stage0.stateHash = V4State.hashMiller(millerState)
    const prepTx = makeTx(prep, 1_001, stage0.lockingScript, 1_001)
    results.push({ name: 'prepare', ...execute('prepare', prep, prepTx, 1_001, (self) =>
        self.prepare(preparationState, stage0.codePart)
    ) })

    const stageTemplates = [s0Template, s1Template, s2Template, s3Template]
    const starts = [0, 23, 44, 67]
    let current: any = stage0
    for (let stage = 0; stage < 4; stage++) {
        const inputState = millerState
        millerState = runSlice(inputState, vk, stage * 16, starts[stage])
        const next = stage === 3 ? finalTemplate : stageTemplates[stage + 1]
        next.stateHash = V4State.hashMiller(millerState)
        const tx = makeTx(current, 1_001, next.lockingScript, 1_001)
        results.push({ name: `miller-${stage}`, ...execute(`miller-${stage}`, current, tx, 1_001, (self) =>
            self.advance(inputState, next.codePart)
        ) })
        current = next
    }

    const nextPool = pool.next()
    nextPool.noteRoot = transition.newNoteRoot
    nextPool.nullifierRoot = transition.newNullifierRoot
    nextPool.nextIndex = transition.newNextIndex
    const finalTx = makeTx(current, 1_001, nextPool.lockingScript, 1_001)
    finalTx.change(bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet))
    results.push({ name: 'finalize', ...execute('finalize', current, finalTx, 1_001, (self) =>
        self.finalize(millerState, transition, pool.codePart)
    ) })

    const wrongCodeTx = makeTx(prep, 1_001, s1Template.lockingScript, 1_001)
    expectReject('substituted successor code', () => {
        prep.to = { tx: wrongCodeTx, inputIndex: 0 }
        prep.getUnlockingScript((self) =>
            self.prepare(preparationState, s1Template.codePart)
        )
    }, 'wrong Miller stage code')

    const tamperedPreparation: V4PreparationState = {
        ...preparationState,
        signal: preparationState.signal + 1n,
    }
    const tamperedStateTx = makeTx(prep, 1_001, stage0.lockingScript, 1_001)
    expectReject('altered committed preparation state', () => {
        prep.to = { tx: tamperedStateTx, inputIndex: 0 }
        prep.getUnlockingScript((self) =>
            self.prepare(tamperedPreparation, stage0.codePart)
        )
    }, 'wrong preparation state')

    const invalidFinalState: V4MillerState = {
        ...millerState,
        residue: BN256.FQ12Zero,
        residueInverse: BN256.FQ12Zero,
    }
    finalTemplate.stateHash = V4State.hashMiller(invalidFinalState)
    const invalidFinalTx = makeTx(
        finalTemplate,
        1_001,
        nextPool.lockingScript,
        1_001
    )
    invalidFinalTx.change(
        bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet)
    )
    expectReject('all-zero residue witness', () => {
        finalTemplate.to = { tx: invalidFinalTx, inputIndex: 0 }
        finalTemplate.getUnlockingScript((self) =>
            self.finalize(invalidFinalState, transition, pool.codePart)
        )
    }, 'invalid residue inverse')

    const initialMillerState: V4MillerState = {
        q,
        p0,
        p1,
        p2,
        r: q,
        acc: witness.residueInverse,
        residue: witness.residue,
        residueInverse: witness.residueInverse,
        scale: witness.scale,
        context: preparationState.context,
    }
    stage0.stateHash = V4State.hashMiller(initialMillerState)
    const recoveredPool = pool.next()
    const prematureAbortTx = makeTx(
        stage0,
        1_001,
        recoveredPool.lockingScript,
        1_001,
        Number(abortHeight - 1n)
    )
    prematureAbortTx.change(
        bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet)
    )
    expectReject('premature timeout recovery', () => {
        stage0.to = { tx: prematureAbortTx, inputIndex: 0 }
        stage0.getUnlockingScript((self) =>
            self.abort(initialMillerState, transition, pool.codePart)
        )
    }, 'verification timeout not reached')

    const abortTx = makeTx(
        stage0,
        1_001,
        recoveredPool.lockingScript,
        1_001,
        Number(abortHeight)
    )
    abortTx.change(
        bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet)
    )
    results.push({
        name: 'abort',
        ...execute('abort', stage0, abortTx, 1_001, (self) =>
            self.abort(initialMillerState, transition, pool.codePart)
        ),
    })
    console.log('✓ timeout recovery restored the prior pool state at the committed height')

    console.log('✓ complete v4 shield pipeline accepted by Bitcoin Script')
    for (const result of results) {
        console.log(
            `  ${result.name.padEnd(10)} ${result.seconds.toFixed(3)}s, ` +
            `unlock ${result.unlockingBytes.toLocaleString()} B, ` +
            `tx ${result.transactionBytes.toLocaleString()} B, ` +
            `max Script number ${result.maximumScriptNumber.toLocaleString()} B`
        )
    }
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error)
        process.exit(1)
    }
)
