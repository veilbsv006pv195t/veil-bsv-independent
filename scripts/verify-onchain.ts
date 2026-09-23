import { readFile } from 'node:fs/promises'
import path from 'node:path'
import {
    bsv,
    int2ByteString,
    PubKeyHash,
    Utils,
} from 'scrypt-ts'
import { groth16 } from 'snarkjs'
import { BN256 } from 'scrypt-ts-lib/dist/ec/bn256'
import { PoolState, createHash } from '../src/crypto'
import { ShieldedPool } from '../src/contracts/shieldedPool'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')
const SCRIPT_NUMBER_POLICY_BYTES = 10_000

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

async function main(): Promise<void> {
    const hash = await createHash()
    const state = new PoolState(hash)
    const sender = 101n
    const receiver = 202n
    const recipientField = 0x00112233445566778899aabbccddeeff00112233n

    const shield = state.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: sender, rho: 10_001n }],
    })
    const transfer = state.build({
        mode: 1,
        spend: { note: shield.outputNotes[0] },
        currentHeight: 899_900n,
        outputs: [
            { amount: 600n, ownerKey: receiver, rho: 20_001n, lockHeight: 900_000n },
            { amount: 400n, ownerKey: sender, rho: 20_002n },
        ],
    })
    const transition = state.build({
        mode: 2,
        spend: { note: transfer.outputNotes[0] },
        currentHeight: 900_000n,
        publicOut: 500n,
        recipient: recipientField,
        outputs: [{ amount: 100n, ownerKey: receiver, rho: 30_001n }],
    })

    const jsonVkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey
    const { proof } = await groth16.fullProve(transition.circuitInput, WASM, ZKEY)
    const vk = toPreparedVerifyingKey(jsonVkey)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const residueWitness = buildPairingResidueWitness(
        transition.statement,
        scryptProof,
        vk
    )

    ShieldedPool.loadArtifact()
    const current = new ShieldedPool(
        transition.public.oldNoteRoot,
        transition.public.oldNullifierRoot,
        transition.public.oldNextIndex,
        vk
    )
    const next = current.next()
    next.noteRoot = transition.public.newNoteRoot
    next.nullifierRoot = transition.public.newNullifierRoot
    next.nextIndex = transition.public.newNextIndex

    const recipientPkh = PubKeyHash(int2ByteString(recipientField, 20n))
    const sourceOutput = new bsv.Transaction.Output({
        script: current.lockingScript,
        satoshis: 1_001,
    })
    const tx = new bsv.Transaction()
    tx.addInput(
        new bsv.Transaction.Input({
            prevTxId: Buffer.alloc(32),
            outputIndex: 0,
            script: bsv.Script.empty(),
            output: sourceOutput,
        })
    )
    tx.addOutput(
        new bsv.Transaction.Output({ script: next.lockingScript, satoshis: 501 })
    )
    tx.lockUntilBlockHeight(Number(transition.public.currentHeight))
    tx.addOutput(
        new bsv.Transaction.Output({
            script: bsv.Script.fromHex(
                Utils.buildPublicKeyHashOutput(recipientPkh, 500n)
                    .slice(18) // strip the serialized amount + script length
            ),
            satoshis: 500,
        })
    )
    // Tell scrypt-ts which script would receive change. Inputs and explicit
    // outputs balance exactly, so no change output is actually appended.
    tx.change(
        bsv.Address.fromPublicKeyHash(Buffer.alloc(20), bsv.Networks.testnet)
    )

    current.to = { tx, inputIndex: 0 }
    const validUnlocking = current.getUnlockingScript((self) => {
        self.transit(
            scryptProof,
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
            recipientPkh
        )
    })
    if (validUnlocking instanceof Promise) {
        throw new Error('unexpected asynchronous verifier')
    }
    tx.inputs[0].setScript(validUnlocking)
    const started = performance.now()
    const numberPolicy = installScriptNumberPolicyMonitor(
        SCRIPT_NUMBER_POLICY_BYTES
    )
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const validInterpreter = new bsv.Script.Interpreter()
    let lastStep: { opcode?: number; pc?: number } = {}
    validInterpreter.stepListener = (step) => {
        lastStep = {
            opcode: step.opcode?.toNumber(),
            pc: step.pc,
        }
    }
    let validAccepted = false
    try {
        validAccepted = validInterpreter.verify(
            validUnlocking,
            current.lockingScript,
            tx,
            0,
            bsv.Script.Interpreter.DEFAULT_FLAGS,
            new bsv.crypto.BN(1_001)
        )
    } finally {
        numberPolicy.restore()
    }
    if (!validAccepted) {
        const pc = lastStep.pc ?? 0
        const context = current.lockingScript.chunks
            .slice(Math.max(0, pc - 4), pc + 5)
            .map((chunk, offset) => ({
                index: Math.max(0, pc - 4) + offset,
                opcode: new bsv.Opcode(chunk.opcodenum).toString(),
                pushedBytes: chunk.buf?.length ?? 0,
            }))
        throw new Error(
            `${validInterpreter.errstr}; maximum Script number observed ` +
            `${numberPolicy.maximumBytes()} bytes; last step ${JSON.stringify(lastStep)}; ` +
            `context ${JSON.stringify(context)}`
        )
    }
    console.log(
        `✓ Bitcoin Script accepted the unshield proof (${((performance.now() - started) / 1000).toFixed(2)}s)`
    )
    console.log(
        `✓ maximum Script number ${numberPolicy.maximumBytes().toLocaleString()} bytes ` +
        `(policy ${SCRIPT_NUMBER_POLICY_BYTES.toLocaleString()} bytes)`
    )

    const zeroWitnessCurrent = new ShieldedPool(
        transition.public.oldNoteRoot,
        transition.public.oldNullifierRoot,
        transition.public.oldNextIndex,
        vk
    )
    zeroWitnessCurrent.to = { tx, inputIndex: 0 }
    let zeroWitnessAccepted = false
    try {
        const zeroWitnessResult = zeroWitnessCurrent.verify((self) => {
            self.transit(
                scryptProof,
                {
                    residue: BN256.FQ12Zero,
                    residueInverse: BN256.FQ12Zero,
                    scale: 0n,
                },
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
                recipientPkh
            )
        })
        if (zeroWitnessResult instanceof Promise) {
            throw new Error('unexpected asynchronous verifier')
        }
        zeroWitnessAccepted = zeroWitnessResult.success
    } catch (error) {
        if (!(error instanceof Error) || !error.message.includes('invalid Groth16 proof')) {
            throw error
        }
    }
    if (zeroWitnessAccepted) {
        throw new Error('Bitcoin Script accepted an all-zero residue witness')
    }
    console.log('✓ Bitcoin Script rejected an all-zero residue witness')

    tx.lockUntilBlockHeight(Number(transition.public.currentHeight - 1n))
    const prematureCurrent = new ShieldedPool(
        transition.public.oldNoteRoot,
        transition.public.oldNullifierRoot,
        transition.public.oldNextIndex,
        vk
    )
    prematureCurrent.to = { tx, inputIndex: 0 }
    let prematureAccepted = false
    try {
        const prematureResult = prematureCurrent.verify((self) => {
            self.transit(
                scryptProof,
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
                recipientPkh
            )
        })
        if (prematureResult instanceof Promise) {
            throw new Error('unexpected asynchronous verifier')
        }
        prematureAccepted = prematureResult.success
    } catch (error) {
        if (!(error instanceof Error) || !error.message.includes('height-locked')) {
            throw error
        }
    }
    if (prematureAccepted) {
        throw new Error('Bitcoin Script accepted the note before its unlock height')
    }
    console.log('✓ Bitcoin Script rejected the note one block before unlock')
    tx.lockUntilBlockHeight(Number(transition.public.currentHeight))

    const tamperedCurrent = new ShieldedPool(
        transition.public.oldNoteRoot,
        transition.public.oldNullifierRoot,
        transition.public.oldNextIndex,
        vk
    )
    tamperedCurrent.to = { tx, inputIndex: 0 }
    const tamperSourceUnlocking = tamperedCurrent.getUnlockingScript((self) => {
        self.transit(
            scryptProof,
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
            recipientPkh
        )
    })
    if (tamperSourceUnlocking instanceof Promise) throw new Error('unexpected asynchronous builder')

    // Flip a byte inside proof.c.x after serialization, without changing the
    // rest of the unlocking call, then execute that script in the same VM.
    const encodedCx = bsv.crypto.BN.fromString(scryptProof.c.x.toString(), 10).toSM({
        endian: 'little',
    })
    const unlockingHex = tamperSourceUnlocking.toHex()
    const encodedHex = encodedCx.toString('hex')
    const proofOffset = unlockingHex.indexOf(encodedHex)
    if (proofOffset < 0) throw new Error('could not locate proof coordinate in unlocking script')
    const originalByte = Number.parseInt(unlockingHex.slice(proofOffset, proofOffset + 2), 16)
    const replacementByte = (originalByte ^ 1).toString(16).padStart(2, '0')
    const tamperedUnlocking = bsv.Script.fromHex(
        unlockingHex.slice(0, proofOffset) +
            replacementByte +
            unlockingHex.slice(proofOffset + 2)
    )
    bsv.Script.Interpreter.MAX_SCRIPT_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    bsv.Script.Interpreter.MAXIMUM_ELEMENT_SIZE = Number.MAX_SAFE_INTEGER
    const interpreter = new bsv.Script.Interpreter()
    const tamperedAccepted = interpreter.verify(
        tamperedUnlocking,
        tamperedCurrent.lockingScript,
        tx,
        0,
        bsv.Script.Interpreter.DEFAULT_FLAGS,
        new bsv.crypto.BN(1_001)
    )
    if (tamperedAccepted) throw new Error('Bitcoin Script accepted a tampered proof')
    console.log('✓ Bitcoin Script rejected a tampered proof')
    console.log(`  locking script: ${current.scriptSize.toLocaleString()} bytes`)
    console.log(`  transaction: ${tx.toString().length / 2} bytes including unlocking proof`)
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error)
        process.exit(1)
    }
)
