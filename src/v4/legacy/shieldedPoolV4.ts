// Frozen pre-uint160-fix contract, used only to reproduce historical deployment evidence.
import {
    assert,
    byteString2Int,
    ByteString,
    hash256,
    int2ByteString,
    method,
    prop,
    Sha256,
    sha256,
    slice,
    SmartContract,
    toByteString,
    Utils,
} from 'scrypt-ts'
import { Proof } from 'scrypt-ts-lib/dist/zk/g16bn256'
import { PairingResidueWitness } from '../../optimizedGroth16'
import {
    V4PreparationState,
    V4State,
    V4Transition,
} from '../v4State'

const STATEMENT_DOMAIN = 1447381314n
const MAX_ABORT_DELAY = 144n

/**
 * Small public pool covenant for optimized-v4.
 *
 * `begin` escrows the unchanged pool state into the authenticated verifier
 * pipeline.  The finalizer can apply only the committed transition after a
 * valid proof; every pipeline stage also has a bounded timeout recovery path.
 */
export class ShieldedPoolV4 extends SmartContract {
    @prop(true)
    noteRoot: bigint

    @prop(true)
    nullifierRoot: bigint

    @prop(true)
    nextIndex: bigint

    @prop()
    readonly preparationCodeHash: Sha256

    constructor(
        noteRoot: bigint,
        nullifierRoot: bigint,
        nextIndex: bigint,
        preparationCodeHash: Sha256
    ) {
        super(...arguments)
        this.noteRoot = noteRoot
        this.nullifierRoot = nullifierRoot
        this.nextIndex = nextIndex
        this.preparationCodeHash = preparationCodeHash
    }

    @method()
    public begin(
        proof: Proof,
        residueWitness: PairingResidueWitness,
        transition: V4Transition,
        startHeight: bigint,
        abortHeight: bigint,
        preparationCodePart: ByteString,
        poolCodePart: ByteString
    ) {
        assert(transition.oldNoteRoot == this.noteRoot, 'wrong old note root')
        assert(
            transition.oldNullifierRoot == this.nullifierRoot,
            'wrong old nullifier root'
        )
        assert(transition.oldNextIndex == this.nextIndex, 'wrong old note index')
        assert(transition.publicIn >= 0n && transition.publicOut >= 0n, 'negative public value')
        assert(startHeight < 500000000n, 'start lock must be a block height')
        assert(abortHeight > startHeight, 'abort height must follow start')
        assert(abortHeight <= startHeight + MAX_ABORT_DELAY, 'abort delay too long')
        assert(this.timeLock(startHeight), 'verification start height not reached')
        if (transition.mode > 0n) {
            assert(
                transition.currentHeight < 500000000n,
                'note lock must use a block height'
            )
            assert(
                this.timeLock(transition.currentHeight),
                'input note is still height-locked'
            )
        }
        assert(hash256(preparationCodePart) == this.preparationCodeHash, 'wrong preparation code')
        assert(
            V4State.poolStateScript(
                poolCodePart,
                this.noteRoot,
                this.nullifierRoot,
                this.nextIndex
            ) == this.getStateScript(),
            'wrong pool code'
        )

        let statementBytes = int2ByteString(STATEMENT_DOMAIN, 4n)
        statementBytes += int2ByteString(transition.mode, 1n)
        statementBytes += int2ByteString(transition.outCount, 1n)
        statementBytes += int2ByteString(this.noteRoot, 32n)
        statementBytes += int2ByteString(transition.newNoteRoot, 32n)
        statementBytes += int2ByteString(this.nullifierRoot, 32n)
        statementBytes += int2ByteString(transition.newNullifierRoot, 32n)
        statementBytes += int2ByteString(this.nextIndex, 1n)
        statementBytes += int2ByteString(transition.newNextIndex, 1n)
        statementBytes += int2ByteString(transition.nullifier, 32n)
        statementBytes += int2ByteString(transition.outputCommitment0, 32n)
        statementBytes += int2ByteString(transition.outputCommitment1, 32n)
        statementBytes += int2ByteString(transition.publicIn, 8n)
        statementBytes += int2ByteString(transition.publicOut, 8n)
        statementBytes += int2ByteString(transition.recipientField, 20n)
        statementBytes += int2ByteString(transition.currentHeight, 4n)
        const digest = sha256(statementBytes)
        const signal = byteString2Int(
            slice(digest, 0n, 31n) + toByteString('00')
        )

        const lockedValue = this.ctx.utxo.value + transition.publicIn
        assert(lockedValue >= 1n, 'pool anchor must remain')
        const preparation: V4PreparationState = {
            signal,
            proof,
            residue: residueWitness.residue,
            residueInverse: residueWitness.residueInverse,
            scale: residueWitness.scale,
            context: {
                transitionHash: V4State.hashTransition(transition),
                poolCodeHash: hash256(poolCodePart),
                lockedValue,
                abortHeight,
            },
        }
        const preparationScript = V4State.stateScript(
            preparationCodePart,
            V4State.hashPreparation(preparation)
        )
        const outputs =
            Utils.buildOutput(preparationScript, lockedValue) +
            this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected begin outputs')
    }
}
