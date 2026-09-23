import {
    assert,
    ByteString,
    hash256,
    int2ByteString,
    method,
    prop,
    Sha256,
    SmartContract,
    Utils,
} from 'scrypt-ts'
import { BN256, FQ12 } from 'scrypt-ts-lib/dist/ec/bn256'
import { PreparedLine, StagedGroth16 } from './stagedGroth16'
import {
    V4MillerState,
    V4State,
    V4Transition,
} from './v4State'

/** Completes the pairing check and releases only the proof-bound pool state. */
export class VeilV4Finalizer extends SmartContract {
    @prop(true)
    stateHash: Sha256

    @prop()
    readonly millerb1a1: FQ12

    @prop()
    readonly root27: FQ12

    @prop()
    readonly root27Squared: FQ12

    @prop()
    readonly finalGamma0: PreparedLine

    @prop()
    readonly finalDelta0: PreparedLine

    @prop()
    readonly finalGamma1: PreparedLine

    @prop()
    readonly finalDelta1: PreparedLine

    constructor(
        stateHash: Sha256,
        millerb1a1: FQ12,
        root27: FQ12,
        root27Squared: FQ12,
        finalGamma0: PreparedLine,
        finalDelta0: PreparedLine,
        finalGamma1: PreparedLine,
        finalDelta1: PreparedLine
    ) {
        super(...arguments)
        this.stateHash = stateHash
        this.millerb1a1 = millerb1a1
        this.root27 = root27
        this.root27Squared = root27Squared
        this.finalGamma0 = finalGamma0
        this.finalDelta0 = finalDelta0
        this.finalGamma1 = finalGamma1
        this.finalDelta1 = finalDelta1
    }

    @method()
    public finalize(
        snapshot: V4MillerState,
        transition: V4Transition,
        poolCodePart: ByteString
    ) {
        assert(V4State.hashMiller(snapshot) == this.stateHash, 'wrong final state')
        assert(V4State.hashTransition(transition) == snapshot.context.transitionHash, 'wrong transition')
        assert(hash256(poolCodePart) == snapshot.context.poolCodeHash, 'wrong pool code')
        assert(this.ctx.utxo.value == snapshot.context.lockedValue, 'wrong locked value')

        let acc = StagedGroth16.finishPair(
            snapshot.acc,
            snapshot.r,
            snapshot.q,
            snapshot.p0
        )
        acc = StagedGroth16.mulPreparedLine(acc, this.finalGamma0, snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.finalDelta0, snapshot.p2)
        acc = StagedGroth16.mulPreparedLine(acc, this.finalGamma1, snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.finalDelta1, snapshot.p2)
        acc = BN256.modFQ12(acc)

        let left = BN256.modFQ12(BN256.mulFQ12(this.millerb1a1, acc))
        let validScale = true
        if (snapshot.scale == 1n) {
            left = BN256.modFQ12(BN256.mulFQ12(left, this.root27))
        } else if (snapshot.scale == 2n) {
            left = BN256.modFQ12(BN256.mulFQ12(left, this.root27Squared))
        } else if (snapshot.scale != 0n) {
            validScale = false
        }
        const inverseCheck = BN256.modFQ12(
            BN256.mulFQ12(snapshot.residue, snapshot.residueInverse)
        )
        const inverseP = BN256.frobeniusFQ12(snapshot.residueInverse)
        const inverseP2 = BN256.frobeniusP2FQ12(snapshot.residueInverse)
        const inverseP3 = BN256.frobeniusFQ12(inverseP2)
        left = BN256.modFQ12(BN256.mulFQ12(left, inverseP3))
        left = BN256.modFQ12(BN256.mulFQ12(left, inverseP))
        assert(validScale, 'invalid residue scale')
        assert(
            BN256.compareFQ12(inverseCheck, BN256.FQ12One),
            'invalid residue inverse'
        )
        assert(BN256.compareFQ12(left, inverseP2), 'invalid Groth16 proof')

        if (transition.publicOut > 0n) {
            assert(
                transition.recipientPkh == int2ByteString(transition.recipientField, 20n),
                'recipient does not match proof'
            )
        } else {
            assert(transition.recipientField == 0n, 'private transition has recipient')
        }
        const nextPoolValue = snapshot.context.lockedValue - transition.publicOut
        assert(nextPoolValue >= 1n, 'pool anchor must remain')
        const poolScript = V4State.poolStateScript(
            poolCodePart,
            transition.newNoteRoot,
            transition.newNullifierRoot,
            transition.newNextIndex
        )
        let outputs = Utils.buildOutput(poolScript, nextPoolValue)
        if (transition.publicOut > 0n) {
            outputs += Utils.buildPublicKeyHashOutput(
                transition.recipientPkh,
                transition.publicOut
            )
        }
        outputs += this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected final outputs')
    }

    @method()
    public abort(
        snapshot: V4MillerState,
        transition: V4Transition,
        poolCodePart: ByteString
    ) {
        assert(V4State.hashMiller(snapshot) == this.stateHash, 'wrong abort state')
        assert(V4State.hashTransition(transition) == snapshot.context.transitionHash, 'wrong transition')
        assert(hash256(poolCodePart) == snapshot.context.poolCodeHash, 'wrong pool code')
        assert(this.timeLock(snapshot.context.abortHeight), 'verification timeout not reached')
        const poolScript = V4State.poolStateScript(
            poolCodePart,
            transition.oldNoteRoot,
            transition.oldNullifierRoot,
            transition.oldNextIndex
        )
        const outputs =
            Utils.buildOutput(poolScript, snapshot.context.lockedValue) +
            this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected abort outputs')
    }
}
