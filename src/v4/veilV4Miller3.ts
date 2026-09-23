import {
    assert,
    ByteString,
    FixedArray,
    hash256,
    method,
    prop,
    Sha256,
    SmartContract,
    Utils,
} from 'scrypt-ts'
import {
    BN256,
    BN256Pairing,
    LineFuncRes,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { PreparedLine, StagedGroth16 } from './stagedGroth16'
import { V4MillerState, V4State, V4Transition } from './v4State'

/** Optimized-v4 Miller slice 4 of 4 (22 prepared lines). */
export class VeilV4Miller3 extends SmartContract {
    @prop(true)
    stateHash: Sha256

    @prop()
    readonly nextCodeHash: Sha256

    @prop()
    readonly gammaLines: FixedArray<PreparedLine, 22>

    @prop()
    readonly deltaLines: FixedArray<PreparedLine, 22>

    constructor(
        stateHash: Sha256,
        nextCodeHash: Sha256,
        gammaLines: FixedArray<PreparedLine, 22>,
        deltaLines: FixedArray<PreparedLine, 22>
    ) {
        super(...arguments)
        this.stateHash = stateHash
        this.nextCodeHash = nextCodeHash
        this.gammaLines = gammaLines
        this.deltaLines = deltaLines
    }

    @method()
    public advance(snapshot: V4MillerState, nextCodePart: ByteString) {
        assert(V4State.hashMiller(snapshot) == this.stateHash, 'wrong Miller state')
        assert(hash256(nextCodePart) == this.nextCodeHash, 'wrong next-stage code')
        assert(this.ctx.utxo.value == snapshot.context.lockedValue, 'wrong locked value')

        const qMinus = BN256.negTwistPoint(snapshot.q)
        const addR20 = BN256.squareFQ2(snapshot.q.y)
        let acc = snapshot.acc
        let r = snapshot.r
        let line: LineFuncRes = BN256Pairing.lineFuncDouble(r, snapshot.p0)

        // Global Miller digit 48: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[0], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[0], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 49: 1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residueInverse)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[1], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[1], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, snapshot.q, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[2], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[2], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 50: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[3], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[3], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 51: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[4], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[4], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 52: -1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residue)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[5], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[5], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, qMinus, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[6], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[6], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 53: 1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residueInverse)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[7], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[7], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, snapshot.q, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[8], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[8], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 54: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[9], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[9], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 55: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[10], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[10], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 56: -1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residue)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[11], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[11], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, qMinus, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[12], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[12], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 57: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[13], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[13], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 58: 1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residueInverse)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[14], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[14], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, snapshot.q, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[15], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[15], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 59: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[16], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[16], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 60: 1
        acc = BN256.squareFQ12(acc)
        acc = BN256.mulFQ12(acc, snapshot.residueInverse)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[17], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[17], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        line = BN256Pairing.lineFuncAdd(r, snapshot.q, snapshot.p0, addR20)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[18], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[18], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 61: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[19], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[19], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 62: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[20], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[20], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        // Global Miller digit 63: 0
        acc = BN256.squareFQ12(acc)
        line = BN256Pairing.lineFuncDouble(r, snapshot.p0)
        acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        acc = StagedGroth16.mulPreparedLine(acc, this.gammaLines[21], snapshot.p1)
        acc = StagedGroth16.mulPreparedLine(acc, this.deltaLines[21], snapshot.p2)
        r = BN256.modTwistPoint(line.rOut)
        acc = BN256.modFQ12(acc)

        const nextState: V4MillerState = {
            q: snapshot.q,
            p0: snapshot.p0,
            p1: snapshot.p1,
            p2: snapshot.p2,
            r,
            acc,
            residue: snapshot.residue,
            residueInverse: snapshot.residueInverse,
            scale: snapshot.scale,
            context: snapshot.context,
        }
        const nextScript = V4State.stateScript(
            nextCodePart,
            V4State.hashMiller(nextState)
        )
        const outputs = Utils.buildOutput(nextScript, snapshot.context.lockedValue)
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected stage output')
    }

    @method()
    public abort(
        snapshot: V4MillerState,
        transition: V4Transition,
        poolCodePart: ByteString
    ) {
        assert(V4State.hashMiller(snapshot) == this.stateHash, 'wrong abort state')
        assert(
            V4State.hashTransition(transition) == snapshot.context.transitionHash,
            'wrong transition'
        )
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
