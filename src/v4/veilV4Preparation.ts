import {
    assert,
    ByteString,
    hash256,
    method,
    prop,
    Sha256,
    SmartContract,
    Utils,
} from 'scrypt-ts'
import { BN256, G1Point } from 'scrypt-ts-lib/dist/ec/bn256'
import { StagedGroth16 } from './stagedGroth16'
import {
    V4MillerState,
    V4PreparationState,
    V4State,
    V4Transition,
} from './v4State'

/** Converts the proof and public signal into the normalized Miller state. */
export class VeilV4Preparation extends SmartContract {
    @prop(true)
    stateHash: Sha256

    @prop()
    readonly nextCodeHash: Sha256

    @prop()
    readonly gammaAbc0: G1Point

    @prop()
    readonly gammaAbc1: G1Point

    constructor(
        stateHash: Sha256,
        nextCodeHash: Sha256,
        gammaAbc0: G1Point,
        gammaAbc1: G1Point
    ) {
        super(...arguments)
        this.stateHash = stateHash
        this.nextCodeHash = nextCodeHash
        this.gammaAbc0 = gammaAbc0
        this.gammaAbc1 = gammaAbc1
    }

    @method()
    public prepare(snapshot: V4PreparationState, nextCodePart: ByteString) {
        assert(V4State.hashPreparation(snapshot) == this.stateHash, 'wrong preparation state')
        assert(hash256(nextCodePart) == this.nextCodeHash, 'wrong Miller stage code')

        const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(snapshot.proof.b))
        const negA: G1Point = { x: snapshot.proof.a.x, y: -snapshot.proof.a.y }
        const p0 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(negA))
        const scaled = StagedGroth16.mulG1PointBounded(
            this.gammaAbc1,
            snapshot.signal
        )
        const vkX = BN256.addG1Points(this.gammaAbc0, scaled)
        const p1 = BN256.makeAffineCurvePoint(BN256.createCurvePoint(vkX))
        const p2 = BN256.makeAffineCurvePoint(
            BN256.createCurvePoint(snapshot.proof.c)
        )
        const nextState: V4MillerState = {
            q,
            p0,
            p1,
            p2,
            r: q,
            acc: snapshot.residueInverse,
            residue: snapshot.residue,
            residueInverse: snapshot.residueInverse,
            scale: snapshot.scale,
            context: snapshot.context,
        }
        const nextScript = V4State.stateScript(
            nextCodePart,
            V4State.hashMiller(nextState)
        )
        const outputs = Utils.buildOutput(nextScript, this.ctx.utxo.value)
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected preparation output')
    }

    @method()
    public abort(
        snapshot: V4PreparationState,
        transition: V4Transition,
        poolCodePart: ByteString
    ) {
        assert(V4State.hashPreparation(snapshot) == this.stateHash, 'wrong abort state')
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
