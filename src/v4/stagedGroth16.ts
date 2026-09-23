import {
    and,
    assert,
    FixedArray,
    lshift,
    method,
    SmartContractLib,
} from 'scrypt-ts'
import {
    BN256,
    BN256Pairing,
    CurvePoint,
    FQ2,
    FQ12,
    G1Point,
    LineFuncRes,
    TwistPoint,
} from 'scrypt-ts-lib/dist/ec/bn256'

export type PreparedLine = { a: FQ2; b: FQ2; c: FQ2 }
export type MillerStageResult = { acc: FQ12; r: TwistPoint }

/**
 * One bounded Miller-loop slice for optimized-v4.
 *
 * The four 16-element line arrays are supplied by the unlocking transaction.
 * A production stage contract authenticates them against immutable chunk
 * commitments before calling this routine.  Add-line entries for zero digits
 * are ignored.
 */
export class StagedGroth16 extends SmartContractLib {
    @method()
    static mulG1PointBounded(a: G1Point, scalar: bigint): G1Point {
        const point = BN256.createCurvePoint(a)
        let t: CurvePoint = { x: 0n, y: 0n, z: 0n, t: 0n }
        let sum: CurvePoint = { x: 0n, y: 1n, z: 0n, t: 0n }
        let firstOne = false
        for (let k = 0; k < 128; k++) {
            sum = BN256.modCurvePoint(sum)
            for (let j = 0; j < 2; j++) {
                if (firstOne) {
                    t = BN256.doubleCurvePoint(sum)
                }
                const shifted = lshift(1n, BigInt(255 - (2 * k + j)))
                if (and(scalar, shifted) != 0n) {
                    firstOne = true
                    sum = BN256.addCurvePoints(t, point)
                } else {
                    sum = t
                }
            }
        }
        return BN256.getG1Point(sum)
    }

    @method()
    static mulPreparedLine(acc: FQ12, line: PreparedLine, p: CurvePoint): FQ12 {
        const b = BN256.mulScalarFQ2(line.b, p.x)
        const c = BN256.mulScalarFQ2(line.c, p.y)
        return BN256Pairing.mulLine(acc, line.a, b, c)
    }

    @method()
    static run16(
        q: TwistPoint,
        p0: CurvePoint,
        p1: CurvePoint,
        p2: CurvePoint,
        rInput: TwistPoint,
        accInput: FQ12,
        initialAccumulator: FQ12,
        inverseAccumulator: FQ12,
        digits: FixedArray<bigint, 16>,
        gammaDouble: FixedArray<PreparedLine, 16>,
        deltaDouble: FixedArray<PreparedLine, 16>,
        gammaAdd: FixedArray<PreparedLine, 16>,
        deltaAdd: FixedArray<PreparedLine, 16>
    ): MillerStageResult {
        const qAffine = BN256.makeAffineTwistPoint(q)
        const qMinus = BN256.negTwistPoint(qAffine)
        const addR20 = BN256.squareFQ2(qAffine.y)
        const p0Affine = BN256.makeAffineCurvePoint(p0)
        const p1Affine = BN256.makeAffineCurvePoint(p1)
        const p2Affine = BN256.makeAffineCurvePoint(p2)
        let acc = accInput
        let r = rInput
        let line: LineFuncRes = BN256Pairing.lineFuncDouble(r, p0Affine)
        let addQ = qAffine

        for (let i = 0; i < 16; i++) {
            assert(
                digits[i] == -1n || digits[i] == 0n || digits[i] == 1n,
                'invalid Miller digit'
            )
            acc = BN256.squareFQ12(acc)
            if (digits[i] == 1n) {
                acc = BN256.mulFQ12(acc, initialAccumulator)
            } else if (digits[i] == -1n) {
                acc = BN256.mulFQ12(acc, inverseAccumulator)
            }

            line = BN256Pairing.lineFuncDouble(r, p0Affine)
            acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
            acc = StagedGroth16.mulPreparedLine(acc, gammaDouble[i], p1Affine)
            acc = StagedGroth16.mulPreparedLine(acc, deltaDouble[i], p2Affine)
            r = BN256.modTwistPoint(line.rOut)

            if (digits[i] != 0n) {
                addQ = qAffine
                if (digits[i] == -1n) {
                    addQ = qMinus
                }
                line = BN256Pairing.lineFuncAdd(r, addQ, p0Affine, addR20)
                acc = BN256Pairing.mulLine(acc, line.a, line.b, line.c)
                acc = StagedGroth16.mulPreparedLine(acc, gammaAdd[i], p1Affine)
                acc = StagedGroth16.mulPreparedLine(acc, deltaAdd[i], p2Affine)
                r = BN256.modTwistPoint(line.rOut)
            }
            acc = BN256.modFQ12(acc)
        }

        return { acc, r }
    }

    @method()
    static finishPair(
        accInput: FQ12,
        rInput: TwistPoint,
        qInput: TwistPoint,
        p: CurvePoint
    ): FQ12 {
        const q = BN256.makeAffineTwistPoint(qInput)
        const pAffine = BN256.makeAffineCurvePoint(p)
        let q1x = BN256.conjugateFQ2(q.x)
        q1x = BN256.mulFQ2(q1x, BN256.xiToPMinus1Over3)
        let q1y = BN256.conjugateFQ2(q.y)
        q1y = BN256.mulFQ2(q1y, BN256.xiToPMinus1Over2)
        const q1: TwistPoint = {
            x: q1x,
            y: q1y,
            z: { x: 0n, y: 1n },
            t: { x: 0n, y: 1n },
        }
        const minusQ2: TwistPoint = {
            x: BN256.mulScalarFQ2(q.x, BN256.xiToPSquaredMinus1Over3),
            y: q.y,
            z: { x: 0n, y: 1n },
            t: { x: 0n, y: 1n },
        }
        let line = BN256Pairing.lineFuncAdd(
            rInput,
            q1,
            pAffine,
            BN256.squareFQ2(q1.y)
        )
        let acc = BN256Pairing.mulLine(
            accInput,
            line.a,
            line.b,
            line.c
        )
        acc = BN256.modFQ12(acc)
        line = BN256Pairing.lineFuncAdd(
            BN256.modTwistPoint(line.rOut),
            minusQ2,
            pAffine,
            BN256.squareFQ2(minusQ2.y)
        )
        return BN256.modFQ12(
            BN256Pairing.mulLine(acc, line.a, line.b, line.c)
        )
    }
}
