import { FixedArray } from 'scrypt-ts'
import {
    BN256,
    BN256Pairing,
    CurvePoint,
    G2Point,
    LineFuncRes,
    TwistPoint,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { SnarkVerificationKey, toScryptVerifyingKey } from './groth16'
import {
    PreparedLine,
    PreparedVerifyingKey,
} from './optimizedGroth16'
import { ROOT_27, ROOT_27_SQUARED } from './pairingResidue'

const MILLER_DIGITS = [
    1, 0, 1, 0, 0, -1, 0, 1,
    1, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 0,
    0, 1, 0, 0, -1, 0, 0, 1,
    1, 1, 0, 0, 0, 0, -1, 0,
    1, 0, 0, -1, 0, 1, 1, 0,
    0, 1, 0, 0, -1, 1, 0, 0,
    -1, 0, 1, 0, 1, 0, 0, 0,
] as const

const UNIT_CURVE_POINT: CurvePoint = { x: 1n, y: 1n, z: 1n, t: 1n }

function prepared(line: LineFuncRes): PreparedLine {
    return { a: line.a, b: line.b, c: line.c }
}

/** Precompute the G2-only portion of every Miller line for a fixed VK point. */
export function prepareMillerLines(point: G2Point): FixedArray<PreparedLine, 91> {
    const q = BN256.makeAffineTwistPoint(BN256.createTwistPoint(point))
    const minusQ = BN256.negTwistPoint(q)
    const addR2 = BN256.squareFQ2(q.y)
    let r: TwistPoint = q
    const lines: PreparedLine[] = []

    for (let i = 0; i < MILLER_DIGITS.length; i++) {
        if (i % 2 === 1) r = BN256.modTwistPoint(r)
        let line = BN256Pairing.lineFuncDouble(r, UNIT_CURVE_POINT)
        lines.push(prepared(line))
        r = line.rOut
        const digit = MILLER_DIGITS[i]
        if (digit !== 0) {
            line = BN256Pairing.lineFuncAdd(
                r,
                digit === 1 ? q : minusQ,
                UNIT_CURVE_POINT,
                addR2
            )
            lines.push(prepared(line))
            r = line.rOut
        }
    }

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
        r,
        q1,
        UNIT_CURVE_POINT,
        BN256.squareFQ2(q1.y)
    )
    lines.push(prepared(line))
    line = BN256Pairing.lineFuncAdd(
        line.rOut,
        minusQ2,
        UNIT_CURVE_POINT,
        BN256.squareFQ2(minusQ2.y)
    )
    lines.push(prepared(line))

    if (lines.length !== 91) throw new Error(`expected 91 prepared lines, got ${lines.length}`)
    return lines as FixedArray<PreparedLine, 91>
}

export function toPreparedVerifyingKey(
    value: SnarkVerificationKey
): PreparedVerifyingKey {
    const vk = toScryptVerifyingKey(value)
    return {
        millerb1a1: vk.millerb1a1,
        gammaAbc: vk.gammaAbc,
        gammaLines: prepareMillerLines(vk.gamma),
        deltaLines: prepareMillerLines(vk.delta),
        root27: ROOT_27,
        root27Squared: ROOT_27_SQUARED,
    }
}
