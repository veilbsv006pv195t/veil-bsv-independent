import {
    BN256,
    FQ12,
    G1Point,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { Proof } from 'scrypt-ts-lib/dist/zk/g16bn256'
import {
    OptimizedG16BN256,
    PairingResidueWitness,
    PreparedVerifyingKey,
} from './optimizedGroth16'

const SCALAR_ORDER =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n
const BN_SEED = 4965661367192848881n
const GROUP_ORDER = BN256.P ** 12n - 1n
const PAIRING_COFACTOR = GROUP_ORDER / SCALAR_ORDER
const LAMBDA =
    6n * BN_SEED + 2n + BN256.P - BN256.P ** 2n + BN256.P ** 3n
const M = LAMBDA / (3n * SCALAR_ORDER)
const CUBIC_TEST_EXPONENT = GROUP_ORDER / 3n
const CUBE_ROOT_EXPONENT = (GROUP_ORDER / 27n + 1n) / 3n

function inverseMod(value: bigint, modulus: bigint): bigint {
    let oldR = value
    let r = modulus
    let oldS = 1n
    let s = 0n
    while (r !== 0n) {
        const quotient = oldR / r
        ;[oldR, r] = [r, oldR - quotient * r]
        ;[oldS, s] = [s, oldS - quotient * s]
    }
    if (oldR !== 1n) throw new Error('value has no modular inverse')
    return ((oldS % modulus) + modulus) % modulus
}

const R_INVERSE = inverseMod(SCALAR_ORDER, PAIRING_COFACTOR)
const M_INVERSE = inverseMod(M, GROUP_ORDER)

/** A primitive 27th root of unity in the Fp6 subfield. */
export const ROOT_27: FQ12 = {
    x: BN256.FQ6Zero,
    y: {
        x: BN256.FQ2Zero,
        y: {
            x: 4534159768373982659291990808346042891252278737770656686799127720849666919525n,
            y: 9483667112135124394372960210728142145589475128897916459350428495526310884707n,
        },
        z: BN256.FQ2Zero,
    },
}

export const ROOT_27_SQUARED = BN256.modFQ12(BN256.squareFQ12(ROOT_27))

function multiply(a: FQ12, b: FQ12): FQ12 {
    return BN256.modFQ12(BN256.mulFQ12(a, b))
}

function square(a: FQ12): FQ12 {
    return BN256.modFQ12(BN256.squareFQ12(a))
}

/** Variable-length exponentiation is only used by the off-chain witness builder. */
export function powFQ12(base: FQ12, exponent: bigint): FQ12 {
    if (exponent < 0n) throw new Error('negative FQ12 exponent')
    let result = BN256.FQ12One
    let factor = BN256.modFQ12(base)
    let remaining = exponent
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n) result = multiply(result, factor)
        remaining >>= 1n
        if (remaining > 0n) factor = square(factor)
    }
    return result
}

export function verifyPairingResidueWitness(
    millerProduct: FQ12,
    witness: PairingResidueWitness
): boolean {
    const scale =
        witness.scale === 0n
            ? BN256.FQ12One
            : witness.scale === 1n
              ? ROOT_27
              : witness.scale === 2n
                ? ROOT_27_SQUARED
                : BN256.FQ12Zero
    const left = multiply(millerProduct, scale)
    const right = powFQ12(witness.residue, LAMBDA)
    return (
        BN256.compareFQ12(left, right) &&
        BN256.compareFQ12(
            multiply(witness.residue, witness.residueInverse),
            BN256.FQ12One
        )
    )
}

/**
 * Build the prover-side residue witness from Section 4.3.2 of
 * "On Proving Pairings" (Novakovic and Eagen, 2024).
 */
export function residueWitness(millerProduct: FQ12): PairingResidueWitness {
    let scale = 0n
    let adjusted = BN256.modFQ12(millerProduct)
    if (!BN256.compareFQ12(powFQ12(adjusted, CUBIC_TEST_EXPONENT), BN256.FQ12One)) {
        const scaledOnce = multiply(adjusted, ROOT_27)
        if (BN256.compareFQ12(powFQ12(scaledOnce, CUBIC_TEST_EXPONENT), BN256.FQ12One)) {
            scale = 1n
            adjusted = scaledOnce
        } else {
            scale = 2n
            adjusted = multiply(adjusted, ROOT_27_SQUARED)
            if (!BN256.compareFQ12(powFQ12(adjusted, CUBIC_TEST_EXPONENT), BN256.FQ12One)) {
                throw new Error('could not scale Miller product to a cubic residue')
            }
        }
    }

    let residue = powFQ12(adjusted, R_INVERSE)
    residue = powFQ12(residue, M_INVERSE)

    const target = residue
    const targetInverse = BN256.inverseFQ12(target)
    let root = powFQ12(target, CUBE_ROOT_EXPONENT)
    const rootAdjustment = powFQ12(ROOT_27, CUBE_ROOT_EXPONENT)

    for (let attempts = 0; attempts < 27; attempts++) {
        const rootCubed = multiply(square(root), root)
        if (BN256.compareFQ12(rootCubed, target)) {
            const residueInverse = BN256.inverseFQ12(root)
            return { residue: root, residueInverse, scale }
        }
        const quotient = multiply(rootCubed, targetInverse)
        let orderPower = quotient
        let order = 0
        while (!BN256.compareFQ12(orderPower, BN256.FQ12One) && order < 3) {
            orderPower = multiply(square(orderPower), orderPower)
            order++
        }
        if (order === 0 || order >= 3) {
            throw new Error('invalid cubic-root correction order')
        }
        root = multiply(root, rootAdjustment)
    }
    throw new Error('could not construct pairing residue witness')
}

export function buildPairingResidueWitness(
    signal: bigint,
    proof: Proof,
    vk: PreparedVerifyingKey
): PairingResidueWitness {
    const scaled = BN256.mulG1Point(vk.gammaAbc[1], signal)
    const vkX = BN256.addG1Points(vk.gammaAbc[0], scaled)
    const negA: G1Point = { x: proof.a.x, y: -proof.a.y }
    const dynamic = OptimizedG16BN256.millerPrepared3(
        BN256.createTwistPoint(proof.b),
        BN256.createCurvePoint(negA),
        BN256.createCurvePoint(vkX),
        BN256.createCurvePoint(proof.c),
        vk.gammaLines,
        vk.deltaLines,
        BN256.FQ12One,
        BN256.FQ12One
    )
    const product = multiply(vk.millerb1a1, dynamic)
    return residueWitness(product)
}
