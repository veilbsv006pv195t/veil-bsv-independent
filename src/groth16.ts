import { BN256, BN256Pairing, G1Point, G2Point } from 'scrypt-ts-lib/dist/ec/bn256'
import {
    G16BN256,
    Proof,
    VerifyingKey,
} from 'scrypt-ts-lib/dist/zk/g16bn256'

type JsonPoint = readonly (string | readonly string[])[]

export interface SnarkProof {
    pi_a: JsonPoint
    pi_b: JsonPoint
    pi_c: JsonPoint
}

export interface SnarkVerificationKey {
    vk_alpha_1: JsonPoint
    vk_beta_2: JsonPoint
    vk_gamma_2: JsonPoint
    vk_delta_2: JsonPoint
    IC: JsonPoint[]
}

function g1(point: JsonPoint): G1Point {
    return { x: BigInt(point[0] as string), y: BigInt(point[1] as string) }
}

function g2(point: JsonPoint): G2Point {
    const x = point[0] as readonly string[]
    const y = point[1] as readonly string[]
    return {
        x: { x: BigInt(x[0]), y: BigInt(x[1]) },
        y: { x: BigInt(y[0]), y: BigInt(y[1]) },
    }
}

export function toScryptProof(proof: SnarkProof): Proof {
    return { a: g1(proof.pi_a), b: g2(proof.pi_b), c: g1(proof.pi_c) }
}

export function toScryptVerifyingKey(vkey: SnarkVerificationKey): VerifyingKey {
    if (vkey.IC.length !== G16BN256.N + 1) {
        throw new Error(`expected ${G16BN256.N + 1} IC points, got ${vkey.IC.length}`)
    }
    const alpha = g1(vkey.vk_alpha_1)
    const beta = g2(vkey.vk_beta_2)
    return {
        millerb1a1: BN256Pairing.miller(
            BN256.createTwistPoint(beta),
            BN256.createCurvePoint(alpha)
        ),
        gamma: g2(vkey.vk_gamma_2),
        delta: g2(vkey.vk_delta_2),
        gammaAbc: [g1(vkey.IC[0]), g1(vkey.IC[1])],
    }
}
