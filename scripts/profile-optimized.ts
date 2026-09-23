import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { groth16 } from 'snarkjs'
import {
    BN256,
    BN256Pairing,
    G1Point,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { PoolState, createHash } from '../src/crypto'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { OptimizedG16BN256 } from '../src/optimizedGroth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import {
    buildPairingResidueWitness,
    verifyPairingResidueWitness,
} from '../src/pairingResidue'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')

function timed<T>(label: string, action: () => T): T {
    const started = performance.now()
    const result = action()
    console.log(`${label}: ${((performance.now() - started) / 1000).toFixed(3)}s`)
    return result
}

async function main(): Promise<void> {
    const state = new PoolState(await createHash())
    const transition = state.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: 101n, rho: 10_001n }],
    })
    const jsonVkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey
    const { proof } = await groth16.fullProve(transition.circuitInput, WASM, ZKEY)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const vk = toPreparedVerifyingKey(jsonVkey)

    const vkX = timed('public-input G1 multiplication', () =>
        BN256.addG1Points(
            vk.gammaAbc[0],
            BN256.mulG1Point(vk.gammaAbc[1], transition.statement)
        )
    )
    const negA: G1Point = { x: scryptProof.a.x, y: -scryptProof.a.y }
    const miller = timed('three-pair shared Miller loop', () =>
        OptimizedG16BN256.millerPrepared3(
            BN256.createTwistPoint(scryptProof.b),
            BN256.createCurvePoint(negA),
            BN256.createCurvePoint(vkX),
            BN256.createCurvePoint(scryptProof.c),
            vk.gammaLines,
            vk.deltaLines,
            BN256.FQ12One,
            BN256.FQ12One
        )
    )
    const product = timed('constant-pair multiplication', () =>
        BN256.modFQ12(BN256.mulFQ12(vk.millerb1a1, miller))
    )
    const result = timed('final exponentiation', () =>
        BN256Pairing.finalExponentiation(product)
    )
    console.log(`accepted: ${BN256.compareFQ12(result, BN256.FQ12One)}`)
    const residue = timed('residue witness generation', () =>
        buildPairingResidueWitness(transition.statement, scryptProof, vk)
    )
    console.log(
        `residue accepted: ${verifyPairingResidueWitness(product, residue)} (scale ${residue.scale})`
    )
}

main().catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
})
