import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { groth16 } from 'snarkjs'
import { PoolState, createHash } from '../src/crypto'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { OptimizedG16BN256 } from '../src/optimizedGroth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')

async function main(): Promise<void> {
    const state = new PoolState(await createHash())
    const transition = state.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: 101n, rho: 10_001n }],
    })
    const jsonVkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const seen = new Set<bigint>()

    for (let attempt = 1; attempt <= 12 && seen.size < 3; attempt++) {
        const { proof } = await groth16.fullProve(transition.circuitInput, WASM, ZKEY)
        const scryptProof = toScryptProof(proof as SnarkProof)
        const witness = buildPairingResidueWitness(
            transition.statement,
            scryptProof,
            vk
        )
        if (!OptimizedG16BN256.verify(transition.statement, scryptProof, witness, vk)) {
            throw new Error(`residue class ${witness.scale} failed verification`)
        }
        seen.add(witness.scale)
        console.log(`✓ proof ${attempt}: residue class ${witness.scale}`)
    }

    if (seen.size !== 3) {
        throw new Error(`covered ${seen.size} of 3 residue classes after 12 proofs`)
    }
    console.log('✓ all three BN254 residue classes accepted valid proofs')
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error)
        process.exit(1)
    }
)
